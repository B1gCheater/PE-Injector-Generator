// remotemap.cpp — remote DLL manual map.
//
// Writes the DLL bytes + a position-independent loader stub into the target
// process; the stub maps the DLL and runs its DllMain inside the target. The
// stub takes a ctx struct whose function pointers hold kernel32 entry points
// (system DLLs share a base across a boot session, so these addresses are
// valid in the target process too).

#include "remotemap.hpp"
#include "proc.hpp"
#include "config.h"
#include "log.hpp"
#include "ti_util.hpp"
#include "stub_data.h"

#include <windows.h>
#include <vector>

namespace {

// Must match struct ctx in stub.c exactly (field order and alignment).
struct remote_ctx {
    unsigned char *dll;
    unsigned int dll_len;
    unsigned int _pad;
    void *va;
    void *vp;
    void *ll;
    void *gpa;
    void *flush;
    void *token;      /* TI impersonation token handle in the target, or 0 */
    void *set_token;  /* SetThreadToken */
};

}  // namespace

int dll_remote_map(const unsigned char *dll, unsigned int dll_len, const wchar_t *target, bool ti) {
    std::vector<DWORD> pids = find_pids(target);
    if (pids.empty())
        return 5;

    HANDLE hp = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_DUP_HANDLE,
        FALSE, pids[0]);
    if (!hp)
        return 6;

    // kernel32 entry points (valid in the target: system DLLs share a base)
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    void *va = reinterpret_cast<void *>(GetProcAddress(k32, "VirtualAlloc"));
    void *vp = reinterpret_cast<void *>(GetProcAddress(k32, "VirtualProtect"));
    void *ll = reinterpret_cast<void *>(GetProcAddress(k32, "LoadLibraryA"));
    void *gpa = reinterpret_cast<void *>(GetProcAddress(k32, "GetProcAddress"));
    void *flush = reinterpret_cast<void *>(GetProcAddress(k32, "FlushInstructionCache"));
    if (!va || !vp || !ll || !gpa || !flush) {
        CloseHandle(hp);
        return 6;
    }

    // TrustedInstaller: build an impersonation token here (we have an IAT and
    // can call TiLib), then DuplicateHandle it into the target process so the
    // stub can SetThreadToken it. Best effort — on failure the target keeps
    // its own (admin) token.
    void *token = nullptr;
    void *set_token = nullptr;
    if (ti) {
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
            PIG_LOG(L"remotemap: TI token setup failed (falling back to admin token)");
        else
            PIG_LOG(L"remotemap: TI impersonation token ready");
    }

    SIZE_T data_size = sizeof(remote_ctx) + dll_len;
    auto *data = static_cast<unsigned char *>(
        VirtualAllocEx(hp, nullptr, data_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    auto *code = static_cast<unsigned char *>(
        VirtualAllocEx(hp, nullptr, stub_code_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!data || !code) {
        CloseHandle(hp);
        return 6;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(hp, data + sizeof(remote_ctx), dll, dll_len, &written)) {
        CloseHandle(hp);
        return 6;
    }

    remote_ctx ctx = {};
    ctx.dll = data + sizeof(remote_ctx);
    ctx.dll_len = dll_len;
    ctx.va = va;
    ctx.vp = vp;
    ctx.ll = ll;
    ctx.gpa = gpa;
    ctx.flush = flush;
    ctx.token = token;
    ctx.set_token = set_token;
    if (!WriteProcessMemory(hp, data, &ctx, sizeof(ctx), &written)) {
        CloseHandle(hp);
        return 6;
    }

    if (!WriteProcessMemory(hp, code, stub_code, stub_code_len, &written)) {
        CloseHandle(hp);
        return 6;
    }

    DWORD old = 0;
    if (!VirtualProtectEx(hp, code, stub_code_len, PAGE_EXECUTE_READ, &old)) {
        CloseHandle(hp);
        return 6;
    }

    HANDLE t = CreateRemoteThread(hp, nullptr, 0,
                                  reinterpret_cast<LPTHREAD_START_ROUTINE>(code), data, 0, nullptr);
    if (!t) {
        CloseHandle(hp);
        return 6;
    }
    CloseHandle(t);
    CloseHandle(hp);
    return 0;
}
