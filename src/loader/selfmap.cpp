// selfmap.cpp — EXE self-mapping (manual PE map, x64, own process).
//
// Flow: alloc SizeOfImage -> copy headers -> map sections -> fix relocations
// -> resolve imports -> set section permissions -> flush icache -> run entry.
//
// Support matrix (P3): native x64, dynamic CRT, must keep .reloc, no .NET.
// Known limits: ExitProcess from the mapped EXE terminates the loader process;
// static TLS data is not fully initialised (callbacks run once with
// PROCESS_ATTACH); x64 unwind info is not registered.

#include "selfmap.hpp"
#include "config.h"
#include "log.hpp"
#include "ti_util.hpp"

#include <windows.h>

#include <cwchar>
#include <cstring>

namespace {

// Minimal UNICODE_STRING (matches ntdef.h layout; avoids pulling winternl.h).
struct unicode_string_t {
    unsigned short Length;
    unsigned short MaximumLength;
    wchar_t *Buffer;
};

// GetCommandLineW caches the *pointer* to PEB.ProcessParameters.CommandLine
// buffer, so rewriting the buffer pointer does nothing — but rewriting the
// buffer's *contents* (within its allocated size) is visible. We do the latter.
struct cmdline_save {
    wchar_t saved[1024];
    unsigned short length;
};

bool patch_command_line(const wchar_t *args, cmdline_save &save) {
    auto *pp = *reinterpret_cast<void **>(reinterpret_cast<char *>(__readgsqword(0x60)) + 0x20);
    auto *cmd = reinterpret_cast<unicode_string_t *>(reinterpret_cast<char *>(pp) + 0x70);
    if (!cmd->Buffer || cmd->MaximumLength == 0)
        return false;

    wchar_t buf[1024];
    swprintf(buf, 1024, L"loader.exe %s", args);
    size_t need = (wcslen(buf) + 1) * sizeof(wchar_t);
    if (need > static_cast<size_t>(cmd->MaximumLength) + sizeof(wchar_t))
        return false;  // new command line does not fit

    size_t save_chars = cmd->Length / sizeof(wchar_t);
    if (save_chars >= 1024)
        save_chars = 1023;
    wcsncpy(save.saved, cmd->Buffer, save_chars);
    save.saved[save_chars] = 0;
    save.length = cmd->Length;

    wcscpy(cmd->Buffer, buf);
    cmd->Length = static_cast<unsigned short>(wcslen(buf) * sizeof(wchar_t));

    // The CRT also keeps its own cached _wcmdln/_acmdln; mainCRTStartup may
    // build argv from those instead of GetCommandLineW. Rewrite them too.
    typedef wchar_t **(__cdecl *fn_p_wcmdln)(void);
    typedef char **(__cdecl *fn_p_acmdln)(void);
    HMODULE ucrt = GetModuleHandleA("ucrtbase.dll");
    if (ucrt) {
        auto p_wcmdln = reinterpret_cast<fn_p_wcmdln>(GetProcAddress(ucrt, "__p__wcmdln"));
        if (p_wcmdln && *p_wcmdln()) {
            if (wcslen(buf) <= wcslen(*p_wcmdln()))
                wcscpy(*p_wcmdln(), buf);
        }
        auto p_acmdln = reinterpret_cast<fn_p_acmdln>(GetProcAddress(ucrt, "__p__acmdln"));
        if (p_acmdln && *p_acmdln()) {
            char ansi[1024];
            WideCharToMultiByte(CP_ACP, 0, buf, -1, ansi, sizeof(ansi), nullptr, nullptr);
            if (strlen(ansi) <= strlen(*p_acmdln()))
                strcpy(*p_acmdln(), ansi);
        }
    }
    return true;
}

void restore_command_line(const cmdline_save &save) {
    auto *pp = *reinterpret_cast<void **>(reinterpret_cast<char *>(__readgsqword(0x60)) + 0x20);
    auto *cmd = reinterpret_cast<unicode_string_t *>(reinterpret_cast<char *>(pp) + 0x70);
    wcscpy(cmd->Buffer, save.saved);
    cmd->Length = save.length;
}

// Map a raw PE image into a fresh region. Returns 0 on success and stores the
// base in *out_base; returns a non-zero loader exit code on failure.
int map_image_impl(const unsigned char *raw, unsigned int raw_len, void **out_base) {
    *out_base = nullptr;
    if (raw_len < sizeof(IMAGE_DOS_HEADER))
        return 8;

    const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(raw);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 8;

    const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(raw + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return 8;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return 8;

    const IMAGE_OPTIONAL_HEADER64 &opt = nt->OptionalHeader;

    // 1. allocate the whole image, read/write first (permissions applied later)
    void *base = VirtualAlloc(nullptr, opt.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base)
        return 8;

    // 2. copy headers
    memcpy(base, raw, opt.SizeOfHeaders);

    // section table sits right after the optional header
    const auto *sec = reinterpret_cast<const IMAGE_SECTION_HEADER *>(
        reinterpret_cast<const char *>(nt) + 4 + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader);

    // 3. map sections (file offset -> virtual address)
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData == 0)
            continue;
        memcpy(reinterpret_cast<char *>(base) + sec[i].VirtualAddress,
               raw + sec[i].PointerToRawData,
               sec[i].SizeOfRawData);
    }

    // 4. fix relocations
    const ULONG_PTR delta = reinterpret_cast<ULONG_PTR>(base) - opt.ImageBase;
    if (delta != 0) {
        const auto &reloc = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc.VirtualAddress == 0) {
            VirtualFree(base, 0, MEM_RELEASE);
            return 8;  // no reloc but not loaded at preferred base
        }
        const auto *block = reinterpret_cast<const IMAGE_BASE_RELOCATION *>(
            reinterpret_cast<const char *>(base) + reloc.VirtualAddress);
        while (block->VirtualAddress != 0) {
            int count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            const WORD *entries = reinterpret_cast<const WORD *>(block + 1);
            for (int i = 0; i < count; i++) {
                int type = entries[i] >> 12;
                int off = entries[i] & 0xFFF;
                if (type == IMAGE_REL_BASED_DIR64) {
                    auto *patch = reinterpret_cast<ULONG_PTR *>(
                        reinterpret_cast<char *>(base) + block->VirtualAddress + off);
                    *patch += delta;
                }
            }
            block = reinterpret_cast<const IMAGE_BASE_RELOCATION *>(
                reinterpret_cast<const char *>(block) + block->SizeOfBlock);
        }
    }

    // 5. resolve imports
    const auto &imp_dir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp_dir.VirtualAddress != 0) {
        const auto *imp = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(
            reinterpret_cast<const char *>(base) + imp_dir.VirtualAddress);
        for (; imp->Name != 0; imp++) {
            const char *dll = reinterpret_cast<const char *>(base) + imp->Name;
            HMODULE h = LoadLibraryA(dll);
            if (!h) {
                PIG_LOG(L"selfmap: LoadLibraryA(%S) failed", dll);
                VirtualFree(base, 0, MEM_RELEASE);
                return 8;
            }
            // Some images zero OriginalFirstThunk; fall back to FirstThunk.
            const ULONG_PTR thunk_rva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
            const auto *thunk = reinterpret_cast<const IMAGE_THUNK_DATA64 *>(
                reinterpret_cast<const char *>(base) + thunk_rva);
            auto *iat = reinterpret_cast<IMAGE_THUNK_DATA64 *>(
                reinterpret_cast<char *>(base) + imp->FirstThunk);
            for (; thunk->u1.AddressOfData != 0; thunk++, iat++) {
                ULONG_PTR addr;
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    addr = reinterpret_cast<ULONG_PTR>(
                        GetProcAddress(h, reinterpret_cast<LPCSTR>(thunk->u1.Ordinal & 0xFFFF)));
                } else {
                    const auto *byname = reinterpret_cast<const IMAGE_IMPORT_BY_NAME *>(
                        reinterpret_cast<const char *>(base) + thunk->u1.AddressOfData);
                    addr = reinterpret_cast<ULONG_PTR>(GetProcAddress(h, byname->Name));
                }
                if (addr == 0) {
                    VirtualFree(base, 0, MEM_RELEASE);
                    return 8;
                }
                iat->u1.Function = addr;
            }
        }
    }

    // 6. run TLS callbacks once (PROCESS_ATTACH); static TLS data is not
    //    relocated/initialised beyond this in P3.
    const auto &tls_dir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls_dir.VirtualAddress != 0) {
        const auto *tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY64 *>(
            reinterpret_cast<const char *>(base) + tls_dir.VirtualAddress);
        if (tls->AddressOfCallBacks != 0) {
            auto **cb = reinterpret_cast<PIMAGE_TLS_CALLBACK *>(tls->AddressOfCallBacks);
            while (*cb != nullptr) {
                (*cb)(base, DLL_PROCESS_ATTACH, nullptr);
                cb++;
            }
        }
    }

    // 7. apply section permissions: executable -> RX, otherwise RW
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD prot = (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? PAGE_EXECUTE_READ : PAGE_READWRITE;
        SIZE_T size = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (size == 0)
            continue;
        DWORD old = 0;
        VirtualProtect(reinterpret_cast<char *>(base) + sec[i].VirtualAddress, size, prot, &old);
    }

    FlushInstructionCache(GetCurrentProcess(), base, opt.SizeOfImage);

    *out_base = base;
    return 0;
}

}  // namespace

int pe_map_image(const unsigned char *raw, unsigned int raw_len, void **out_base) {
    return map_image_impl(raw, raw_len, out_base);
}

int selfmap_execute(const unsigned char *data, unsigned int len, const wchar_t *args, bool ti) {
    void *base = nullptr;
    int rc = pe_map_image(data, len, &base);
    if (rc != 0)
        return rc;

    const auto *dos = static_cast<const IMAGE_DOS_HEADER *>(base);
    const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(
        static_cast<const char *>(base) + dos->e_lfanew);
    ULONG_PTR entry = reinterpret_cast<ULONG_PTR>(base) + nt->OptionalHeader.AddressOfEntryPoint;

    PIG_LOG(L"selfmap: entry=0x%llx", static_cast<unsigned long long>(entry));

    cmdline_save saved{};
    bool patched = false;
    if (args && args[0]) {
        patched = patch_command_line(args, saved);
        PIG_LOG(L"selfmap: patch_cmdline ok=%d args=%s", patched ? 1 : 0, args);
    }

    if (ti) {
        // TI impersonation is thread-level, so run the entry point INLINE on
        // this thread (a new thread would drop the token). Best effort.
        ti_impersonate();
        reinterpret_cast<void (*)()>(entry)();
        RevertToSelf();
    } else {
        // Run the entry point (the CRT startup code) on a fresh thread. If the
        // mapped EXE's main returns, it calls ExitProcess and tears the loader
        // down — a documented limitation.
        HANDLE t = CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(entry), nullptr, 0, nullptr);
        if (!t) {
            VirtualFree(base, 0, MEM_RELEASE);
            return 8;
        }
        WaitForSingleObject(t, INFINITE);
        CloseHandle(t);
    }

    if (patched)
        restore_command_line(saved);
    // Do not free: the mapped image may still be referenced (thread teardown).
    return 0;
}
