// dllload.cpp — local DLL memory loading + optional export invocation.
//
// Reuses pe_map_image (see selfmap.cpp); the only real difference from an EXE
// is the entry point: a DLL's entry is its DllMain, called with the mapped
// base as the pseudo-HINSTANCE.

#include "dllload.hpp"
#include "selfmap.hpp"
#include "config.h"
#include "log.hpp"
#include "ti_util.hpp"

#include <windows.h>
#include <cstring>

namespace {

void *find_export(void *base, const char *name) {
    const auto *dos = static_cast<const IMAGE_DOS_HEADER *>(base);
    const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(
        static_cast<const char *>(base) + dos->e_lfanew);
    const auto &exp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp.VirtualAddress == 0)
        return nullptr;

    const auto *ed = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(
        static_cast<const char *>(base) + exp.VirtualAddress);
    const auto *names = reinterpret_cast<const DWORD *>(
        static_cast<const char *>(base) + ed->AddressOfNames);
    const auto *ordinals = reinterpret_cast<const WORD *>(
        static_cast<const char *>(base) + ed->AddressOfNameOrdinals);
    const auto *funcs = reinterpret_cast<const DWORD *>(
        static_cast<const char *>(base) + ed->AddressOfFunctions);

    for (DWORD i = 0; i < ed->NumberOfNames; i++) {
        const char *n = static_cast<const char *>(base) + names[i];
        if (strcmp(n, name) == 0)
            return static_cast<char *>(base) + funcs[ordinals[i]];
    }
    return nullptr;
}

}  // namespace

int dll_load_local(const unsigned char *data, unsigned int len, const wchar_t *export_name, bool ti) {
    void *base = nullptr;
    int rc = pe_map_image(data, len, &base);
    if (rc != 0)
        return rc;

    if (ti)
        ti_impersonate();  // DllMain/export below run inline on this thread

    const auto *dos = static_cast<const IMAGE_DOS_HEADER *>(base);
    const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(
        static_cast<const char *>(base) + dos->e_lfanew);
    auto dll_main = reinterpret_cast<BOOL(WINAPI *)(HINSTANCE, DWORD, LPVOID)>(
        static_cast<char *>(base) + nt->OptionalHeader.AddressOfEntryPoint);

    PIG_LOG(L"dllload: DllMain=0x%llx", static_cast<unsigned long long>(
        reinterpret_cast<ULONG_PTR>(dll_main)));

    if (!dll_main(static_cast<HINSTANCE>(base), DLL_PROCESS_ATTACH, nullptr))
        return 8;

    if (export_name) {
        char name[256] = {0};
        WideCharToMultiByte(CP_ACP, 0, export_name, -1, name, sizeof(name), nullptr, nullptr);
        void *fn = find_export(base, name);
        if (!fn) {
            PIG_LOG(L"dllload: export %s not found", export_name);
            return 8;
        }
        PIG_LOG(L"dllload: calling export %s", export_name);
        reinterpret_cast<void (*)()>(fn)();
    }
    return 0;
}
