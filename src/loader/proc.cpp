// proc.cpp — process enumeration and name matching.

#include "proc.hpp"
#include "config.h"

#include <tlhelp32.h>

#include <cwchar>
#include <cwctype>
#include <string>

namespace {

std::wstring strip_exe(const wchar_t *name) {
    std::wstring s(name);
    if (s.size() > 4 && _wcsicmp(s.c_str() + s.size() - 4, L".exe") == 0)
        s.resize(s.size() - 4);
    return s;
}

}  // namespace

bool match_name(const wchar_t *proc, const wchar_t *target) {
    std::wstring p = strip_exe(proc);
    std::wstring t = strip_exe(target);
    if (PIG_MATCH_SUBSTRING) {
        for (auto &c : p) c = (wchar_t)towlower(c);
        for (auto &c : t) c = (wchar_t)towlower(c);
        return p.find(t) != std::wstring::npos;
    }
    return _wcsicmp(p.c_str(), t.c_str()) == 0;
}

std::vector<DWORD> find_pids(const wchar_t *target) {
    std::vector<DWORD> pids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return pids;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (match_name(pe.szExeFile, target))
                pids.push_back(pe.th32ProcessID);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pids;
}
