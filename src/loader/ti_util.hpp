// ti_util.hpp — shared TrustedInstaller impersonation helper.
#pragma once

#include "config.h"
#include "log.hpp"

#include "ti.h"

#include <windows.h>

// Best-effort TrustedInstaller impersonation on the current thread.
// On any failure it returns false and the caller keeps its existing token
// (e.g. the elevated administrator). Impersonation is thread-level, so any
// code that must run as TI has to execute INLINE on this same thread.
inline bool ti_impersonate() {
    HANDLE tok = nullptr;
    DWORD e = TiCreateToken(TI_SESSION_CURRENT, &tok);
    if (e != ERROR_SUCCESS) {
        PIG_LOG(L"ti: TiCreateToken failed err=%u", e);
        return false;
    }
    HANDLE imp = nullptr;
    if (!DuplicateTokenEx(tok, TOKEN_IMPERSONATE | TOKEN_QUERY, nullptr,
                          SecurityImpersonation, TokenImpersonation, &imp)) {
        PIG_LOG(L"ti: DuplicateTokenEx failed err=%u", GetLastError());
        CloseHandle(tok);
        return false;
    }
    CloseHandle(tok);
    if (!SetThreadToken(nullptr, imp)) {
        PIG_LOG(L"ti: SetThreadToken failed err=%u", GetLastError());
        CloseHandle(imp);
        return false;
    }
    CloseHandle(imp);
    PIG_LOG(L"ti: impersonating TrustedInstaller");
    return true;
}
