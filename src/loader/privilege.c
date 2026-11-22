// privilege.c - privilege level probe.
//
// Classifies the current process token into three tiers:
//   plain user (0) < elevated admin (1) < SYSTEM / TrustedInstaller (2).
// Uses only the documented token APIs (no external references).
#include "privilege.h"

#include <windows.h>
#include <sddl.h>
#include <stdlib.h>

// True when the token's user SID is SYSTEM (S-1-5-18) or the TrustedInstaller
// service account (S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464).
static int token_is_system_or_ti(HANDLE hToken)
{
    DWORD size = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &size);
    if (size == 0)
        return 0;
    PTOKEN_USER user = (PTOKEN_USER)malloc(size);
    if (!user)
        return 0;

    int level = 0;
    if (GetTokenInformation(hToken, TokenUser, user, size, &size)) {
        BYTE systemSid[SECURITY_MAX_SID_SIZE];
        DWORD cbSystem = sizeof(systemSid);
        PSID tiSid = NULL;

        if (CreateWellKnownSid(WinLocalSystemSid, NULL, systemSid, &cbSystem) &&
            EqualSid(user->User.Sid, systemSid)) {
            level = 2;  // SYSTEM
        } else if (ConvertStringSidToSidA(
                       "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
                       &tiSid)) {
            if (EqualSid(user->User.Sid, tiSid))
                level = 2;  // TrustedInstaller service account
            LocalFree(tiSid);
        }
    }
    free(user);
    return level;
}

int privilege_level(void)
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return 0;

    int level = token_is_system_or_ti(hToken);

    if (level == 0) {
        BYTE adminSid[SECURITY_MAX_SID_SIZE];
        DWORD cbAdmin = sizeof(adminSid);
        BOOL isAdmin = FALSE;
        if (CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, adminSid,
                               &cbAdmin) &&
            CheckTokenMembership(NULL, adminSid, &isAdmin) && isAdmin)
            level = 1;
    }

    CloseHandle(hToken);
    return level;
}
