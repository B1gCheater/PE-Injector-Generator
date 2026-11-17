/*
 * ti.h - TiLib: borrow the TrustedInstaller token and launch processes with it.
 *
 * Static library, pure C ABI. Link ti.lib plus advapi32.lib and wtsapi32.lib.
 *
 * Design guarantees (see TiLib-API design doc):
 *   - No CRT dependency: only kernel32 / advapi32 / wtsapi32 imports.
 *   - No global state: thread-safe, reentrant, position-independent friendly.
 *   - No assumption about the caller's own image (works from a DLL or an
 *     injected payload): no GetModuleFileName / resource / manifest / console
 *     assumptions, no printing, no dialogs.
 *   - Thread-token etiquette: any SYSTEM impersonation performed internally
 *     saves and restores the calling thread's original token, even on failure.
 *
 * Requirement: the caller must already run as an elevated administrator.
 * The library never elevates itself; it borrows the TrustedInstaller token
 * using the admin's SeDebugPrivilege. Without elevation it returns
 * ERROR_ACCESS_DENIED.
 *
 * Error model: every DWORD-returning function returns a Win32 error code.
 * ERROR_SUCCESS (0) means success. Use FormatMessage to describe failures.
 */

#ifndef TI_H
#define TI_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Pass to TiCreateToken to use the calling process's current session. */
#define TI_SESSION_CURRENT ((DWORD)-1)

/* TiLaunchAsParent flag: create the child suspended, do NOT enable its
 * privileges and do NOT resume it; the caller controls the child afterwards. */
#define TI_SUSPENDED 0x00000001u

/* Output of the launch functions. The caller owns hProcess / hThread and
 * must CloseHandle them. cbSize must be set to sizeof(TI_LAUNCH_INFO). */
typedef struct _TI_LAUNCH_INFO {
    DWORD  cbSize;
    HANDLE hProcess;
    HANDLE hThread;
    DWORD  dwProcessId;
    DWORD  dwThreadId;
} TI_LAUNCH_INFO;

/* ---- High-level convenience ------------------------------------------------ */

/* Route C: launch pszCommandLine as TrustedInstaller in a NEW console window.
 * One shot: elevation check -> SeDebug -> start TI service -> parent-process
 * attribute -> create suspended -> enable all privileges -> resume.
 * Does not wait. pInfo may be NULL (handles closed internally). */
DWORD TiRunNewWindow(LPCWSTR pszCommandLine, TI_LAUNCH_INFO* pInfo);

/* Route B: launch pszCommandLine as TrustedInstaller in the CALLER'S console
 * (seamless, no new window), wait for it, and return its exit code.
 * Requires the caller to have a console (else ERROR_INVALID_HANDLE).
 * pdwExitCode may be NULL. */
DWORD TiRunSeamless(LPCWSTR pszCommandLine, DWORD* pdwExitCode);

/* ---- Building blocks ------------------------------------------------------- */

/* TRUE if the current process token is an elevated administrator. */
BOOL TiIsElevated(void);

/* The calling process's session id (falls back to the active console session). */
DWORD TiCurrentSessionId(void);

/* Enable SeDebugPrivilege on the current process token. */
DWORD TiEnableDebugPrivilege(void);

/* Start / wait for the TrustedInstaller service to run; output its PID.
 * 30s internal timeout; tolerates ERROR_SERVICE_ALREADY_RUNNING. */
DWORD TiStartService(DWORD* pdwPid);

/* Build a full-privilege TrustedInstaller PRIMARY token:
 *   save caller thread token -> impersonate SYSTEM (services.exe) ->
 *   open TI process token -> DuplicateTokenEx(TokenPrimary) ->
 *   set TokenSessionId = dwSessionId -> enable all privileges ->
 *   restore caller thread token.
 * dwSessionId: a session id, or TI_SESSION_CURRENT for the caller's session.
 * *phToken is owned by the caller (CloseHandle). Needs SeDebug (auto-enabled).
 *
 * Injection recipe: to run code (e.g. shellcode) on the CURRENT thread as TI,
 * duplicate *phToken to an impersonation token and SetThreadToken it, then run
 * the code inline on that same thread. A NEW thread does NOT inherit the
 * impersonation, and CreateProcess from an impersonating thread uses the
 * process primary token (not TI) -- use TiLaunchWithToken for TI children. */
DWORD TiCreateToken(DWORD dwSessionId, HANDLE* phToken);

/* Enable every available privilege on hToken (missing ones skipped).
 * pdwEnabled (may be NULL) receives the count actually enabled. */
DWORD TiEnableAllPrivileges(HANDLE hToken, DWORD* pdwEnabled);

/* Route C creation step: create a child with TrustedInstaller as its parent
 * process (child inherits the TI token). Internally does SeDebug / service /
 * open TI process. dwCreationFlags are caller-controlled; the library forces
 * EXTENDED_STARTUPINFO_PRESENT and CREATE_NEW_CONSOLE. Pass TI_SUSPENDED to
 * create suspended without enabling privileges / resuming. */
DWORD TiLaunchAsParent(LPCWSTR pszCommandLine, DWORD dwCreationFlags,
                       TI_LAUNCH_INFO* pInfo);

/* Route B creation step: CreateProcessAsUser with the caller-supplied token.
 * bSeamless TRUE: flags = 0, inherit the caller's console (requires a console);
 * FALSE: CREATE_NEW_CONSOLE. Does not wait. */
DWORD TiLaunchWithToken(HANDLE hToken, LPCWSTR pszCommandLine,
                        BOOL bSeamless, TI_LAUNCH_INFO* pInfo);

/* Wait for hProcess to exit and return its exit code. dwTimeoutMs may be
 * INFINITE. On timeout returns ERROR_TIMEOUT and does NOT kill the process. */
DWORD TiWaitExit(HANDLE hProcess, DWORD dwTimeoutMs, DWORD* pdwExitCode);

#ifdef __cplusplus
}
#endif

#endif /* TI_H */