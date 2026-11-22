// privilege.h - current process privilege level probe.
//
// Determines the elevation level of the current process token so the loader
// can gate itself early: a plain user cannot inject remotely or elevate.
#ifndef PRIVILEGE_H
#define PRIVILEGE_H

#ifdef __cplusplus
extern "C" {
#endif

// Returns:
//   0 - plain user
//   1 - member of BUILTIN\Administrators (elevated admin token)
//   2 - SYSTEM or TrustedInstaller token
int privilege_level(void);

#ifdef __cplusplus
}
#endif

#endif  // PRIVILEGE_H
