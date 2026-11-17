// remotemap.hpp — remote DLL manual map (reflective loading without disk).
#pragma once

// Maps and loads a raw x64 DLL into the target process via a position
// independent loader stub (no disk write, no LoadLibrary in the target).
// If ti is true, a TrustedInstaller impersonation token is duplicated into the
// target and the stub impersonates it before running DllMain (best effort).
// Returns a loader exit code (0 = success).
int dll_remote_map(const unsigned char *dll, unsigned int dll_len, const wchar_t *target, bool ti);
