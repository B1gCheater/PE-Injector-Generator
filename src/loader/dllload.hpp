// dllload.hpp — local DLL memory loading (MemoryModule-style).
#pragma once

// Maps a raw x64 DLL into the loader process and runs its entry point
// (DllMain). If export_name is non-null, resolves and calls that export
// (no-arg) after DllMain returns. If ti is true, impersonates TrustedInstaller
// first (DllMain/export run inline on this thread, so the token is kept).
// Returns a loader exit code (0 = success).
int dll_load_local(const unsigned char *data, unsigned int len, const wchar_t *export_name, bool ti);
