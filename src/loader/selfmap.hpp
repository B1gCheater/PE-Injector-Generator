// selfmap.hpp — manual PE mapping (shared) + EXE self-mapping entry.
#pragma once

// Maps a raw x64 PE image (EXE or DLL) into a fresh region. Returns 0 and
// stores the base in *out_base on success; non-zero loader exit code on error.
int pe_map_image(const unsigned char *raw, unsigned int raw_len, void **out_base);

// Maps and runs a raw x64 EXE image in a freshly allocated region (never
// overwriting our own image). If args is non-null it is passed as the mapped
// EXE's command line. If ti is true, impersonates TrustedInstaller and runs
// the entry point inline (best effort; falls back to the caller's token).
// Returns a loader exit code (0 = success).
int selfmap_execute(const unsigned char *data, unsigned int len, const wchar_t *args, bool ti);
