// proc.hpp — process enumeration and name matching.
#pragma once

#include <windows.h>
#include <vector>

// True if the process image name matches the target (exact or substring,
// case-insensitive, ".exe" stripped), per the PIG_MATCH_SUBSTRING config.
bool match_name(const wchar_t *proc, const wchar_t *target);

// PIDs of all processes whose image name matches target.
std::vector<DWORD> find_pids(const wchar_t *target);
