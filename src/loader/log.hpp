// log.hpp — compile-time pruned logging (PE-Injector-Generator loader).
#pragma once

#include "config.h"
#include <cstdio>

// Logs are compiled in only for a debug console build; GUI builds (or
// release builds) get zero logging and zero log strings in the binary.
#if PIG_DEBUG && PIG_CONSOLE
#define PIG_LOG(...)                      \
    do {                                  \
        wprintf(L"[pig] " __VA_ARGS__);   \
        wprintf(L"\n");                   \
    } while (0)
#else
#define PIG_LOG(...) do { } while (0)
#endif
