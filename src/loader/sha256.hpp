// sha256.hpp — minimal SHA-256 (FIPS 180-4), public-domain algorithm.
#pragma once

#include <cstddef>

// Computes SHA-256 of data into out (32 bytes).
void sha256(const unsigned char *data, size_t len, unsigned char out[32]);
