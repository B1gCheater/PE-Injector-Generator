// codec.hpp — payload decode chain.
#pragma once

#include "jobs.h"

// Decodes the job's payload per job.codec into raw bytes.
//   codec & 0x03: 0=raw 1=zstd 2=deflate
//   codec & 0x04: base64 (data is a NUL-terminated base64 string)
//   codec & 0x08: AES-256 encrypted (key = 32 bytes, IV prepended)
//   codec & 0x10: CTR mode (else CBC, PKCS#7 padded)
// Returns a malloc'd buffer (caller frees) or nullptr on failure.
unsigned char *codec_decode(const job_t &j, const unsigned char *key, unsigned int *out_len);
