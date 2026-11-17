// codec.cpp — payload decode chain: base64 -> AES -> zstd.
//
// The generator embeds data with bin2source and stamps each job's transform
// flags in jobs.h (see codec.hpp for the flag layout).

#include "codec.hpp"
#include "config.h"
#include "log.hpp"

extern "C" {
#include "aes.h"
#include "miniz.h"
}

#include <cstdlib>
#include <cstring>

#ifdef PIG_ZSTD
#include <zstd.h>
#endif

namespace {

int b64_val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

// Decodes RFC 4648 base64 (whitespace tolerated). Returns malloc'd bytes.
unsigned char *b64_decode(const char *txt, unsigned int txt_len, unsigned int *out_len) {
    unsigned char *out = static_cast<unsigned char *>(malloc(txt_len * 3 / 4 + 4));
    if (!out)
        return nullptr;
    unsigned int n = 0;
    unsigned int acc = 0;
    int bits = 0;
    for (unsigned int i = 0; i < txt_len; i++) {
        int v = b64_val(static_cast<unsigned char>(txt[i]));
        if (v < 0)
            continue;
        acc = (acc << 6) | static_cast<unsigned int>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[n++] = static_cast<unsigned char>((acc >> bits) & 0xFF);
        }
    }
    *out_len = n;
    return out;
}

// AES-256 decrypt. data = 16-byte IV followed by ciphertext.
unsigned char *aes_decrypt(const unsigned char *data, unsigned int len,
                           const unsigned char *key, bool ctr, unsigned int *out_len) {
    if (len < 16)
        return nullptr;
    const unsigned char *iv = data;
    const unsigned char *ct = data + 16;
    unsigned int ct_len = len - 16;

    unsigned char *out = static_cast<unsigned char *>(malloc(ct_len));
    if (!out)
        return nullptr;

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    if (ctr) {
        memcpy(out, ct, ct_len);
        AES_CTR_xcrypt_buffer(&ctx, out, ct_len);
        *out_len = ct_len;
    } else {
        memcpy(out, ct, ct_len);
        AES_CBC_decrypt_buffer(&ctx, out, ct_len);
        // strip PKCS#7 padding
        unsigned char pad = out[ct_len - 1];
        if (pad >= 1 && pad <= 16 && static_cast<unsigned int>(pad) <= ct_len)
            *out_len = ct_len - pad;
        else
            *out_len = ct_len;
    }
    return out;
}

}  // namespace

unsigned char *codec_decode(const job_t &j, const unsigned char *key, unsigned int *out_len) {
    const unsigned char *cur = j.data;
    unsigned int cur_len = j.len;
    unsigned char *owned = nullptr;  // malloc'd chain buffer, freed on the way

    // 1. base64
    if (j.codec & 0x04) {
        cur_len = static_cast<unsigned int>(strlen(reinterpret_cast<const char *>(cur)));
        unsigned int nlen = 0;
        unsigned char *d = b64_decode(reinterpret_cast<const char *>(cur), cur_len, &nlen);
        if (!d) { free(owned); return nullptr; }
        free(owned);
        owned = d;
        cur = d;
        cur_len = nlen;
    }

    // 2. AES
    if (j.codec & 0x08) {
        if (!key) { free(owned); return nullptr; }
        unsigned int nlen = 0;
        unsigned char *d = aes_decrypt(cur, cur_len, key, (j.codec & 0x10) != 0, &nlen);
        if (!d) { free(owned); return nullptr; }
        free(owned);
        owned = d;
        cur = d;
        cur_len = nlen;
    }

    // 3. decompress
    const int codec_kind = j.codec & 0x03;
    if (codec_kind == 1) {  // zstd
#ifdef PIG_ZSTD
        unsigned char *d = static_cast<unsigned char *>(malloc(j.raw_len));
        if (!d) { free(owned); return nullptr; }
        size_t r = ZSTD_decompress(d, j.raw_len, cur, cur_len);
        if (ZSTD_isError(r)) {
            free(d);
            free(owned);
            return nullptr;
        }
        free(owned);
        owned = d;
        cur = d;
        cur_len = static_cast<unsigned int>(r);
#else
        free(owned);
        return nullptr;  // zstd not linked into this build
#endif
    } else if (codec_kind == 2) {  // deflate (raw, RFC 1951)
        unsigned char *d = static_cast<unsigned char *>(malloc(j.raw_len));
        if (!d) { free(owned); return nullptr; }
        mz_stream stream;
        memset(&stream, 0, sizeof(stream));
        if (mz_inflateInit2(&stream, -MZ_DEFAULT_WINDOW_BITS) != MZ_OK) {
            free(d);
            free(owned);
            return nullptr;
        }
        stream.next_in = const_cast<unsigned char *>(cur);
        stream.avail_in = cur_len;
        stream.next_out = d;
        stream.avail_out = j.raw_len;
        int r = mz_inflate(&stream, MZ_FINISH);
        mz_inflateEnd(&stream);
        if (r != MZ_STREAM_END) {
            free(d);
            free(owned);
            return nullptr;
        }
        free(owned);
        owned = d;
        cur = d;
        cur_len = j.raw_len;
    }

    if (owned) {
        *out_len = cur_len;
        return owned;
    }
    // raw: return a malloc'd copy so the caller can always free()
    unsigned char *out = static_cast<unsigned char *>(malloc(cur_len));
    if (!out)
        return nullptr;
    memcpy(out, cur, cur_len);
    *out_len = cur_len;
    return out;
}
