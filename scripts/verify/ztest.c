#include <stdio.h>
#include <string.h>
#include "zstd.h"

/* zstd 静态库链接验证：版本号 + 压缩/解压往返。
 * 该 .lib 是 MinGW 编的，链接必须加 -alternatename:___chkstk_ms=__chkstk */
int main(void)
{
    printf("ZSTD_versionNumber: %u\n", ZSTD_versionNumber());

    const char *src =
        "hello PE-Injector-Generator, this is a zstd roundtrip test payload 1234567890";
    size_t srcLen = strlen(src);
    char cbuf[512], dbuf[512];

    size_t cSize = ZSTD_compress(cbuf, sizeof(cbuf), src, srcLen, 3);
    if (ZSTD_isError(cSize)) {
        printf("compress error: %s\n", ZSTD_getErrorName(cSize));
        return 1;
    }
    size_t dSize = ZSTD_decompress(dbuf, sizeof(dbuf), cbuf, cSize);
    if (ZSTD_isError(dSize)) {
        printf("decompress error: %s\n", ZSTD_getErrorName(dSize));
        return 1;
    }
    printf("roundtrip: %zu -> %zu -> %zu, match=%d\n", srcLen, cSize, dSize,
           (dSize == srcLen && memcmp(src, dbuf, dSize) == 0) ? 1 : 0);
    return 0;
}
