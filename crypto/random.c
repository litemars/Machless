/*
 * Cryptographically secure random bytes via CommonCrypto.
 * Fall back to /dev/urandom if the CommonCrypto call fails.
 */
#include "machless.h"

#include <stdio.h>
#include <stdlib.h>
#include <CommonCrypto/CommonRandom.h>

int ml_random_bytes(uint8_t *out, size_t n) {
    if (CCRandomGenerateBytes(out, n) == kCCSuccess) return 0;

    FILE *u = fopen("/dev/urandom", "rb");
    if (!u) return -1;
    size_t r = fread(out, 1, n, u);
    fclose(u);
    return r == n ? 0 : -1;
}
