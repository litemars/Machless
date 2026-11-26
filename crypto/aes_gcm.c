/* AES-256-GCM through CommonCrypto. GCM mode and its helper functions are
 * exported by libSystem but absent from the public macOS SDK headers, so
 * this file declares them locally. */
#include "machless.h"
#include "crypto/crypto.h"

#include <string.h>
#include <CommonCrypto/CommonCryptor.h>

/* kCCModeGCM is value 11 in the SPI; the public header only goes up to
 * kCCModeCFB8 = 10. */
#ifndef kCCModeGCM
#define kCCModeGCM 11
#endif

extern CCCryptorStatus CCCryptorGCMAddIV (CCCryptorRef ref, const void *iv,  size_t iv_len);
extern CCCryptorStatus CCCryptorGCMAddAAD(CCCryptorRef ref, const void *aad, size_t aad_len);
extern CCCryptorStatus CCCryptorGCMFinal (CCCryptorRef ref,       void *tag, size_t *tag_len);

static CCCryptorStatus gcm_run(CCOperation op,
                               const uint8_t key[32], const uint8_t iv[12],
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *in,  size_t len,
                               uint8_t *out, uint8_t tag[16],
                               int is_decrypt) {
    CCCryptorRef ref = NULL;
    CCCryptorStatus s = CCCryptorCreateWithMode(
        op, kCCModeGCM, kCCAlgorithmAES,
        ccNoPadding, NULL, key, 32, NULL, 0, 0, 0, &ref);
    if (s != kCCSuccess) return s;

    s = CCCryptorGCMAddIV(ref, iv, 12);
    if (s != kCCSuccess) { CCCryptorRelease(ref); return s; }

    if (aad_len) {
        s = CCCryptorGCMAddAAD(ref, aad, aad_len);
        if (s != kCCSuccess) { CCCryptorRelease(ref); return s; }
    }

    size_t moved = 0;
    if (len) {
        s = CCCryptorUpdate(ref, in, len, out, len, &moved);
        if (s != kCCSuccess) { CCCryptorRelease(ref); return s; }
    }

    if (is_decrypt) {
        uint8_t got[16];
        memcpy(got, tag, 16);
        size_t tl = 16;
        s = CCCryptorGCMFinal(ref, got, &tl);
        /* On macOS, the tag is BOTH input (expected) and output (computed) for
         * decrypt. We trust the status code: kCCUnspecifiedError on mismatch. */
        if (s == kCCSuccess) {
            if (memcmp(got, tag, 16) != 0) s = kCCDecodeError;
        }
        ml_secure_zero(got, sizeof(got));
    } else {
        size_t tl = 16;
        s = CCCryptorGCMFinal(ref, tag, &tl);
        if (s == kCCSuccess && tl != 16) s = kCCParamError;
    }
    CCCryptorRelease(ref);
    return s;
}

int ml_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t iv[12],
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *in,  size_t len,
                          uint8_t *out, uint8_t tag[16]) {
    return gcm_run(kCCEncrypt, key, iv, aad, aad_len, in, len, out, tag, 0)
           == kCCSuccess ? 0 : -1;
}

int ml_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t iv[12],
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *in,  size_t len,
                          uint8_t *out, const uint8_t tag[16]) {
    uint8_t tag_copy[16];
    memcpy(tag_copy, tag, 16);
    return gcm_run(kCCDecrypt, key, iv, aad, aad_len, in, len, out,
                   tag_copy, 1) == kCCSuccess ? 0 : -1;
}
