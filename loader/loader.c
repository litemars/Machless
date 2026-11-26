/*
 * Core loader logic — parses a packed container, decrypts the right slice,
 * and hands off to the execution backend.
 *
 * Shared between the standalone exe (loader/main.c) and the injectable
 * dylib variant (loader/injectable.c).
 */
#include "machless.h"
#include "machoutil/machoutil.h"
#include "crypto/crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

const ml_pack_header_t *ml_find_header(const uint8_t *data, size_t size) {
    if (!data || size < sizeof(ml_pack_header_t)) return NULL;
    if ((uintptr_t)data % _Alignof(ml_pack_header_t) != 0) return NULL;

    const ml_pack_header_t *h = (const ml_pack_header_t *)data;
    if (h->magic != ML_MAGIC || h->version != ML_FORMAT_VERSION) return NULL;
    if (h->cipher_suite != ML_CIPHER_NONE &&
        h->cipher_suite != ML_CIPHER_AES256_GCM &&
        h->cipher_suite != ML_CIPHER_CHACHA20_P) return NULL;
#ifdef ML_CIPHER_ONLY
    if (h->cipher_suite != ML_CIPHER_ONLY) return NULL;
#endif
    if (h->slice_count < 1 || h->slice_count > ML_MAX_SLICES) return NULL;
    if (h->flags & ~ML_KNOWN_FLAGS) return NULL;
    if ((h->flags & ML_FLAG_SPLIT_KEY) &&
        h->cipher_suite == ML_CIPHER_NONE) return NULL;
    for (size_t i = 0; i < sizeof(h->reserved); i++)
        if (h->reserved[i] != 0) return NULL;

    const size_t blob_size = size - sizeof(*h);
    size_t expected_offset = 0;
    for (uint32_t i = 0; i < h->slice_count; i++) {
        const ml_slice_t *slice = &h->slices[i];
        const size_t ciphertext_size = (size_t)slice->ciphertext_size;

        if (slice->ciphertext_size == 0 || slice->plaintext_size == 0 ||
            slice->ciphertext_size != slice->plaintext_size ||
            slice->plaintext_size > (uint32_t)INT_MAX) return NULL;

        /* The packer emits consecutive slices. Requiring that canonical
         * layout rejects overlap, gaps, integer wrap, and trailing bytes. */
        if ((size_t)slice->ciphertext_offset != expected_offset ||
            expected_offset > blob_size ||
            ciphertext_size > blob_size - expected_offset) return NULL;
        expected_offset += ciphertext_size;
    }
    if (expected_offset != blob_size) return NULL;

    return h;
}

/* Keep profile constants encoded and materialize their mask only after the
 * authenticated container has been selected. noinline prevents the optimizer
 * from turning the complementary profile back into a contiguous data key. */
#ifdef ML_BUILD_PROFILE
static uint32_t ml_rotl32(uint32_t value, unsigned count) {
    return (value << count) | (value >> (32u - count));
}
#endif

__attribute__((noinline))
static int ml_container_key(const ml_pack_header_t *hdr, uint8_t key[32]) {
    memcpy(key, hdr->master_key, 32);
    if (!(hdr->flags & ML_FLAG_SPLIT_KEY)) return 0;

#ifdef ML_BUILD_PROFILE
    volatile const ml_pack_header_t *source = hdr;
    uint8_t mask[32];
    uint32_t marker = source->magic;
    uint32_t word;
#define ML_PROFILE_WORD(index, rotation) do { \
        word = ML_KEY_ENCODED_##index ^ ML_KEY_MIX_##index ^ \
               ml_rotl32(marker, rotation); \
        memcpy(mask + (index) * sizeof(word), &word, sizeof(word)); \
    } while (0)
    ML_PROFILE_WORD(0, 3);
    ML_PROFILE_WORD(1, 7);
    ML_PROFILE_WORD(2, 11);
    ML_PROFILE_WORD(3, 13);
    ML_PROFILE_WORD(4, 17);
    ML_PROFILE_WORD(5, 19);
    ML_PROFILE_WORD(6, 23);
    ML_PROFILE_WORD(7, 29);
#undef ML_PROFILE_WORD
    for (size_t i = 0; i < sizeof(mask); i++) key[i] ^= mask[i];
    word = 0;
    ml_secure_zero(mask, sizeof(mask));
    return 0;
#else
    ml_secure_zero(key, 32);
    return -1;
#endif
}

int ml_decrypt_slice(const ml_pack_header_t *hdr,
                     const ml_slice_t *slice,
                     const uint8_t *ciphertext,
                     uint8_t *plaintext_out) {
    ml_aad_t aad;
    uint8_t  slice_idx = (uint8_t)(slice - hdr->slices);
    ml_build_aad(hdr, slice, slice_idx, &aad);

    int rc;
    uint8_t key[32];
    switch (hdr->cipher_suite) {
        case ML_CIPHER_NONE:
            memcpy(plaintext_out, ciphertext, slice->ciphertext_size);
            rc = 0;
            break;
        case ML_CIPHER_AES256_GCM:
#if !defined(ML_CIPHER_ONLY) || ML_CIPHER_ONLY == ML_CIPHER_AES256_GCM
            if (ml_container_key(hdr, key) != 0) return -1;
            rc = ml_aes256_gcm_decrypt(key, slice->iv,
                                       (const uint8_t *)&aad, sizeof(aad),
                                       ciphertext, slice->ciphertext_size,
                                       plaintext_out, slice->tag);
#else
            rc = -1;
#endif
            break;
        case ML_CIPHER_CHACHA20_P:
#if !defined(ML_CIPHER_ONLY) || ML_CIPHER_ONLY == ML_CIPHER_CHACHA20_P
            if (ml_container_key(hdr, key) != 0) return -1;
            rc = ml_chacha20_p1305_decrypt(key, slice->iv,
                                           (const uint8_t *)&aad, sizeof(aad),
                                           ciphertext, slice->ciphertext_size,
                                           plaintext_out, slice->tag);
#else
            rc = -1;
#endif
            break;
        default:
            rc = -1;
    }
    if (hdr->cipher_suite != ML_CIPHER_NONE) ml_secure_zero(key, sizeof(key));
    return rc;
}

int ml_load_and_run(const uint8_t *packed_data, size_t packed_size,
                    char *const argv[], char *const envp[]) {
    (void)argv; (void)envp;

    const ml_pack_header_t *hdr = ml_find_header(packed_data, packed_size);
    if (!hdr) { ML_DBG("invalid packed payload\n"); return -1; }

    const uint8_t *blob = (const uint8_t *)hdr + sizeof(*hdr);

#if defined(__arm64__)
    const uint32_t want = ML_ARCH_ARM64;
#elif defined(__x86_64__)
    const uint32_t want = ML_ARCH_X86_64;
#else
    ML_DBG("unsupported host architecture\n");
    return -1;
#endif

    const ml_slice_t *chosen = NULL;
    for (uint32_t i = 0; i < hdr->slice_count; i++) {
        if (hdr->slices[i].cpu_type == want) { chosen = &hdr->slices[i]; break; }
    }
    if (!chosen) { ML_DBG("no payload slice for host architecture\n"); return -1; }

    uint8_t *plain = malloc(chosen->plaintext_size);
    if (!plain) return -1;

    if (ml_decrypt_slice(hdr, chosen,
                         blob + chosen->ciphertext_offset,
                         plain) != 0) {
        ML_DBG("decrypt/auth failed\n");
        ml_secure_zero(plain, chosen->plaintext_size);
        free(plain);
        return -1;
    }

    /* Check the dylib header before passing plaintext to the backend.
     * AEAD authenticates encrypted slices; NONE provides no authentication. */
    if (!ml_is_macho_dylib(plain, chosen->plaintext_size)) {
        ML_DBG("decrypted payload is not a Mach-O dylib\n");
        ml_secure_zero(plain, chosen->plaintext_size);
        free(plain);
        return -1;
    }

    int rc = ml_execute_from_memory(plain, chosen->plaintext_size);

    /* ReflectiveLoader copies every mapped segment and changes its internal
     * fMachOData/fLinkEditBase pointers to those mappings before returning.
     * Remove the redundant RW source image regardless of result. */
    ml_secure_zero(plain, chosen->plaintext_size);
    free(plain);
    return rc;
}
