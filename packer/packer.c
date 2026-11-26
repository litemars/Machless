#include "machless.h"
#include "machoutil/machoutil.h"
#include "crypto/crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>

static int read_file(const char *path, uint8_t **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno)); return -1; }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz <= 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
    /* Slice lengths and offsets are uint32_t in format v3, while the
     * reflective-loading backend accepts an int-sized image. Refuse inputs
     * that cannot be represented instead of silently truncating them. */
    if ((unsigned long)sz > UINT32_MAX || sz > INT_MAX) {
        fprintf(stderr, "%s is too large for the packed format\n", path);
        fclose(f);
        return -1;
    }
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return -1;
    }
    fclose(f);
    *out = buf;
    *out_len = (size_t)sz;
    return 0;
}

static int write_file(const char *path, const void *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t w = fwrite(data, 1, len, f);
    fclose(f);
    return w == len ? 0 : -1;
}

int ml_encrypt_slice(ml_pack_header_t *hdr,
                     ml_slice_t *slice,
                     const uint8_t *plaintext, size_t plaintext_size,
                     uint8_t **ciphertext_out, size_t *ciphertext_size_out) {
    if (!hdr || !slice || !plaintext || !ciphertext_out ||
        !ciphertext_size_out || plaintext_size == 0 ||
        plaintext_size > UINT32_MAX || plaintext_size > INT_MAX) {
        return -1;
    }
    /* Generate a per-slice IV; the NONE cipher does not use it. */
    if (ml_random_bytes(slice->iv, sizeof(slice->iv)) != 0) return -1;

    /* Populate sizes before building AAD so an AEAD tag covers them. */
    slice->plaintext_size  = (uint32_t)plaintext_size;
    slice->ciphertext_size = (uint32_t)plaintext_size;

    ml_aad_t aad;
    uint8_t  slice_idx = (uint8_t)(slice - hdr->slices);
    ml_build_aad(hdr, slice, slice_idx, &aad);

    /* Allocate ciphertext buffer. AEADs do not change size. */
    uint8_t *ct = malloc(plaintext_size);
    if (!ct) return -1;

    switch (hdr->cipher_suite) {
        case ML_CIPHER_NONE:
            memcpy(ct, plaintext, plaintext_size);
            memset(slice->tag, 0, sizeof(slice->tag));
            break;

        case ML_CIPHER_AES256_GCM:
            if (ml_aes256_gcm_encrypt(hdr->master_key, slice->iv,
                                      (const uint8_t *)&aad, sizeof(aad),
                                      plaintext, plaintext_size,
                                      ct, slice->tag) != 0) {
                free(ct); return -1;
            }
            break;

        case ML_CIPHER_CHACHA20_P:
            if (ml_chacha20_p1305_encrypt(hdr->master_key, slice->iv,
                                          (const uint8_t *)&aad, sizeof(aad),
                                          plaintext, plaintext_size,
                                          ct, slice->tag) != 0) {
                free(ct); return -1;
            }
            break;

        default:
            free(ct); return -1;
    }

    *ciphertext_out      = ct;
    *ciphertext_size_out = plaintext_size;
    return 0;
}

int ml_pack_dylib(const char *input_dylib,
                  const char *output_packed,
                  uint16_t cipher_suite,
                  int raw,
                  uint32_t cpu_filter,
                  uint32_t marker,
                  const uint8_t key_mask[32]) {
    if (!input_dylib || !output_packed ||
        marker == 0 ||
        (cpu_filter != 0 && cpu_filter != ML_ARCH_ARM64 &&
         cpu_filter != ML_ARCH_X86_64) ||
        (cipher_suite != ML_CIPHER_NONE &&
         cipher_suite != ML_CIPHER_AES256_GCM &&
         cipher_suite != ML_CIPHER_CHACHA20_P)) {
        fprintf(stderr, "invalid packer arguments\n");
        return 1;
    }
    uint8_t *file = NULL;
    size_t file_size = 0;
    if (read_file(input_dylib, &file, &file_size) != 0) return 1;

    /* Raw mode skips Mach-O validation and fat slicing. */
    ml_slice_view_t views[ML_MAX_SLICES];
    size_t nviews;

    if (raw) {
        nviews = 1;
        views[0].data     = file;
        views[0].size     = file_size;
        views[0].cpu_type = 0;   /* not a Mach-O slice — opaque payload */
    } else {
        if (!ml_is_macho_dylib(file, file_size)) {
            fprintf(stderr, "input is not a Mach-O dylib\n");
            free(file);
            return 1;
        }
        nviews = ML_MAX_SLICES;
        if (ml_enumerate_slices(file, file_size, views, &nviews) != 0) {
            fprintf(stderr, "could not enumerate slices\n");
            free(file);
            return 1;
        }
        if (cpu_filter) {
            size_t selected = nviews;
            for (size_t i = 0; i < nviews; i++) {
                if (views[i].cpu_type == cpu_filter) { selected = i; break; }
            }
            if (selected == nviews) {
                fprintf(stderr, "requested architecture is not present\n");
                free(file);
                return 1;
            }
            views[0] = views[selected];
            nviews = 1;
        }
    }

    ml_pack_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic         = marker;
    hdr.version       = ML_FORMAT_VERSION;
    hdr.cipher_suite  = cipher_suite;
    hdr.slice_count   = (uint32_t)nviews;
    hdr.flags         = key_mask && cipher_suite != ML_CIPHER_NONE
                        ? ML_FLAG_SPLIT_KEY : 0;

    if (ml_random_bytes(hdr.master_key, sizeof(hdr.master_key)) != 0) {
        fprintf(stderr, "RNG failed\n");
        free(file);
        return 1;
    }

    uint8_t *blob = NULL;
    size_t   blob_size = 0;
    for (size_t i = 0; i < nviews; i++) {
        uint8_t *ct = NULL;
        size_t   ct_size = 0;
        hdr.slices[i].cpu_type = views[i].cpu_type;
        if (views[i].size == 0 || views[i].size > UINT32_MAX ||
            blob_size > UINT32_MAX || views[i].size > UINT32_MAX - blob_size) {
            fprintf(stderr, "packed payload exceeds format limits\n");
            free(blob); free(file);
            return 1;
        }
        hdr.slices[i].ciphertext_offset = (uint32_t)blob_size;
        if (ml_encrypt_slice(&hdr, &hdr.slices[i], views[i].data, views[i].size,
                             &ct, &ct_size) != 0) {
            fprintf(stderr, "encrypt failed (slice %zu)\n", i);
            free(blob); free(file);
            return 1;
        }
        if (ct_size > SIZE_MAX - blob_size) {
            free(ct); free(blob); free(file); return 1;
        }
        uint8_t *grown = realloc(blob, blob_size + ct_size);
        if (!grown) { free(ct); free(blob); free(file); return 1; }
        blob = grown;
        memcpy(blob + blob_size, ct, ct_size);
        blob_size += ct_size;
        free(ct);
    }

    if (blob_size > SIZE_MAX - sizeof(hdr)) {
        free(blob); free(file); return 1;
    }
    /* The encryption key is never present verbatim in a final packed section.
     * Its complementary mask is emitted only into the loader build profile. */
    if (hdr.flags & ML_FLAG_SPLIT_KEY) {
        for (size_t i = 0; i < sizeof(hdr.master_key); i++)
            hdr.master_key[i] ^= key_mask[i];
    }

    size_t out_size = sizeof(hdr) + blob_size;
    uint8_t *out = malloc(out_size);
    if (!out) { free(blob); free(file); return 1; }
    memcpy(out, &hdr, sizeof(hdr));
    memcpy(out + sizeof(hdr), blob, blob_size);

    int rc = write_file(output_packed, out, out_size);
    if (rc == 0) chmod(output_packed, 0644);

    ml_secure_zero(&hdr, sizeof(hdr));
    ml_secure_zero(blob, blob_size);
    ml_secure_zero(out, out_size);
    ml_secure_zero(file, file_size);
    free(out); free(blob); free(file);
    return rc == 0 ? 0 : 1;
}
