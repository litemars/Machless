/* Matryoshka entry point. Decrypt the outer ChaCha20-Poly1305 layer, then
 * pass its inner AES-256-GCM packed blob to the shared loader. */
#include "machless.h"
#include "crypto/crypto.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

int main(void) {

    const uint8_t *packed = NULL;
    size_t packed_size = 0;
    if (ml_get_embedded_payload((const void *)&main,
                                &packed, &packed_size) != 0) return 1;

    const ml_pack_header_t *hdr = ml_find_header(packed, packed_size);
    if (!hdr || hdr->cipher_suite != ML_CIPHER_CHACHA20_P || hdr->slice_count != 1) {
        return 1;
    }
    const ml_slice_t *sl = &hdr->slices[0];
    const uint8_t *ct = (const uint8_t *)hdr + sizeof(*hdr) + sl->ciphertext_offset;

    uint8_t *inner_blob = malloc(sl->plaintext_size);
    if (!inner_blob) return 1;

    if (ml_decrypt_slice(hdr, sl, ct, inner_blob) != 0) {
        ml_secure_zero(inner_blob, sl->plaintext_size);
        free(inner_blob); return 1;
    }

    if (ml_load_and_run(inner_blob, sl->plaintext_size, NULL, NULL) != 0) {
        ml_secure_zero(inner_blob, sl->plaintext_size);
        free(inner_blob); return 1;
    }

    /* ml_load_and_run retains its decrypted dylib on success. The inner
     * packed buffer is no longer needed; keep payload threads alive. */
    ml_secure_zero(inner_blob, sl->plaintext_size);
    free(inner_blob);
    pthread_exit(NULL);
    return 0;
}
