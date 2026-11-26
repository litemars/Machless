/*
 * Internal crypto interface used by the packer and loaders.
 */
#ifndef MACHLESS_CRYPTO_H
#define MACHLESS_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

void ml_secure_zero(void *memory, size_t size);

/* RNG */
int ml_random_bytes(uint8_t *out, size_t n);

/* AES-256-GCM authenticated encryption.
 *   key: 32 bytes, iv: 12 bytes, tag: 16 bytes.
 *   in/out may alias (in-place is supported).
 * Returns 0 on success, -1 on failure (decrypt: tag mismatch).
 */
int ml_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t iv[12],
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *in,  size_t len,
                          uint8_t *out, uint8_t tag[16]);

int ml_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t iv[12],
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *in,  size_t len,
                          uint8_t *out, const uint8_t tag[16]);

/* ChaCha20-Poly1305 AEAD (RFC 8439). 12-byte nonce, 16-byte tag. */
int ml_chacha20_p1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *in, size_t len,
                              uint8_t *out, uint8_t tag[16]);

int ml_chacha20_p1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *in, size_t len,
                              uint8_t *out, const uint8_t tag[16]);

#endif
