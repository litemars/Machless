/*
 * ChaCha20-Poly1305 AEAD (RFC 8439) implementation.
 *
 * Implements ChaCha20 and Poly1305 locally.
 */
#include "machless.h"
#include "crypto/crypto.h"

#include <string.h>

/* ── Little-endian load/store ──────────────────────────────────── */
static uint32_t LE32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void STORE32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;       p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void STORE64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

/* ── ChaCha20 ──────────────────────────────────────────────────── */
#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static void chacha20_block(uint32_t state[16], uint8_t out[64]) {
    uint32_t x[16];
    memcpy(x, state, sizeof(x));
    for (int i = 0; i < 10; i++) {
#define QR(a,b,c,d) \
    x[a]+=x[b]; x[d]^=x[a]; x[d]=ROTL32(x[d],16); \
    x[c]+=x[d]; x[b]^=x[c]; x[b]=ROTL32(x[b],12); \
    x[a]+=x[b]; x[d]^=x[a]; x[d]=ROTL32(x[d],8);  \
    x[c]+=x[d]; x[b]^=x[c]; x[b]=ROTL32(x[b],7);
        QR(0,4, 8,12); QR(1,5, 9,13); QR(2,6,10,14); QR(3,7,11,15);
        QR(0,5,10,15); QR(1,6,11,12); QR(2,7, 8,13); QR(3,4, 9,14);
#undef QR
    }
    for (int i = 0; i < 16; i++) STORE32(out + 4*i, x[i] + state[i]);
    ml_secure_zero(x, sizeof(x));
}

static void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                         uint32_t counter,
                         const uint8_t *in, size_t len, uint8_t *out) {
    uint32_t s[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        LE32(key),    LE32(key+4),  LE32(key+8),  LE32(key+12),
        LE32(key+16), LE32(key+20), LE32(key+24), LE32(key+28),
        counter, LE32(nonce), LE32(nonce+4), LE32(nonce+8),
    };
    uint8_t block[64];
    while (len) {
        chacha20_block(s, block);
        size_t n = len < 64 ? len : 64;
        for (size_t i = 0; i < n; i++) out[i] = in[i] ^ block[i];
        in  += n; out += n; len -= n;
        s[12]++;
    }
    ml_secure_zero(block, sizeof(block));
    ml_secure_zero(s, sizeof(s));
}

/* ── Poly1305 (RFC 8439 section 2.5) ──────────────────────────── */
typedef struct {
    uint32_t r[5];      /* clamped r, base 2^26 */
    uint32_t h[5];      /* accumulator */
    uint32_t pad[4];    /* s */
    uint8_t  buf[16];
    size_t   buf_used;
} poly1305_t;

static void poly1305_init(poly1305_t *p, const uint8_t key[32]) {
    uint32_t t0 = LE32(key   );
    uint32_t t1 = LE32(key+ 4);
    uint32_t t2 = LE32(key+ 8);
    uint32_t t3 = LE32(key+12);
    p->r[0] =  t0                         & 0x3ffffff;
    p->r[1] = ((t0 >> 26) | (t1 <<  6))   & 0x3ffff03;
    p->r[2] = ((t1 >> 20) | (t2 << 12))   & 0x3ffc0ff;
    p->r[3] = ((t2 >> 14) | (t3 << 18))   & 0x3f03fff;
    p->r[4] =  (t3 >>  8)                 & 0x00fffff;
    p->h[0]=p->h[1]=p->h[2]=p->h[3]=p->h[4] = 0;
    p->pad[0]=LE32(key+16); p->pad[1]=LE32(key+20);
    p->pad[2]=LE32(key+24); p->pad[3]=LE32(key+28);
    p->buf_used = 0;
}

static void poly1305_blocks(poly1305_t *p, const uint8_t *m, size_t bytes, int final) {
    uint32_t r0=p->r[0], r1=p->r[1], r2=p->r[2], r3=p->r[3], r4=p->r[4];
    uint32_t s1=r1*5, s2=r2*5, s3=r3*5, s4=r4*5;
    uint32_t h0=p->h[0], h1=p->h[1], h2=p->h[2], h3=p->h[3], h4=p->h[4];
    uint32_t hibit = final ? 0 : (1u << 24);

    while (bytes >= 16) {
        uint32_t t0=LE32(m), t1=LE32(m+4), t2=LE32(m+8), t3=LE32(m+12);
        h0 +=  t0                       & 0x3ffffff;
        h1 += ((t0 >> 26) | (t1 <<  6)) & 0x3ffffff;
        h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
        h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
        h4 += (t3 >> 8) | hibit;

        uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;

        uint32_t c;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff; d1 += c;
        c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff; d2 += c;
        c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff; d3 += c;
        c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff; d4 += c;
        c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff; h0 += c * 5;
        c = h0 >> 26;            h0 = h0 & 0x3ffffff;            h1 += c;

        m     += 16;
        bytes -= 16;
    }
    p->h[0]=h0; p->h[1]=h1; p->h[2]=h2; p->h[3]=h3; p->h[4]=h4;
}

static void poly1305_update(poly1305_t *p, const uint8_t *m, size_t bytes) {
    if (p->buf_used) {
        size_t want = 16 - p->buf_used;
        if (want > bytes) want = bytes;
        memcpy(p->buf + p->buf_used, m, want);
        p->buf_used += want; m += want; bytes -= want;
        if (p->buf_used == 16) {
            poly1305_blocks(p, p->buf, 16, 0);
            p->buf_used = 0;
        }
    }
    if (bytes >= 16) {
        size_t whole = bytes & ~(size_t)15;
        poly1305_blocks(p, m, whole, 0);
        m += whole; bytes -= whole;
    }
    if (bytes) { memcpy(p->buf, m, bytes); p->buf_used = bytes; }
}

static void poly1305_finish(poly1305_t *p, uint8_t mac[16]) {
    if (p->buf_used) {
        p->buf[p->buf_used++] = 1;
        memset(p->buf + p->buf_used, 0, 16 - p->buf_used);
        poly1305_blocks(p, p->buf, 16, 1);
    }
    uint32_t h0=p->h[0], h1=p->h[1], h2=p->h[2], h3=p->h[3], h4=p->h[4];
    uint32_t c;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c*5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    uint32_t g0=h0+5, g1, g2, g3, g4;
    c = g0 >> 26; g0 &= 0x3ffffff; g1 = h1 + c;
    c = g1 >> 26; g1 &= 0x3ffffff; g2 = h2 + c;
    c = g2 >> 26; g2 &= 0x3ffffff; g3 = h3 + c;
    c = g3 >> 26; g3 &= 0x3ffffff; g4 = h4 + c - (1u << 26);

    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    uint32_t f0 = (h0      ) | (h1 << 26);
    uint32_t f1 = (h1 >>  6) | (h2 << 20);
    uint32_t f2 = (h2 >> 12) | (h3 << 14);
    uint32_t f3 = (h3 >> 18) | (h4 <<  8);

    uint64_t t;
    t = (uint64_t)f0 + p->pad[0]; f0 = (uint32_t)t;
    t = (uint64_t)f1 + p->pad[1] + (t >> 32); f1 = (uint32_t)t;
    t = (uint64_t)f2 + p->pad[2] + (t >> 32); f2 = (uint32_t)t;
    t = (uint64_t)f3 + p->pad[3] + (t >> 32); f3 = (uint32_t)t;

    STORE32(mac,    f0);
    STORE32(mac+4,  f1);
    STORE32(mac+8,  f2);
    STORE32(mac+12, f3);
    ml_secure_zero(p, sizeof(*p));
}

/* ── AEAD wrapper (RFC 8439 section 2.8) ──────────────────────── */
static void aead_tag(const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *ct, size_t ct_len,
                     uint8_t tag[16]) {
    /* Generate Poly1305 one-time key from ChaCha20 block 0 */
    uint8_t poly_key[64] = {0};
    chacha20_xor(key, nonce, 0, poly_key, 32, poly_key);

    poly1305_t p;
    poly1305_init(&p, poly_key);

    uint8_t pad[16] = {0};
    poly1305_update(&p, aad, aad_len);
    if (aad_len % 16) poly1305_update(&p, pad, 16 - (aad_len % 16));

    poly1305_update(&p, ct, ct_len);
    if (ct_len % 16) poly1305_update(&p, pad, 16 - (ct_len % 16));

    uint8_t lengths[16];
    STORE64(lengths,   (uint64_t)aad_len);
    STORE64(lengths+8, (uint64_t)ct_len);
    poly1305_update(&p, lengths, 16);

    poly1305_finish(&p, tag);
    ml_secure_zero(poly_key, sizeof(poly_key));
}

static int ct_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
    return d == 0;
}

int ml_chacha20_p1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *in, size_t len,
                              uint8_t *out, uint8_t tag[16]) {
    chacha20_xor(key, nonce, 1, in, len, out);
    aead_tag(key, nonce, aad, aad_len, out, len, tag);
    return 0;
}

int ml_chacha20_p1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *in, size_t len,
                              uint8_t *out, const uint8_t tag[16]) {
    uint8_t computed[16];
    aead_tag(key, nonce, aad, aad_len, in, len, computed);
    if (!ct_eq(computed, tag, 16)) {
        ml_secure_zero(computed, sizeof(computed));
        return -1;
    }
    chacha20_xor(key, nonce, 1, in, len, out);
    ml_secure_zero(computed, sizeof(computed));
    return 0;
}
