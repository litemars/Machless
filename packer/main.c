/* Command-line entry point and per-artifact build-profile handling. */
#include "machless.h"

#include "crypto/crypto.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef struct {
    uint32_t marker;
    uint32_t encoded[8];
    uint32_t mix[8];
    uint8_t mask[32];
} ml_build_profile_t;

static const unsigned profile_rotations[8] = {3, 7, 11, 13, 17, 19, 23, 29};

static uint32_t rotl32(uint32_t value, unsigned count) {
    return (value << count) | (value >> (32u - count));
}

static void decode_profile(ml_build_profile_t *profile) {
    for (size_t i = 0; i < 8; i++) {
        uint32_t word = profile->encoded[i] ^ profile->mix[i] ^
                        rotl32(profile->marker, profile_rotations[i]);
        memcpy(profile->mask + i * sizeof(word), &word, sizeof(word));
    }
}

static int write_profile(const char *path, ml_build_profile_t *profile) {
    uint8_t raw[68];
    if (ml_random_bytes(raw, sizeof(raw)) != 0) return -1;

    memcpy(&profile->marker, raw, sizeof(profile->marker));
    if (profile->marker == 0 || profile->marker == ML_MAGIC)
        profile->marker ^= 0xa5935c2du;
    memcpy(profile->mask, raw + 4, sizeof(profile->mask));
    memcpy(profile->mix, raw + 36, sizeof(profile->mix));

    for (size_t i = 0; i < 8; i++) {
        uint32_t word;
        memcpy(&word, profile->mask + i * sizeof(word), sizeof(word));
        profile->encoded[i] = word ^ profile->mix[i] ^
                              rotl32(profile->marker, profile_rotations[i]);
    }

    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    int ok = fprintf(f,
        "#ifndef ML_BUILD_PROFILE\n"
        "#define ML_BUILD_PROFILE 1\n"
        "#define ML_MAGIC 0x%08Xu\n",
        profile->marker) > 0;
    for (size_t i = 0; i < 8 && ok; i++) {
        ok = fprintf(f, "#define ML_KEY_ENCODED_%zu 0x%08Xu\n",
                     i, profile->encoded[i]) > 0;
        ok = ok && fprintf(f, "#define ML_KEY_MIX_%zu 0x%08Xu\n",
                           i, profile->mix[i]) > 0;
    }
    if (ok) ok = fprintf(f, "#endif\n") > 0;
    if (fclose(f) != 0) ok = 0;
    if (ok) chmod(path, 0600);
    ml_secure_zero(raw, sizeof(raw));
    return ok ? 0 : -1;
}

static int read_profile(const char *path, ml_build_profile_t *profile) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    char line[160];
    unsigned seen_marker = 0;
    unsigned seen_encoded = 0;
    unsigned seen_mix = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned value;
        size_t index;
        if (sscanf(line, "#define ML_MAGIC 0x%Xu", &value) == 1) {
            profile->marker = (uint32_t)value;
            seen_marker++;
        } else if (sscanf(line, "#define ML_KEY_ENCODED_%zu 0x%Xu", &index,
                          &value) == 2 && index < 8) {
            profile->encoded[index] = (uint32_t)value;
            seen_encoded |= 1u << index;
        } else if (sscanf(line, "#define ML_KEY_MIX_%zu 0x%Xu", &index,
                          &value) == 2 && index < 8) {
            profile->mix[index] = (uint32_t)value;
            seen_mix |= 1u << index;
        }
    }
    int failed = ferror(f);
    fclose(f);
    if (failed || seen_marker != 1 || profile->marker == 0 ||
        seen_encoded != 0xffu || seen_mix != 0xffu) return -1;
    decode_profile(profile);
    return 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "machless-pack - pack a Mach-O dylib for in-memory loading.\n"
        "\n"
        "Usage: %s [options] <input> <output.packed>\n"
        "\n"
        "Options:\n"
        "  --cipher=<aes-gcm|chacha20|none> default: chacha20\n"
        "  --arch=<arm64|x86_64|all>        retain only the requested slice\n"
        "  --new-profile=<path>             create per-build key/magic header\n"
        "  --profile=<path>                 reuse a profile (nested packing)\n"
        "  --raw                            wrap an opaque inner blob\n"
        "  -h, --help                       show this help\n",
        prog);
}

int main(int argc, char *argv[]) {
    uint16_t cipher = ML_CIPHER_CHACHA20_P;
    uint32_t cpu_filter = 0;
    int raw = 0;
    int new_profile = 0;
    const char *profile_path = NULL;

    const char *input = NULL, *output = NULL;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(argv[0]);
            return 0;
        }
        if (!strncmp(a, "--cipher=", 9)) {
            const char *v = a + 9;
            if      (!strcmp(v, "aes-gcm"))  cipher = ML_CIPHER_AES256_GCM;
            else if (!strcmp(v, "chacha20")) cipher = ML_CIPHER_CHACHA20_P;
            else if (!strcmp(v, "none"))     cipher = ML_CIPHER_NONE;
            else { fprintf(stderr, "unknown cipher: %s\n", v); return 1; }
        } else if (!strncmp(a, "--arch=", 7)) {
            const char *v = a + 7;
            if      (!strcmp(v, "all"))    cpu_filter = 0;
            else if (!strcmp(v, "arm64"))  cpu_filter = ML_ARCH_ARM64;
            else if (!strcmp(v, "x86_64")) cpu_filter = ML_ARCH_X86_64;
            else { fprintf(stderr, "unknown architecture: %s\n", v); return 1; }
        } else if (!strncmp(a, "--new-profile=", 14)) {
            if (profile_path) { fprintf(stderr, "only one profile option is allowed\n"); return 1; }
            profile_path = a + 14;
            new_profile = 1;
        } else if (!strncmp(a, "--profile=", 10)) {
            if (profile_path) { fprintf(stderr, "only one profile option is allowed\n"); return 1; }
            profile_path = a + 10;
        } else if (!strcmp(a, "--raw")) {
            raw = 1;
        } else if (a[0] != '-') {
            if (!input) input = a;
            else if (!output) output = a;
            else { usage(argv[0]); return 1; }
        } else {
            fprintf(stderr, "unknown option: %s\n", a);
            return 1;
        }
    }
    if (!input || !output || (profile_path && !*profile_path)) {
        usage(argv[0]);
        return 1;
    }
    if (raw && cpu_filter) {
        fprintf(stderr, "--arch is not meaningful with --raw\n");
        return 1;
    }

    ml_build_profile_t profile;
    ml_secure_zero(&profile, sizeof(profile));
    if (profile_path) {
        int rc = new_profile ? write_profile(profile_path, &profile)
                             : read_profile(profile_path, &profile);
        if (rc != 0) {
            fprintf(stderr, "%s profile %s: %s\n",
                    new_profile ? "cannot create" : "cannot read",
                    profile_path, strerror(errno));
            return 1;
        }
    }

    int rc = ml_pack_dylib(input, output, cipher, raw, cpu_filter,
                           profile_path ? profile.marker : ML_MAGIC,
                           profile_path ? profile.mask : NULL);
    ml_secure_zero(&profile, sizeof(profile));
    if (rc != 0) {
        fprintf(stderr, "pack failed\n");
        return 1;
    }
    return 0;
}
