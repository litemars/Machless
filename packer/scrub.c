/* Remove stable third-party loader tokens after symbol stripping. An optional
 * codesign pass runs after this edit. */
#include "crypto/crypto.h"

#include <errno.h>
#include <mach-o/loader.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int replace_token(uint8_t *file, size_t file_size, const char *token) {
    size_t size = strlen(token);
    uint8_t replacement[32];
    if (size > sizeof(replacement) || ml_random_bytes(replacement, size) != 0)
        return -1;
    for (size_t i = 0; i < size; i++)
        replacement[i] = (uint8_t)('a' + replacement[i] % 26);

    int matches = 0;
    for (size_t offset = 0; offset + size <= file_size; offset++) {
        if (memcmp(file + offset, token, size) == 0) {
            memcpy(file + offset, replacement, size);
            matches++;
            offset += size - 1;
        }
    }
    ml_secure_zero(replacement, sizeof(replacement));
    return matches;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <linked-macho>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "r+b");
    if (!f) {
        fprintf(stderr, "cannot open %s: %s\n", argv[1], strerror(errno));
        return 1;
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 1; }
    long length = ftell(f);
    if (length <= 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 1;
    }
    uint8_t *file = malloc((size_t)length);
    if (!file) { fclose(f); return 1; }
    if (fread(file, 1, (size_t)length, f) != (size_t)length) {
        free(file); fclose(f); return 1;
    }
    if ((size_t)length < sizeof(struct mach_header_64) ||
        ((const struct mach_header_64 *)file)->magic != MH_MAGIC_64) {
        fprintf(stderr, "%s is not a thin 64-bit Mach-O\n", argv[1]);
        free(file); fclose(f); return 1;
    }

    const char *tokens[] = {
        "isolator", "ImageLoader", "custom_dlopen", "instantiateFromMemory"
    };
    for (size_t i = 0; i < sizeof(tokens) / sizeof(tokens[0]); i++) {
        if (replace_token(file, (size_t)length, tokens[i]) < 0) {
            ml_secure_zero(file, (size_t)length);
            free(file); fclose(f); return 1;
        }
    }
    int write_failed = fseek(f, 0, SEEK_SET) != 0 ||
                       fwrite(file, 1, (size_t)length, f) != (size_t)length ||
                       fflush(f) != 0;
    if (fclose(f) != 0) write_failed = 1;
    if (write_failed) {
        ml_secure_zero(file, (size_t)length);
        free(file); return 1;
    }
    ml_secure_zero(file, (size_t)length);
    free(file);
    return 0;
}
