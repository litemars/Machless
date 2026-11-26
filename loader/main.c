/*
 * Standalone exe variant entry point.
 *
 * Locates the signed packed section in its image, decrypts it, hands off to
 * the ReflectiveLoader backend, then exits once its synchronous initializers
 * return.
 */
#include "machless.h"

int main(int argc, char *argv[], char *envp[]) {
    (void)argc;

    const uint8_t *packed = NULL;
    size_t packed_size = 0;
    if (ml_get_embedded_payload((const void *)&main,
                                &packed, &packed_size) != 0) {
        ML_DBG("embedded payload section not found\n");
        return 1;
    }

    if (ml_load_and_run(packed, packed_size, argv, envp) != 0) return 1;

    return 0;
}
