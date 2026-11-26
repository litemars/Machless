#include "crypto/crypto.h"

#include <stdint.h>

__attribute__((noinline))
void ml_secure_zero(void *memory, size_t size) {
    volatile uint8_t *byte = (volatile uint8_t *)memory;
    while (size--) *byte++ = 0;
}
