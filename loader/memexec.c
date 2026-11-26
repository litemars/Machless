/*
 * ml_execute_from_memory — thin wrapper around ReflectiveLoader's
 * custom_dlopen_from_memory(). A successful load invokes the payload's
 * initializers in the current process.
 */
#include "machless.h"
#include "custom_dlfcn.h"

#include <stddef.h>
#include <limits.h>

int ml_execute_from_memory(const uint8_t *macho, size_t size) {
    if (!macho || size == 0 || size > INT_MAX) return -1;
    void *handle = custom_dlopen_from_memory((void *)macho, (int)size);
    return handle ? 0 : -1;
}
