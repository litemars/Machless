/*
 * Basic Mach-O dylib header check for thin or fat input.
 */
#include "machless.h"
#include "machoutil/machoutil.h"

#include <mach-o/loader.h>

int ml_is_macho_dylib(const uint8_t *data, size_t size) {
    ml_slice_view_t slices[ML_MAX_SLICES];
    size_t count = ML_MAX_SLICES;
    if (ml_enumerate_slices(data, size, slices, &count) != 0 || count == 0) {
        return 0;
    }

    /* Each slice needs a native-endian 64-bit dylib header and a supported,
     * distinct CPU type. This does not validate every Mach-O load command. */
    for (size_t i = 0; i < count; i++) {
        if (slices[i].size < sizeof(struct mach_header_64)) return 0;
        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)slices[i].data;
        if (mh->magic != MH_MAGIC_64 || mh->filetype != MH_DYLIB ||
            (uint32_t)mh->cputype != slices[i].cpu_type) return 0;
        if (slices[i].cpu_type != ML_ARCH_ARM64 &&
            slices[i].cpu_type != ML_ARCH_X86_64) return 0;
        for (size_t j = 0; j < i; j++) {
            if (slices[j].cpu_type == slices[i].cpu_type) return 0;
        }
    }
    return 1;
}
