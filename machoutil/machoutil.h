/*
 * Mach-O helpers shared by the packer and loader.
 */
#ifndef MACHLESS_MACHOUTIL_H
#define MACHLESS_MACHOUTIL_H

#include <stdint.h>
#include <stddef.h>

/* View into a slice within a (possibly fat) Mach-O. data points into the
 * caller's buffer — no allocation. */
typedef struct {
    uint32_t       cpu_type;   /* CPU_TYPE_ARM64 etc. */
    const uint8_t *data;
    size_t         size;
} ml_slice_view_t;

/*
 * On entry *count_io is the capacity of `out`.
 * On success *count_io is the number of slices written.
 * Returns 0 on success, -1 on failure.
 */
int ml_enumerate_slices(const uint8_t *data, size_t size,
                        ml_slice_view_t *out, size_t *count_io);

#endif
