/*
 * Enumerate slices in thin or fat Mach-O files.
 */
#include "machless.h"
#include "machoutil/machoutil.h"

#include <mach-o/loader.h>
#include <mach-o/fat.h>

static uint32_t ml_swap32(uint32_t value) {
    return __builtin_bswap32(value);
}

static uint32_t ml_fat32(uint32_t value, int swapped) {
    return swapped ? ml_swap32(value) : value;
}

int ml_enumerate_slices(const uint8_t *data, size_t size,
                        ml_slice_view_t *out, size_t *count_io) {
    if (!data || size < 4 || !out || !count_io) return -1;
    size_t cap = *count_io;
    *count_io = 0;

    uint32_t magic;
    __builtin_memcpy(&magic, data, 4);

    if (magic == MH_MAGIC_64) {
        if (cap < 1 || size < sizeof(struct mach_header_64)) return -1;
        const struct mach_header_64 *mh = (const struct mach_header_64 *)data;
        out[0].cpu_type = (uint32_t)mh->cputype;
        out[0].data     = data;
        out[0].size     = size;
        *count_io = 1;
        return 0;
    }
    if (magic != FAT_MAGIC && magic != FAT_CIGAM) return -1;
    if (size < sizeof(struct fat_header)) return -1;

    const int swapped = magic == FAT_CIGAM;
    const struct fat_header *fh = (const struct fat_header *)data;
    uint32_t nfat = ml_fat32(fh->nfat_arch, swapped);
    if (nfat == 0 || nfat > ML_MAX_SLICES || cap < nfat) return -1;
    if ((size_t)nfat > (size - sizeof(*fh)) / sizeof(struct fat_arch)) return -1;

    const struct fat_arch *fa = (const struct fat_arch *)(data + sizeof(*fh));
    size_t produced = 0;
    for (uint32_t i = 0; i < nfat; i++) {
        uint32_t off  = ml_fat32(fa[i].offset, swapped);
        uint32_t sz   = ml_fat32(fa[i].size, swapped);
        uint32_t cput = ml_fat32(fa[i].cputype, swapped);
        if (sz < sizeof(struct mach_header_64) ||
            (size_t)off > size || (size_t)sz > size - (size_t)off) {
            return -1;
        }
        out[produced].cpu_type = cput;
        out[produced].data     = data + off;
        out[produced].size     = sz;
        produced++;
    }
    *count_io = produced;
    return produced == nfat ? 0 : -1;
}
