/* Find the packed container without stable segment or section names. */
#include "machless.h"

#include <dlfcn.h>
#include <mach-o/loader.h>
#include <mach/vm_prot.h>
#include <stdint.h>

static int image_layout(const struct mach_header_64 *header,
                        const struct segment_command_64 **base_out,
                        const uint8_t **end_out) {
    if (header->magic != MH_MAGIC_64) return -1;

    const uint8_t *p = (const uint8_t *)header + sizeof(*header);
    const uint8_t *end = p + header->sizeofcmds;
    const struct segment_command_64 *base = NULL;
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if ((size_t)(end - p) < sizeof(struct load_command)) return -1;
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize < sizeof(*lc) || lc->cmdsize > (size_t)(end - p))
            return -1;
        if (lc->cmd == LC_SEGMENT_64) {
            if (lc->cmdsize < sizeof(struct segment_command_64)) return -1;
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)p;
            if ((size_t)seg->nsects >
                (lc->cmdsize - sizeof(*seg)) / sizeof(struct section_64))
                return -1;
            if (!base && seg->fileoff == 0 && seg->filesize != 0) base = seg;
        }
        p += lc->cmdsize;
    }
    if (!base || p != end) return -1;
    *base_out = base;
    *end_out = end;
    return 0;
}

int ml_get_embedded_payload(const void *image_address,
                            const uint8_t **data, size_t *size) {
    if (!image_address || !data || !size) return -1;
    *data = NULL;
    *size = 0;

    Dl_info info;
    if (dladdr(image_address, &info) == 0 || !info.dli_fbase) return -1;
    const struct mach_header_64 *header =
        (const struct mach_header_64 *)info.dli_fbase;

    const struct segment_command_64 *base = NULL;
    const uint8_t *end = NULL;
    if (image_layout(header, &base, &end) != 0 ||
        base->vmaddr > UINTPTR_MAX) return -1;
    uintptr_t slide = (uintptr_t)header - (uintptr_t)base->vmaddr;

    const uint8_t *p = (const uint8_t *)header + sizeof(*header);
    unsigned matches = 0;
    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)p;
            if ((seg->initprot & VM_PROT_READ) &&
                (!(seg->initprot & VM_PROT_WRITE) ||
                 (seg->flags & SG_READ_ONLY)) &&
                !(seg->initprot & VM_PROT_EXECUTE)) {
                const struct section_64 *sections =
                    (const struct section_64 *)(seg + 1);
                for (uint32_t n = 0; n < seg->nsects; n++) {
                    const struct section_64 *sect = &sections[n];
                    if ((sect->flags & SECTION_TYPE) != S_REGULAR ||
                        sect->size < sizeof(ml_pack_header_t) ||
                        sect->size > SIZE_MAX || sect->addr < seg->vmaddr ||
                        sect->size > seg->vmsize ||
                        sect->addr - seg->vmaddr > seg->vmsize - sect->size ||
                        sect->addr > UINTPTR_MAX - slide) continue;
                    const uint8_t *candidate =
                        (const uint8_t *)((uintptr_t)sect->addr + slide);
                    if (ml_find_header(candidate, (size_t)sect->size)) {
                        *data = candidate;
                        *size = (size_t)sect->size;
                        matches++;
                    }
                }
            }
        }
        p += lc->cmdsize;
    }
    return p == end && matches == 1 ? 0 : -1;
}
