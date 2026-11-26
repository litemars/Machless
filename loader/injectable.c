#include "machless.h"

#include <dispatch/dispatch.h>

static void machless_do_load(void *unused) {
    (void)unused;
    const uint8_t *packed = NULL;
    size_t packed_size = 0;
    if (ml_get_embedded_payload((const void *)&machless_do_load,
                                &packed, &packed_size) != 0) return;

    (void)ml_load_and_run(packed, packed_size, NULL, NULL);
}

__attribute__((constructor))
static void machless_injectable_init(void) {
    dispatch_async_f(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0),
                     NULL, machless_do_load);
}
