/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/*
 * custom_dlfcn.h — ReflectiveLoader public interface, adapted from
 * https://github.com/pwardle/ReflectiveLoader/blob/60f7bf9522b10a8787db4201c03be5c6b0908833/loader/include/custom_dlfcn.h
 *
 * Provides an in-process dyld replacement that loads Mach-O dylibs from
 * memory buffers rather than from disk. custom_dlopen_from_memory() calls
 * ImageLoaderMachO::instantiateFromMemory() -> link() -> runInitializers(),
 * which fires every __attribute__((constructor)) in the payload before
 * returning.
 *
 * Constraint: payloads MUST NOT use LC_DYLD_CHAINED_FIXUPS. Compile the
 * payload dylib with -Wl,-no_fixup_chains.
 */
#ifndef CUSTOM_DLFCN_H
#define CUSTOM_DLFCN_H

#include <dlfcn.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int   custom_dlclose(void *handle);
extern char *custom_dlerror(void);
extern void *custom_dlopen(const char *path, int mode);
extern void *custom_dlsym(void *handle, const char *symbol);

/*
 * Load a Mach-O dylib from an in-memory buffer.
 *   mh:  pointer to first byte of MH_MAGIC_64 image
 *   len: image length in bytes
 * Returns an opaque handle (non-NULL) on success, NULL on failure;
 * call custom_dlerror() for the reason on failure.
 *
 * Fires payload constructors before returning.
 */
extern void *custom_dlopen_from_memory(void *mh, int len);

#ifdef __cplusplus
}
#endif

#endif /* CUSTOM_DLFCN_H */
