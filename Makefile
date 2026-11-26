#
# machless — macOS in-memory Mach-O packer built on ReflectiveLoader.
#
# Quickstart:
#   make all                                 # build packer and loader templates
#   make pack INPUT=foo.dylib OUTPUT=foo     # produce a packed binary
#   make examples                            # build all examples/
#

# ── Toolchain ──────────────────────────────────────────────────────
UNAME_S := $(shell uname -s)
ifneq ($(UNAME_S), Darwin)
$(error machless targets macOS only — current OS: $(UNAME_S))
endif

CC      := clang
ARCH    := -arch arm64
MIN_MACOS ?= 15.0
STD     := -std=c11
WARN    := -Wall -Wextra -Wshadow -Wpointer-arith -Wstrict-prototypes
OPT     := -Oz
SEC     := -fstack-protector-strong

# Release is the default and omits development logging.
MODE ?= release
ifeq ($(MODE), release)
    DEFINES :=
else ifeq ($(MODE), dev)
    DEFINES := -DML_DEBUG
else
    $(error MODE must be dev or release (got $(MODE)))
endif

# ── Layout ─────────────────────────────────────────────────────────
BUILD_DIR    := build
INCLUDE_DIR  := include
REFLECTIVE_LOADER_DIR := third_party/reflective_loader
CRYPTO_DIR   := crypto
MACHO_DIR    := machoutil
PACKER_DIR   := packer
LOADER_DIR   := loader
STAGE1_DIR   := stage1
EXAMPLES_DIR := examples

INCLUDES := -I$(INCLUDE_DIR) -I$(REFLECTIVE_LOADER_DIR) -I.

CFLAGS := $(ARCH) -mmacosx-version-min=$(MIN_MACOS) $(STD) $(WARN) $(OPT) \
          $(SEC) -fvisibility=hidden -ffunction-sections -fdata-sections \
          $(DEFINES) $(INCLUDES)

# Single-layer outputs link only the selected decryptor. ChaCha20 is local and
# avoids carrying the distinctive CommonCrypto GCM SPI import set.
CIPHER ?= chacha20
PACKER_ARGS ?=
KEEP_INTERMEDIATES ?= 0
# Ad-hoc sign outputs by default so the final executable remains valid after
# strip and scrub. Override with a certificate name, or set to empty to opt out.
SIGN_IDENTITY ?= -
ifeq ($(strip $(SIGN_IDENTITY)),)
    SIGN_LDFLAGS := -Wl,-no_adhoc_codesign
else ifeq ($(SIGN_IDENTITY),-)
    CODESIGN_ARGS := --force --sign - --timestamp=none
else
    CODESIGN_ARGS := --force --sign "$(SIGN_IDENTITY)" --timestamp
endif

# ── Outputs ────────────────────────────────────────────────────────
PACKER_BIN     := $(BUILD_DIR)/machless-pack
SCRUB_BIN      := $(BUILD_DIR)/machless-scrub
LOADER_BIN     := $(BUILD_DIR)/machless-loader
LOADER_DYLIB   := $(BUILD_DIR)/libmachless-loader.dylib   # injectable variant
STAGE1_BIN     := $(BUILD_DIR)/machless-stage1

# ── Shared object files ────────────────────────────────────────────
AES_SRC     := $(CRYPTO_DIR)/aes_gcm.c
CHACHA_SRC  := $(CRYPTO_DIR)/chacha20_poly1305.c
RANDOM_SRC  := $(CRYPTO_DIR)/random.c
ZERO_SRC    := $(CRYPTO_DIR)/zero.c
CRYPTO_SRC  := $(AES_SRC) $(CHACHA_SRC) $(RANDOM_SRC) $(ZERO_SRC)
MACHO_SRC  := $(MACHO_DIR)/macho.c $(MACHO_DIR)/fat.c
PAYLOAD_SRC := $(LOADER_DIR)/payload.c
HEADERS    := $(wildcard $(INCLUDE_DIR)/*.h $(CRYPTO_DIR)/*.h \
                     $(MACHO_DIR)/*.h $(REFLECTIVE_LOADER_DIR)/*.h)
REFLECTIVE_LOADER_ARCHIVE := $(REFLECTIVE_LOADER_DIR)/libloader.a

PACKER_SRC := $(PACKER_DIR)/packer.c $(PACKER_DIR)/main.c \
              $(CRYPTO_SRC) $(MACHO_SRC)

LOADER_CORE_SRC := $(LOADER_DIR)/loader.c $(LOADER_DIR)/memexec.c \
                   $(LOADER_DIR)/main.c $(PAYLOAD_SRC) $(MACHO_SRC)

LOADER_SRC := $(LOADER_CORE_SRC) $(AES_SRC) $(CHACHA_SRC) $(ZERO_SRC)

LOADER_DYLIB_SRC := $(LOADER_DIR)/loader.c $(LOADER_DIR)/memexec.c \
                    $(LOADER_DIR)/injectable.c $(PAYLOAD_SRC) \
                    $(CRYPTO_SRC) $(MACHO_SRC)

STAGE1_SRC  := $(STAGE1_DIR)/stage1.c \
               $(LOADER_DIR)/loader.c $(LOADER_DIR)/memexec.c $(PAYLOAD_SRC) \
               $(AES_SRC) $(CHACHA_SRC) $(ZERO_SRC) $(MACHO_SRC)

ifeq ($(CIPHER),chacha20)
    FINAL_CIPHER_ID  := ML_CIPHER_CHACHA20_P
    FINAL_CRYPTO_SRC := $(CHACHA_SRC)
else ifeq ($(CIPHER),aes-gcm)
    FINAL_CIPHER_ID  := ML_CIPHER_AES256_GCM
    FINAL_CRYPTO_SRC := $(AES_SRC)
else ifeq ($(CIPHER),none)
    FINAL_CIPHER_ID  := ML_CIPHER_NONE
    FINAL_CRYPTO_SRC :=
else
    $(error CIPHER must be chacha20, aes-gcm, or none (got $(CIPHER)))
endif
FINAL_LOADER_SRC := $(LOADER_CORE_SRC) $(FINAL_CRYPTO_SRC) $(ZERO_SRC)

# ── Frameworks / libs ──────────────────────────────────────────────
# CommonCrypto is in libSystem — no -framework needed.
# libloader.a provides custom_dlopen_from_memory (APSL 2.0)
LIB_REFL  := -L$(REFLECTIVE_LOADER_DIR) -lloader
FRAMEWORKS := -framework Foundation -framework CoreFoundation -framework IOKit
COMMON_LD := $(LIB_REFL) $(FRAMEWORKS) -lc++
HARDEN_LD := -Wl,-dead_strip,-dead_strip_dylibs,-no_exported_symbols,-x \
             $(SIGN_LDFLAGS)
BUILD_CONFIG_ID := $(shell printf '%s\n' '$(CC)' '$(CFLAGS)' '$(COMMON_LD)' \
                   '$(SIGN_IDENTITY)' | \
                   shasum -a 256 | cut -c1-16)
BUILD_CONFIG := $(BUILD_DIR)/.build-config-$(BUILD_CONFIG_ID)

# ── Top-level targets ──────────────────────────────────────────────
.PHONY: all pack pack-dylib matryoshka examples clean help

all: $(BUILD_DIR) $(PACKER_BIN) $(SCRUB_BIN) $(LOADER_BIN) $(LOADER_DYLIB) $(STAGE1_BIN)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# The filename itself captures command-line build options. This avoids
# relinking every phony pack invocation when nothing relevant changed.
$(BUILD_CONFIG): | $(BUILD_DIR)
	@touch "$@"

# Packer (host tool — no reflective loader needed)
$(PACKER_BIN): $(PACKER_SRC) $(HEADERS) $(BUILD_CONFIG) Makefile | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o "$@" $(PACKER_SRC)

$(SCRUB_BIN): $(PACKER_DIR)/scrub.c $(RANDOM_SRC) $(ZERO_SRC) $(HEADERS) $(BUILD_CONFIG) Makefile | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o "$@" $(PACKER_DIR)/scrub.c $(RANDOM_SRC) $(ZERO_SRC)

# Standalone loader template
$(LOADER_BIN): $(LOADER_SRC) $(HEADERS) $(REFLECTIVE_LOADER_ARCHIVE) $(BUILD_CONFIG) Makefile | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(HARDEN_LD) -o "$@" $(LOADER_SRC) $(COMMON_LD)
ifneq ($(strip $(SIGN_IDENTITY)),)
	@codesign $(CODESIGN_ARGS) "$@"
	@codesign --verify --strict --all-architectures --verbose=2 "$@"
endif

# Loader (injectable dylib variant)
$(LOADER_DYLIB): $(LOADER_DYLIB_SRC) $(HEADERS) $(REFLECTIVE_LOADER_ARCHIVE) $(BUILD_CONFIG) Makefile | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(HARDEN_LD) -dynamiclib -Wl,-no_fixup_chains \
	    -o "$@" $(LOADER_DYLIB_SRC) $(COMMON_LD)
ifneq ($(strip $(SIGN_IDENTITY)),)
	@codesign $(CODESIGN_ARGS) "$@"
	@codesign --verify --strict --all-architectures --verbose=2 "$@"
endif

# Stage 1 matryoshka stub — links full loader + crypto so ml_load_and_run is available
$(STAGE1_BIN): $(STAGE1_SRC) $(HEADERS) $(REFLECTIVE_LOADER_ARCHIVE) $(BUILD_CONFIG) Makefile | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(HARDEN_LD) -o "$@" $(STAGE1_SRC) $(COMMON_LD)
ifneq ($(strip $(SIGN_IDENTITY)),)
	@codesign $(CODESIGN_ARGS) "$@"
	@codesign --verify --strict --all-architectures --verbose=2 "$@"
endif

# ── pack / pack-dylib ──────────────────────────────────────────────
pack: $(PACKER_BIN) $(SCRUB_BIN)
	@if [ -z "$(INPUT)" ] || [ -z "$(OUTPUT)" ]; then \
	    echo "Usage: make pack INPUT=<dylib> OUTPUT=<output>"; exit 1; fi
	@lipo "$(INPUT)" -verify_arch arm64 >/dev/null 2>&1 || { \
	    echo "Input must contain an arm64 Mach-O slice"; exit 1; }
	@set -eu; \
	profile=$$(/usr/bin/mktemp -t mlprofile); \
	trap '/bin/rm -f "$$profile"' EXIT; \
	"$(PACKER_BIN)" $(PACKER_ARGS) --new-profile="$$profile" --cipher=$(CIPHER) \
	    --arch=arm64 "$(INPUT)" "$(OUTPUT).packed"; \
	$(CC) $(CFLAGS) $(HARDEN_LD) -DML_CIPHER_ONLY=$(FINAL_CIPHER_ID) \
	    -include "$$profile" -o "$(OUTPUT)" $(FINAL_LOADER_SRC) \
	    -Xlinker -sectcreate -Xlinker __DATA_CONST -Xlinker __auth_const \
	    -Xlinker "$(OUTPUT).packed" \
	    $(COMMON_LD); \
	/usr/bin/strip -x "$(OUTPUT)"; \
	"$(SCRUB_BIN)" "$(OUTPUT)"; \
	/bin/chmod 700 "$(OUTPUT)"; \
	if [ -n "$(strip $(SIGN_IDENTITY))" ]; then \
	    /usr/bin/codesign $(CODESIGN_ARGS) "$(OUTPUT)"; \
	    /usr/bin/codesign --verify --strict --all-architectures --verbose=2 "$(OUTPUT)"; \
	fi; \
	if [ "$(KEEP_INTERMEDIATES)" = 1 ]; then \
	    /bin/cp "$$profile" "$(OUTPUT).profile.h"; \
	    /bin/chmod 600 "$(OUTPUT).profile.h"; \
	else \
	    /bin/rm -f "$(OUTPUT).packed"; \
	fi; \
	echo "Packed binary ready: $(OUTPUT)"

pack-dylib: $(PACKER_BIN) $(SCRUB_BIN)
	@if [ -z "$(INPUT)" ] || [ -z "$(OUTPUT)" ]; then \
	    echo "Usage: make pack-dylib INPUT=<dylib> OUTPUT=<output>"; exit 1; fi
	@lipo "$(INPUT)" -verify_arch arm64 >/dev/null 2>&1 || { \
	    echo "Input must contain an arm64 Mach-O slice"; exit 1; }
	@set -eu; \
	profile=$$(/usr/bin/mktemp -t mlprofile); \
	trap '/bin/rm -f "$$profile"' EXIT; \
	"$(PACKER_BIN)" $(PACKER_ARGS) --new-profile="$$profile" --cipher=$(CIPHER) \
	    --arch=arm64 "$(INPUT)" "$(OUTPUT).packed"; \
	$(CC) $(CFLAGS) $(HARDEN_LD) -DML_CIPHER_ONLY=$(FINAL_CIPHER_ID) \
	    -include "$$profile" -dynamiclib -Wl,-no_fixup_chains \
	    -o "$(OUTPUT)" $(FINAL_LOADER_SRC:$(LOADER_DIR)/main.c=$(LOADER_DIR)/injectable.c) \
	    -Xlinker -sectcreate -Xlinker __DATA_CONST -Xlinker __auth_const \
	    -Xlinker "$(OUTPUT).packed" \
	    $(COMMON_LD); \
	/usr/bin/strip -x "$(OUTPUT)"; \
	"$(SCRUB_BIN)" "$(OUTPUT)"; \
	if [ -n "$(strip $(SIGN_IDENTITY))" ]; then \
	    /usr/bin/codesign $(CODESIGN_ARGS) "$(OUTPUT)"; \
	    /usr/bin/codesign --verify --strict --all-architectures --verbose=2 "$(OUTPUT)"; \
	fi; \
	if [ "$(KEEP_INTERMEDIATES)" = 1 ]; then \
	    /bin/cp "$$profile" "$(OUTPUT).profile.h"; \
	    /bin/chmod 600 "$(OUTPUT).profile.h"; \
	else \
	    /bin/rm -f "$(OUTPUT).packed"; \
	fi; \
	echo "Packed injectable dylib ready: $(OUTPUT)"

# ── Matryoshka (two-layer nested packing) ─────────────────────
#
# Outer packed blob: ChaCha20-Poly1305, embedded in the stage1 executable
# Inner packed blob: AES-256-GCM, handed to the full loader
#
# Usage:  make matryoshka INPUT=payload.dylib OUTPUT=out_binary
matryoshka: $(PACKER_BIN) $(SCRUB_BIN)
	@if [ -z "$(INPUT)" ] || [ -z "$(OUTPUT)" ]; then \
	    echo "Usage: make matryoshka INPUT=<dylib> OUTPUT=<output>"; exit 1; fi
	@lipo "$(INPUT)" -verify_arch arm64 >/dev/null 2>&1 || { \
	    echo "Input must contain an arm64 Mach-O slice"; exit 1; }
	@set -eu; \
	profile=$$(/usr/bin/mktemp -t mlprofile); \
	trap '/bin/rm -f "$$profile"' EXIT; \
	"$(PACKER_BIN)" --new-profile="$$profile" --cipher=aes-gcm --arch=arm64 \
	    "$(INPUT)" "$(OUTPUT).inner.packed"; \
	"$(PACKER_BIN)" --profile="$$profile" --cipher=chacha20 --raw \
	    "$(OUTPUT).inner.packed" "$(OUTPUT).outer.packed"; \
	$(CC) $(CFLAGS) $(HARDEN_LD) -include "$$profile" -o "$(OUTPUT)" \
	    $(STAGE1_SRC) \
	    -Xlinker -sectcreate -Xlinker __DATA_CONST -Xlinker __auth_const \
	    -Xlinker "$(OUTPUT).outer.packed" \
	    $(COMMON_LD); \
	/usr/bin/strip -x "$(OUTPUT)"; \
	"$(SCRUB_BIN)" "$(OUTPUT)"; \
	/bin/chmod 700 "$(OUTPUT)"; \
	if [ -n "$(strip $(SIGN_IDENTITY))" ]; then \
	    /usr/bin/codesign $(CODESIGN_ARGS) "$(OUTPUT)"; \
	    /usr/bin/codesign --verify --strict --all-architectures --verbose=2 "$(OUTPUT)"; \
	fi; \
	if [ "$(KEEP_INTERMEDIATES)" = 1 ]; then \
	    /bin/cp "$$profile" "$(OUTPUT).profile.h"; \
	    /bin/chmod 600 "$(OUTPUT).profile.h"; \
	else \
	    /bin/rm -f "$(OUTPUT).inner.packed" "$(OUTPUT).outer.packed"; \
	fi; \
	echo "Matryoshka ready: $(OUTPUT)"

# ── Examples ───────────────────────────────────────────────────────
examples: all
	@for ex in $(EXAMPLES_DIR)/*/; do \
	    if [ -f "$$ex/Makefile" ]; then \
	        echo "--- building $$ex ---"; \
	        $(MAKE) -C "$$ex" || exit 1; \
	    fi; \
	done

# ── Housekeeping ───────────────────────────────────────────────────
clean:
	rm -rf $(BUILD_DIR) *.packed
	@for ex in $(EXAMPLES_DIR)/*/; do \
	    if [ -f "$$ex/Makefile" ]; then $(MAKE) -C "$$ex" clean; fi; \
	done

help:
	@echo "machless build targets:"
	@echo "  make                        build packer and loader templates"
	@echo "  make pack                   pack a dylib into a standalone executable"
	@echo "                              (INPUT=... OUTPUT=... [CIPHER=chacha20])"
	@echo "                              outputs are ad-hoc signed by default"
	@echo "                              (SIGN_IDENTITY=<name>, or empty to disable)"
	@echo "  make pack-dylib             pack a dylib into an injectable dylib"
	@echo "  make matryoshka             two-layer nested pack (outer: ChaCha20,"
	@echo "                              inner: AES-256-GCM; requires INPUT=... OUTPUT=...)"
	@echo "  make examples               build all examples/*/"
	@echo "  make clean                  remove build artefacts"
	@echo "  make MODE=dev ...           build with development logging (release is default)"
