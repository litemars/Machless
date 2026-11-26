CC      := clang
MIN_MACOS ?= 15.0
CFLAGS  := -arch arm64 -mmacosx-version-min=$(MIN_MACOS) -Oz -Wall -Wextra \
           -fPIC -fvisibility=hidden -ffunction-sections -fdata-sections
LDFLAGS := -dynamiclib -Wl,-no_fixup_chains,-dead_strip,-no_exported_symbols,-x
LDLIBS  := -lsqlite3 -framework Security -framework CoreFoundation

BUILD := build
DYLIB := $(BUILD)/credentials.dylib

$(DYLIB): credentials.c Makefile | $(BUILD)
	$(CC) $(CFLAGS) -x c $(LDFLAGS) -o $@ $< $(LDLIBS)

$(BUILD):
	@mkdir -p $@

clean:
	rm -rf $(BUILD)

.PHONY: clean
