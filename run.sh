#!/usr/bin/env bash
# Verify and run a local artifact selected explicitly by the user.
set -euo pipefail

BIN="${1:-}"
if [[ -z "$BIN" ]]; then
    echo "usage: $0 <local-packed-binary>" >&2
    exit 2
fi
if [[ "$BIN" == http://* || "$BIN" == https://* ]]; then
    echo "error: download and review the artifact before running it" >&2
    exit 2
fi
if [[ "$BIN" != */* ]]; then
    BIN="./$BIN"
fi
if [[ ! -f "$BIN" || ! -x "$BIN" ]]; then
    echo "error: not an executable file: $BIN" >&2
    exit 2
fi

if codesign -d "$BIN" >/dev/null 2>&1; then
    codesign --verify --strict --all-architectures --verbose=2 "$BIN"
else
    echo "This binary is unsigned." >&2
fi

if xattr -p com.apple.quarantine "$BIN" >/dev/null 2>&1; then
    echo "This file is quarantined. Review it and use macOS Privacy & Security" >&2
    echo "→ Open Anyway if you trust it and your organization permits it." >&2
    exit 3
fi

exec "$BIN"
