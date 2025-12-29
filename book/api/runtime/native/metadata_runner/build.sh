#!/bin/sh
# Build the metadata runner binary in-place.
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
TOOL_MARKERS="$ROOT/../ToolMarkers.swift"
SEATBELT_SHIM="$ROOT/../seatbelt_callout_shim.c"
MODULE_CACHE="$ROOT/.swift-module-cache"
TMP_DIR="$ROOT/.build"

mkdir -p "$MODULE_CACHE" "$TMP_DIR"

SHIM_OBJ="$(mktemp "$TMP_DIR/seatbelt_callout_shim.XXXXXX")"
trap 'rm -f "$SHIM_OBJ"' EXIT

xcrun clang -c "$SEATBELT_SHIM" -o "$SHIM_OBJ"
xcrun swiftc -module-cache-path "$MODULE_CACHE" "$ROOT/metadata_runner.swift" "$TOOL_MARKERS" "$SHIM_OBJ" -o "$ROOT/metadata_runner"
