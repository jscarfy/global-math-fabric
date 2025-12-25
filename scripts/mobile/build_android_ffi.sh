#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# Requires: rustup + Android NDK + cargo-ndk
if ! command -v cargo-ndk >/dev/null 2>&1; then
  cargo install cargo-ndk
fi

# Edit these to your flutter app path if different
FLUTTER_ANDROID_DIR="${FLUTTER_ANDROID_DIR:-$ROOT/android/app/src/main/jniLibs}"
mkdir -p "$FLUTTER_ANDROID_DIR"

# targets
TARGETS=("arm64-v8a:aarch64-linux-android" "armeabi-v7a:armv7-linux-androideabi" "x86_64:x86_64-linux-android")

for t in "${TARGETS[@]}"; do
  ABI="${t%%:*}"
  RUST_TARGET="${t##*:}"
  echo "== build $ABI ($RUST_TARGET)"
  cargo ndk -t "$ABI" -o "$FLUTTER_ANDROID_DIR" build -p gmf_mobile_ffi --release
done

# copy header (for reference)
mkdir -p "$ROOT/android/app/src/main/cpp/include"
cp -f "$ROOT/native/include/gmf_mobile_ffi.h" "$ROOT/android/app/src/main/cpp/include/gmf_mobile_ffi.h" || true

echo "OK: Android .so placed in $FLUTTER_ANDROID_DIR/<abi>/libgmf_mobile_ffi.so"
