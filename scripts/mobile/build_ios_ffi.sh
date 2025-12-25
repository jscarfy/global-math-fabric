#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# Flutter iOS Runner FFI dir (edit if your project differs)
IOS_FFI_DIR="${IOS_FFI_DIR:-$ROOT/ios/Runner/ffi}"
mkdir -p "$IOS_FFI_DIR"

# Ensure targets
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

# Build
cargo build -p gmf_mobile_ffi --release --target aarch64-apple-ios
cargo build -p gmf_mobile_ffi --release --target aarch64-apple-ios-sim
cargo build -p gmf_mobile_ffi --release --target x86_64-apple-ios

# Copy static libs (you can also do xcframework below)
cp native/gmf_mobile_ffi/target/aarch64-apple-ios/release/libgmf_mobile_ffi.a "$IOS_FFI_DIR/libgmf_mobile_ffi_device.a"
cp native/gmf_mobile_ffi/target/aarch64-apple-ios-sim/release/libgmf_mobile_ffi.a "$IOS_FFI_DIR/libgmf_mobile_ffi_sim_arm64.a"
cp native/gmf_mobile_ffi/target/x86_64-apple-ios/release/libgmf_mobile_ffi.a "$IOS_FFI_DIR/libgmf_mobile_ffi_sim_x86_64.a"
cp native/include/gmf_mobile_ffi.h "$IOS_FFI_DIR/gmf_mobile_ffi.h"

echo "Built iOS libs+header into $IOS_FFI_DIR"

# Optional (recommended): create XCFramework for easier Xcode linking
XC_DIR="$IOS_FFI_DIR/gmf_mobile_ffi.xcframework"
rm -rf "$XC_DIR"
xcodebuild -create-xcframework \
  -library "$IOS_FFI_DIR/libgmf_mobile_ffi_device.a" -headers "$IOS_FFI_DIR" \
  -library "$IOS_FFI_DIR/libgmf_mobile_ffi_sim_arm64.a" -headers "$IOS_FFI_DIR" \
  -library "$IOS_FFI_DIR/libgmf_mobile_ffi_sim_x86_64.a" -headers "$IOS_FFI_DIR" \
  -output "$XC_DIR"

echo "XCFramework: $XC_DIR"
