#!/usr/bin/env bash
# Cross-compiles rust-core for the Android ABIs the app ships and copies each
# library into app/src/main/jniLibs. Run from the repo root (Git Bash on Windows).
#
# Why the linker is set here and not in .cargo/config.toml: the NDK location is
# per machine, and a checked-in absolute path would break every other clone.
# Why the library is renamed to libuniffi_rust_core.so: UniFFI's generated Kotlin
# loads "uniffi_<crate>" through JNA by default.
#
# Requires: rustup targets aarch64-linux-android and x86_64-linux-android, and
# the NDK (ANDROID_NDK_HOME, or the default SDK location below).
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
ndk_version="27.2.12479018"
min_api=29

local_app_data="$(cygpath -u "${LOCALAPPDATA:-$HOME/AppData/Local}" 2>/dev/null || echo "$HOME")"
sdk="${ANDROID_HOME:-$local_app_data/Android/Sdk}"
ndk="${ANDROID_NDK_HOME:-$sdk/ndk/$ndk_version}"

case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*) host_tag="windows-x86_64" ;;
  Darwin) host_tag="darwin-x86_64" ;;
  *) host_tag="linux-x86_64" ;;
esac
toolchain_bin="$ndk/toolchains/llvm/prebuilt/$host_tag/bin"
if [ ! -d "$toolchain_bin" ]; then
  echo "NDK toolchain not found at $toolchain_bin (set ANDROID_NDK_HOME)" >&2
  exit 1
fi

# ABI -> Rust target triple. Emulators on x86_64 hosts need x86_64.
build_one() {
  local abi="$1" triple="$2" env_triple
  env_triple="$(echo "$triple" | tr 'a-z-' 'A-Z_')"
  local clang="$toolchain_bin/${triple}${min_api}-clang"
  if [ "$host_tag" = "windows-x86_64" ]; then clang="$clang.cmd"; fi

  echo "== $abi ($triple)"
  env "CARGO_TARGET_${env_triple}_LINKER=$clang" \
    cargo build --manifest-path "$repo/rust-core/Cargo.toml" \
    --release --lib --target "$triple"

  local out_dir="$repo/app/src/main/jniLibs/$abi"
  mkdir -p "$out_dir"
  cp "$repo/rust-core/target/$triple/release/librust_core.so" \
    "$out_dir/libuniffi_rust_core.so"
  echo "   wrote app/src/main/jniLibs/$abi/libuniffi_rust_core.so"
}

build_one arm64-v8a aarch64-linux-android
build_one x86_64 x86_64-linux-android
