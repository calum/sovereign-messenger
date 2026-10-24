#!/usr/bin/env bash
# Regenerates the UniFFI Kotlin bindings into app/src/main/java/uniffi/rust_core.
# The generated file is committed, so a normal Gradle build does not need Rust.
# Run from the repo root after changing src/ffi.rs. Requires the uniffi version
# in Cargo.toml to match the bindgen binary, which is built from the same crate.
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
manifest="$repo/rust-core/Cargo.toml"

cargo build --manifest-path "$manifest" --lib

case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*) lib="rust_core.dll" ;;
  Darwin) lib="librust_core.dylib" ;;
  *) lib="librust_core.so" ;;
esac

# Library mode runs `cargo metadata` from the current directory, so cd first.
cd "$repo/rust-core"
cargo run --features bindgen --bin uniffi-bindgen -- \
  generate --library "$repo/rust-core/target/debug/$lib" \
  --language kotlin --out-dir "$repo/app/src/main/java"

echo "generated app/src/main/java/uniffi/rust_core/rust_core.kt"
