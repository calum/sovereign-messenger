//! Generates the Kotlin bindings from the built library. Build with
//! `--features bindgen`; `scripts/gen-kotlin.sh` wraps the call.

fn main() {
    uniffi::uniffi_bindgen_main()
}
