//! `cargo run -p friendlypass-mobile --bin uniffi-bindgen -- generate ...`
//!
//! Library-mode bindgen: point `--library` at the built `libfriendlypass_mobile`
//! shared library (host dylib or an Android `.so`) to emit Kotlin.

fn main() {
    uniffi::uniffi_bindgen_main()
}
