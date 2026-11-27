fn main() {
    #[cfg(target_os = "macos")]
    {
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
            println!("cargo:rerun-if-changed=src/macos_identity_store.m");
            cc::Build::new()
                .file("src/macos_identity_store.m")
                .flag("-fobjc-arc")
                .flag("-mmacosx-version-min=11.0")
                .compile("friendlypass_macos_identity_store");
            println!("cargo:rustc-link-lib=framework=Foundation");
            println!("cargo:rustc-link-lib=framework=AuthenticationServices");
        }
    }
}
