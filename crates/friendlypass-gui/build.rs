fn main() {
    #[cfg(target_os = "macos")]
    {
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
            println!("cargo:rerun-if-changed=src/macos_identity_store.m");
            println!("cargo:rerun-if-changed=src/macos_window.m");
            cc::Build::new()
                .file("src/macos_identity_store.m")
                .file("src/macos_window.m")
                .flag("-fobjc-arc")
                .compile("friendlypass_macos_bridge");
            println!("cargo:rustc-link-lib=framework=Foundation");
            println!("cargo:rustc-link-lib=framework=AppKit");
            println!("cargo:rustc-link-lib=framework=AuthenticationServices");
        }
    }
}
