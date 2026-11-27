fn main() {
    #[cfg(target_os = "macos")]
    {
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
            println!("cargo:rerun-if-changed=src/macos_identity_store.m");
            println!("cargo:rerun-if-changed=src/macos_window.m");
            println!("cargo:rerun-if-changed=src/macos_tray.m");
            cc::Build::new()
                .file("src/macos_identity_store.m")
                .file("src/macos_window.m")
                .file("src/macos_tray.m")
                .flag("-fobjc-arc")
                .compile("friendlypass_macos_bridge");
            println!("cargo:rustc-link-lib=framework=Foundation");
            println!("cargo:rustc-link-lib=framework=AppKit");
            println!("cargo:rustc-link-lib=framework=AuthenticationServices");
        }
    }

    #[cfg(windows)]
    {
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
            println!("cargo:rerun-if-changed=assets/app-icon.ico");
            let mut res = winresource::WindowsResource::new();
            res.set_icon("assets/app-icon.ico");
            res.set("ProductName", "friendlypass");
            res.set("FileDescription", "friendlypass Password Manager");
            res.set("OriginalFilename", "friendlypass-gui.exe");
            res.compile_for("friendlypass-gui")
                .expect("failed to compile Windows icon and version resources");
        }
    }
}
