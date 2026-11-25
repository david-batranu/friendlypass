//! Product branding: one place for the name, the tagline, the app icon and
//! the per-user data directory, so a rename never has to chase string
//! literals through the UI, the startup helpers and the packaging.

use eframe::egui;

/// Human-readable product name (window title, bundle name, about text).
pub const NAME: &str = "friendlypass";

/// One-line description shown under the name on the unlock screen.
pub const TAGLINE: &str = "Keep your passwords friendly";

/// Filesystem/bundle stem used for per-user directories (`config`, keyring
/// service names and autostart entries) and for the macOS `.app` bundle.
pub const SLUG: &str = "friendlypass";

/// The cropped app icon (512×512 RGBA, squircle with transparent
/// corners), embedded straight into the binary so the binary is self
/// contained and does not need `packaging/` on disk at runtime. The same
/// artwork is used for the macOS `AppIcon.icns` and the Linux desktop icon.
pub const ICON_PNG: &[u8] = include_bytes!("../assets/app-icon.png");

/// Decode [`ICON_PNG`] into something egui can upload as a window icon.
pub fn window_icon() -> Option<egui::IconData> {
    let image = image::load_from_memory_with_format(ICON_PNG, image::ImageFormat::Png)
        .ok()?
        .to_rgba8();
    let (width, height) = image.dimensions();
    Some(egui::IconData {
        rgba: image.into_raw(),
        width,
        height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_icon_decodes_to_a_square_rgba_image() {
        let icon = window_icon().expect("embedded app icon decodes");
        assert_eq!(icon.width, 512);
        assert_eq!(icon.height, 512);
        assert_eq!(icon.rgba.len(), 512 * 512 * 4);
        // Transparent corners: the artwork is a squircle, not a full square.
        assert_eq!(&icon.rgba[3..4], &[0]);
        // The centre pixel is opaque artwork.
        let centre = ((256 * 512 + 256) * 4 + 3) as usize;
        assert_eq!(icon.rgba[centre], 255);
    }
}
