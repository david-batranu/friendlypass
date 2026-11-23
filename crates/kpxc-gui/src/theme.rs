//! The GUI look: a light, 1Password-inspired theme.
//!
//! Keep the palette and spacing in one place so the panels, cards and entry
//! list stay visually consistent.

use eframe::egui::{
    self, Color32, CornerRadius, FontFamily, FontId, Stroke, TextStyle, Vec2, Visuals,
};

pub const BG: Color32 = Color32::from_rgb(0xF5, 0xF6, 0xF8);
pub const SIDEBAR: Color32 = Color32::from_rgb(0xF2, 0xF3, 0xF5);
pub const PANEL: Color32 = Color32::from_rgb(0xFF, 0xFF, 0xFF);
pub const CARD: Color32 = Color32::from_rgb(0xFF, 0xFF, 0xFF);
pub const BORDER: Color32 = Color32::from_rgb(0xE4, 0xE7, 0xEC);
pub const TEXT: Color32 = Color32::from_rgb(0x1F, 0x23, 0x28);
pub const MUTED: Color32 = Color32::from_rgb(0x6B, 0x72, 0x80);
pub const ACCENT: Color32 = Color32::from_rgb(0x2F, 0x6F, 0xED);
pub const ACCENT_SOFT: Color32 = Color32::from_rgb(0xE8, 0xF0, 0xFE);
pub const HOVER: Color32 = Color32::from_rgb(0xF0, 0xF2, 0xF5);
pub const DANGER: Color32 = Color32::from_rgb(0xD9, 0x3B, 0x3B);

/// Apply the theme once per egui context.
pub fn setup(ctx: &egui::Context) {
    let id = egui::Id::new("kpxc-theme-v3");
    if ctx.data(|d| d.get_temp::<bool>(id)).unwrap_or(false) {
        return;
    }

    ctx.set_theme(egui::ThemePreference::Light);
    ctx.all_styles_mut(|style| {
        style.visuals = visuals();
        style.spacing.item_spacing = Vec2::new(8.0, 6.0);
        style.spacing.button_padding = Vec2::new(10.0, 5.0);
        style.spacing.interact_size.y = 30.0;
        style.spacing.menu_margin = egui::Margin::same(8);
        style.spacing.scroll.bar_width = 8.0;
        style.spacing.scroll.floating = true;
        style.animation_time = 0.12;
        style.text_styles.insert(
            TextStyle::Body,
            FontId::new(15.0, FontFamily::Proportional),
        );
        style.text_styles.insert(
            TextStyle::Button,
            FontId::new(14.0, FontFamily::Proportional),
        );
        style.text_styles.insert(
            TextStyle::Heading,
            FontId::new(21.0, FontFamily::Proportional),
        );
        style.text_styles.insert(
            TextStyle::Small,
            FontId::new(12.0, FontFamily::Proportional),
        );
        style
            .text_styles
            .insert(TextStyle::Monospace, FontId::new(14.0, FontFamily::Monospace));
    });
    ctx.data_mut(|d| d.insert_temp(id, true));
}

fn visuals() -> Visuals {
    let mut v = Visuals::light();
    v.dark_mode = false;
    v.panel_fill = BG;
    v.window_fill = PANEL;
    v.extreme_bg_color = PANEL;
    v.faint_bg_color = SIDEBAR;
    v.override_text_color = Some(TEXT);
    v.hyperlink_color = ACCENT;
    v.warn_fg_color = Color32::from_rgb(0xB4, 0x6A, 0x00);
    v.error_fg_color = DANGER;
    v.selection.bg_fill = ACCENT_SOFT;
    v.selection.stroke = Stroke::new(0.0, Color32::TRANSPARENT);
    v.window_stroke = Stroke::new(1.0, BORDER);
    v.window_corner_radius = CornerRadius::same(12);
    v.menu_corner_radius = CornerRadius::same(10);
    v.window_shadow = egui::epaint::Shadow {
        offset: [0, 6],
        blur: 24,
        spread: 0,
        color: Color32::from_black_alpha(28),
    };
    v.popup_shadow = egui::epaint::Shadow {
        offset: [0, 4],
        blur: 16,
        spread: 0,
        color: Color32::from_black_alpha(24),
    };
    v.striped = false;
    v.text_cursor.stroke = Stroke::new(1.5, ACCENT);

    let widgets = &mut v.widgets;
    widgets.noninteractive.bg_fill = Color32::TRANSPARENT;
    widgets.noninteractive.weak_bg_fill = Color32::TRANSPARENT;
    widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
    widgets.noninteractive.corner_radius = CornerRadius::same(8);

    widgets.inactive.bg_fill = Color32::from_rgb(0xF3, 0xF4, 0xF6);
    widgets.inactive.weak_bg_fill = Color32::from_rgb(0xF3, 0xF4, 0xF6);
    widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    widgets.inactive.corner_radius = CornerRadius::same(8);
    widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);

    widgets.hovered.bg_fill = HOVER;
    widgets.hovered.weak_bg_fill = HOVER;
    widgets.hovered.fg_stroke = Stroke::new(1.0, TEXT);
    widgets.hovered.corner_radius = CornerRadius::same(8);
    widgets.hovered.bg_stroke = Stroke::new(1.0, BORDER);

    widgets.active.bg_fill = Color32::from_rgb(0xE3, 0xE6, 0xEB);
    widgets.active.weak_bg_fill = Color32::from_rgb(0xE3, 0xE6, 0xEB);
    widgets.active.fg_stroke = Stroke::new(1.0, TEXT);
    widgets.active.corner_radius = CornerRadius::same(8);

    widgets.open.bg_fill = HOVER;
    widgets.open.weak_bg_fill = HOVER;
    widgets.open.fg_stroke = Stroke::new(1.0, TEXT);
    widgets.open.corner_radius = CornerRadius::same(8);

    v
}

/// A filled blue button, for the one primary action in a view.
pub fn primary_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.to_owned()).color(Color32::WHITE).strong())
        .fill(ACCENT)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(8))
}

/// A quiet, text-like button (used in card headers and row actions).
pub fn subtle_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.to_owned()).color(MUTED))
        .frame(false)
        .corner_radius(CornerRadius::same(6))
}
