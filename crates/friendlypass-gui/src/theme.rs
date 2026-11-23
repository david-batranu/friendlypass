//! The GUI look: a light, 1Password-inspired theme.
//!
//! Keep the palette and spacing in one place so the panels, cards and entry
//! list stay visually consistent.

use eframe::egui::{
    self, Color32, CornerRadius, FontFamily, FontId, Stroke, TextStyle, Vec2, Visuals,
};

pub const BG: Color32 = Color32::from_rgb(0xF6, 0xF7, 0xF9);
pub const SIDEBAR: Color32 = Color32::from_rgb(0xEC, 0xEE, 0xF2);
pub const SIDEBAR_HOVER: Color32 = Color32::from_rgb(0xE1, 0xE5, 0xEC);
pub const SIDEBAR_SELECTED: Color32 = Color32::from_rgb(0xD4, 0xE3, 0xFA);
pub const LIST_HOVER: Color32 = Color32::from_rgb(0xF1, 0xF4, 0xF9);
pub const LIST_SELECTED: Color32 = Color32::from_rgb(0xE4, 0xEE, 0xFD);
pub const LIST_SELECTED_STROKE: Color32 = Color32::from_rgb(0xB8, 0xD2, 0xF8);
pub const PANEL: Color32 = Color32::from_rgb(0xFF, 0xFF, 0xFF);
pub const CARD: Color32 = Color32::from_rgb(0xFF, 0xFF, 0xFF);
pub const BORDER: Color32 = Color32::from_rgb(0xE2, 0xE6, 0xED);
pub const TEXT: Color32 = Color32::from_rgb(0x18, 0x1D, 0x24);
pub const MUTED: Color32 = Color32::from_rgb(0x64, 0x6D, 0x7A);
pub const ACCENT: Color32 = Color32::from_rgb(0x18, 0x6A, 0xDE);
pub const ACCENT_SOFT: Color32 = Color32::from_rgb(0xE8, 0xF0, 0xFE);
pub const HOVER: Color32 = Color32::from_rgb(0xEF, 0xF2, 0xF6);
pub const DANGER: Color32 = Color32::from_rgb(0xD9, 0x3B, 0x3B);
pub const GOOD: Color32 = Color32::from_rgb(0x2E, 0xA8, 0x3A);
pub const WARN: Color32 = Color32::from_rgb(0xE5, 0x93, 0x1A);
pub const GOLD: Color32 = Color32::from_rgb(0xF5, 0xB8, 0x1D);
pub const TAG_GREEN: Color32 = Color32::from_rgb(0x2F, 0x9E, 0x62);

/// Apply the theme once per egui context.
pub fn setup(ctx: &egui::Context) {
    let id = egui::Id::new("friendlypass-theme-v3");
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

/// Icons for the quiet action buttons in cards and rows.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ActionIcon {
    None,
    /// Two overlapping pages (clipboard).
    Copy,
    /// Checkmark — the "copied" confirmation.
    Check,
    /// Eye (with a slash when `shown` is false).
    Eye { shown: bool },
    /// Box with an arrow leaving to the top right ("open in browser").
    Open,
}

/// A quiet action button: no chrome at rest, a soft pill on hover, a darker
/// pill while pressed, and an optional leading icon. Returns the click
/// response; `id_salt` must be unique per call site.
pub fn action_button(
    ui: &mut egui::Ui,
    id_salt: &str,
    label: &str,
    icon: ActionIcon,
    hover_text: &str,
) -> egui::Response {
    action_button_ex(ui, id_salt, label, icon, hover_text, None)
}

/// Like [`action_button`], but with a fixed ink color (e.g. green for the
/// "Copied" confirmation, red for destructive actions) that does not change
/// on hover.
pub fn action_button_ex(
    ui: &mut egui::Ui,
    id_salt: &str,
    label: &str,
    icon: ActionIcon,
    hover_text: &str,
    forced_color: Option<Color32>,
) -> egui::Response {
    let font = FontId::new(13.0, FontFamily::Proportional);
    let galley = ui.painter().layout_no_wrap(label.to_owned(), font, TEXT);
    let has_icon = icon != ActionIcon::None;
    let icon_w = if has_icon { 15.0 } else { 0.0 };
    let gap = if has_icon { 5.0 } else { 0.0 };
    let pad_x = 10.0;
    let size = Vec2::new(icon_w + gap + galley.size().x + pad_x * 2.0, 28.0);
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    let hovered = ui.rect_contains_pointer(rect);
    let pressed = hovered && ui.input(|i| i.pointer.primary_down());
    if ui.is_rect_visible(rect) {
        let fg = forced_color.unwrap_or(if hovered || pressed { TEXT } else { MUTED });
        let bg = if pressed {
            Color32::from_rgb(0xE2, 0xE5, 0xEA)
        } else if hovered {
            HOVER
        } else {
            Color32::TRANSPARENT
        };
        let painter = ui.painter();
        if bg != Color32::TRANSPARENT {
            painter.rect_filled(rect, CornerRadius::same(7), bg);
            if hovered && !pressed {
                painter.rect_stroke(
                    rect,
                    CornerRadius::same(7),
                    Stroke::new(1.0, BORDER),
                    egui::StrokeKind::Middle,
                );
            }
        }
        let cy = rect.center().y;
        let mut x = rect.left() + pad_x;
        match icon {
            ActionIcon::None => {}
            ActionIcon::Copy => {
                draw_copy_icon(painter, egui::pos2(x + 7.0, cy), fg);
                x += icon_w + gap;
            }
            ActionIcon::Check => {
                draw_check_icon(painter, egui::pos2(x + 7.0, cy), fg);
                x += icon_w + gap;
            }
            ActionIcon::Eye { shown } => {
                draw_eye_icon(painter, egui::pos2(x + 7.5, cy), fg, shown);
                x += icon_w + gap;
            }
            ActionIcon::Open => {
                draw_open_icon(painter, egui::pos2(x + 7.5, cy), fg);
                x += icon_w + gap;
            }
        }
        let text_rect =
            egui::Align2::LEFT_CENTER.anchor_size(egui::pos2(x, cy), galley.size());
        painter.galley(text_rect.min, galley, fg);
    }
    let mut response = ui.interact(
        rect,
        ui.id().with(("action-btn", id_salt)),
        egui::Sense::click(),
    );
    if !hover_text.is_empty() {
        response = response.on_hover_text(hover_text);
    }
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::Role::Button, ui.is_enabled(), label)
    });
    response
}

/// Clipboard icon: two overlapping pages.
pub fn draw_copy_icon(painter: &egui::Painter, center: egui::Pos2, color: Color32) {
    let back = egui::Rect::from_center_size(center + egui::vec2(2.0, 2.0), egui::vec2(8.5, 10.5));
    painter.rect_stroke(
        back,
        CornerRadius::same(3),
        Stroke::new(1.5, color),
        egui::StrokeKind::Middle,
    );
    let front = egui::Rect::from_center_size(center + egui::vec2(-2.0, -2.0), egui::vec2(8.5, 10.5));
    painter.rect_filled(front, CornerRadius::same(3), Color32::WHITE);
    painter.rect_stroke(
        front,
        CornerRadius::same(3),
        Stroke::new(1.5, color),
        egui::StrokeKind::Middle,
    );
}

/// Checkmark icon.
pub fn draw_check_icon(painter: &egui::Painter, center: egui::Pos2, color: Color32) {
    painter.line_segment(
        [center + egui::vec2(-4.5, 0.5), center + egui::vec2(-1.2, 3.8)],
        Stroke::new(2.0, color),
    );
    painter.line_segment(
        [center + egui::vec2(-1.2, 3.8), center + egui::vec2(5.0, -4.5)],
        Stroke::new(2.0, color),
    );
}

/// Eye icon; crossed with a slash when `shown` is false.
pub fn draw_eye_icon(painter: &egui::Painter, center: egui::Pos2, color: Color32, shown: bool) {
    painter.circle_stroke(center, 5.4, Stroke::new(1.5, color));
    painter.circle_filled(center, 2.1, color);
    if !shown {
        painter.line_segment(
            [center + egui::vec2(-5.6, 5.6), center + egui::vec2(5.6, -5.6)],
            Stroke::new(1.6, color),
        );
    }
}

/// "Open in browser" icon: a box with an arrow leaving to the top right.
pub fn draw_open_icon(painter: &egui::Painter, center: egui::Pos2, color: Color32) {
    let b = egui::Rect::from_center_size(center + egui::vec2(-1.8, 1.8), egui::vec2(8.0, 8.0));
    painter.rect_stroke(b, CornerRadius::same(2), Stroke::new(1.4, color), egui::StrokeKind::Middle);
    let tip = center + egui::vec2(5.8, -5.8);
    painter.line_segment([center + egui::vec2(-2.2, 2.2), tip], Stroke::new(1.5, color));
    painter.line_segment([tip, tip + egui::vec2(-4.4, 0.4)], Stroke::new(1.5, color));
    painter.line_segment([tip, tip + egui::vec2(-0.4, 4.4)], Stroke::new(1.5, color));
}

/// Draw a small progress ring (used for password strength and TOTP countdown).
pub fn draw_progress_ring(ui: &mut egui::Ui, radius: f32, fraction: f32, color: Color32) {
    let size = Vec2::splat(radius * 2.0 + 4.0);
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    let center = rect.center();
    let painter = ui.painter();
    painter.circle_stroke(
        center,
        radius,
        Stroke::new(2.2, Color32::from_rgb(0xE5, 0xE7, 0xEB)),
    );
    let steps = 28usize;
    let clamped = fraction.clamp(0.05, 1.0);
    let active_steps = ((steps as f32 * clamped).round() as usize).max(2);
    let start = -std::f32::consts::FRAC_PI_2;
    let mut pts = Vec::with_capacity(active_steps + 1);
    for i in 0..=active_steps {
        let a = start + (i as f32 / steps as f32) * std::f32::consts::TAU;
        pts.push(center + egui::vec2(a.cos() * radius, a.sin() * radius));
    }
    painter.add(egui::Shape::line(pts, Stroke::new(2.4, color)));
}

/// Draw a small 5-pointed gold star badge.
pub fn draw_star_badge(painter: &egui::Painter, center: egui::Pos2, outer: f32) {
    let inner = outer * 0.45;
    let mut pts = Vec::with_capacity(10);
    for i in 0..10 {
        let r = if i % 2 == 0 { outer } else { inner };
        let a = -std::f32::consts::FRAC_PI_2 + (i as f32) * std::f32::consts::PI / 5.0;
        pts.push(center + egui::vec2(a.cos() * r, a.sin() * r));
    }
    painter.add(egui::Shape::convex_polygon(
        pts,
        GOLD,
        Stroke::new(1.0, Color32::WHITE),
    ));
}

/// Draw a green tag pill icon with a white hole on the left.
pub fn draw_tag_pill(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(16.0, 14.0), egui::Sense::hover());
    let pill = egui::Rect::from_center_size(rect.center(), egui::vec2(13.0, 11.0));
    ui.painter().rect_filled(pill, CornerRadius::same(4), color);
    ui.painter().circle_filled(
        egui::pos2(pill.left() + 3.8, pill.center().y),
        1.7,
        Color32::WHITE,
    );
}

/// Draw a 2x2 blue squares icon ("All Categories").
pub fn draw_categories_grid_icon(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());
    let c = Color32::from_rgb(0x45, 0x9E, 0xDC);
    let base = rect.min + egui::vec2(1.5, 1.5);
    for row in 0..2 {
        for col in 0..2 {
            let p = base + egui::vec2(col as f32 * 7.2, row as f32 * 7.2);
            ui.painter().rect_filled(
                egui::Rect::from_min_size(p, egui::vec2(5.6, 5.6)),
                CornerRadius::same(1),
                c,
            );
        }
    }
}

/// Draw a small downward chevron (`v`).
pub fn draw_chevron_down(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
    let c = rect.center();
    let p1 = c + egui::vec2(-3.5, -1.5);
    let p2 = c + egui::vec2(0.0, 2.0);
    let p3 = c + egui::vec2(3.5, -1.5);
    ui.painter().line_segment([p1, p2], Stroke::new(1.5, color));
    ui.painter().line_segment([p2, p3], Stroke::new(1.5, color));
}

/// Draw a small right chevron (`>`).
pub fn draw_chevron_right(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
    let c = rect.center();
    let p1 = c + egui::vec2(-1.5, -3.5);
    let p2 = c + egui::vec2(2.0, 0.0);
    let p3 = c + egui::vec2(-1.5, 3.5);
    ui.painter().line_segment([p1, p2], Stroke::new(1.5, color));
    ui.painter().line_segment([p2, p3], Stroke::new(1.5, color));
}

/// Draw a left or right navigation arrow (`<-` / `->`).
pub fn draw_nav_arrow(ui: &mut egui::Ui, left: bool, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(20.0, 20.0), egui::Sense::hover());
    let c = rect.center();
    let dir = if left { -1.0 } else { 1.0 };
    let head = c + egui::vec2(dir * 5.0, 0.0);
    let tail = c + egui::vec2(-dir * 5.0, 0.0);
    ui.painter().line_segment([tail, head], Stroke::new(1.6, color));
    ui.painter().line_segment(
        [head, head + egui::vec2(-dir * 3.8, -3.8)],
        Stroke::new(1.6, color),
    );
    ui.painter().line_segment(
        [head, head + egui::vec2(-dir * 3.8, 3.8)],
        Stroke::new(1.6, color),
    );
}

/// Draw a magnifying glass search icon.
pub fn draw_search_icon(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(15.0, 15.0), egui::Sense::hover());
    let c = rect.center() + egui::vec2(-1.0, -1.0);
    ui.painter().circle_stroke(c, 4.3, Stroke::new(1.5, color));
    ui.painter().line_segment(
        [c + egui::vec2(3.1, 3.1), c + egui::vec2(6.2, 6.2)],
        Stroke::new(1.6, color),
    );
}

/// Draw a pencil icon for the Edit action.
pub fn draw_pencil_icon(painter: &egui::Painter, center: egui::Pos2, color: Color32) {
    let p1 = center + egui::vec2(-4.5, 4.5);
    let p2 = center + egui::vec2(4.0, -4.0);
    painter.line_segment([p1, p2], Stroke::new(1.8, color));
    painter.circle_filled(p1 + egui::vec2(-0.6, 0.6), 1.0, color);
}

/// Draw a 3-vertical-dots overflow icon.
pub fn draw_kebab_icon(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(14.0, 16.0), egui::Sense::hover());
    let c = rect.center();
    for dy in [-4.5_f32, 0.0, 4.5] {
        ui.painter().circle_filled(c + egui::vec2(0.0, dy), 1.4, color);
    }
}

/// Draw a share / upload icon (box with upward arrow).
pub fn draw_share_icon(painter: &egui::Painter, center: egui::Pos2, color: Color32) {
    let box_rect = egui::Rect::from_center_size(center + egui::vec2(0.0, 2.0), egui::vec2(10.0, 7.5));
    painter.rect_stroke(box_rect, CornerRadius::same(2), Stroke::new(1.3, color), egui::StrokeKind::Middle);
    let top = center + egui::vec2(0.0, -5.0);
    let mid = center + egui::vec2(0.0, 2.5);
    painter.line_segment([mid, top], Stroke::new(1.4, color));
    painter.line_segment([top, top + egui::vec2(-2.6, 2.6)], Stroke::new(1.4, color));
    painter.line_segment([top, top + egui::vec2(2.6, 2.6)], Stroke::new(1.4, color));
}
