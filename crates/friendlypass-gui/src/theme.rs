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
pub const DANGER_SOFT: Color32 = Color32::from_rgb(0xFD, 0xEC, 0xEC);
pub const DANGER_SOFT_PRESSED: Color32 = Color32::from_rgb(0xF8, 0xD9, 0xD9);
pub const GOOD: Color32 = Color32::from_rgb(0x2E, 0xA8, 0x3A);
pub const WARN: Color32 = Color32::from_rgb(0xE5, 0x93, 0x1A);
pub const GOLD: Color32 = Color32::from_rgb(0xF5, 0xB8, 0x1D);
pub const TAG_GREEN: Color32 = Color32::from_rgb(0x2F, 0x9E, 0x62);

/// Horizontal padding inside a quiet action button.
const ACTION_BUTTON_PAD_X: f32 = 10.0;

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
    /// Pencil ("edit").
    Pencil,
    /// Box with an arrow leaving upwards ("share").
    Share,
    /// Arrow pointing down into a tray ("download" / "export to file").
    Download,
    /// Waste bin ("delete").
    Trash,
}

/// How an action button should look. `Quiet` is the default; `Danger` tints
/// the label and hover pill red so destructive actions read as such before
/// they are clicked.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ActionTone {
    Quiet,
    Danger,
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
    action_button_styled(
        ui,
        id_salt,
        label,
        icon,
        hover_text,
        ActionTone::Quiet,
        forced_color,
    )
}

/// A destructive action button: muted at rest, red on hover/click.
pub fn action_button_danger(
    ui: &mut egui::Ui,
    id_salt: &str,
    label: &str,
    icon: ActionIcon,
    hover_text: &str,
) -> egui::Response {
    action_button_styled(ui, id_salt, label, icon, hover_text, ActionTone::Danger, None)
}

/// The width [`action_button`] will occupy, so callers can lay out a row
/// before drawing it (responsive layouts, truncating a label to fit).
pub fn action_button_width(ui: &egui::Ui, label: &str, icon: ActionIcon) -> f32 {
    let font = FontId::new(13.0, FontFamily::Proportional);
    let galley = ui.painter().layout_no_wrap(label.to_owned(), font, TEXT);
    let has_icon = icon != ActionIcon::None;
    let icon_w = if has_icon { 15.0 } else { 0.0 };
    let gap = if has_icon { 5.0 } else { 0.0 };
    icon_w + gap + galley.size().x + ACTION_BUTTON_PAD_X * 2.0
}

fn action_button_styled(
    ui: &mut egui::Ui,
    id_salt: &str,
    label: &str,
    icon: ActionIcon,
    hover_text: &str,
    tone: ActionTone,
    forced_color: Option<Color32>,
) -> egui::Response {
    let font = FontId::new(13.0, FontFamily::Proportional);
    let galley = ui.painter().layout_no_wrap(label.to_owned(), font, TEXT);
    let has_icon = icon != ActionIcon::None;
    let icon_w = if has_icon { 15.0 } else { 0.0 };
    let gap = if has_icon { 5.0 } else { 0.0 };
    let pad_x = ACTION_BUTTON_PAD_X;
    let size = Vec2::new(icon_w + gap + galley.size().x + pad_x * 2.0, 28.0);
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    let hovered = ui.rect_contains_pointer(rect);
    let pressed = hovered && ui.input(|i| i.pointer.primary_down());
    if ui.is_rect_visible(rect) {
        let (rest, active, hover_bg, press_bg) = match tone {
            ActionTone::Quiet => (MUTED, TEXT, HOVER, Color32::from_rgb(0xE2, 0xE5, 0xEA)),
            ActionTone::Danger => (MUTED, DANGER, DANGER_SOFT, DANGER_SOFT_PRESSED),
        };
        let fg = forced_color.unwrap_or(if hovered || pressed { active } else { rest });
        let bg = if pressed {
            press_bg
        } else if hovered {
            hover_bg
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
            ActionIcon::Pencil => {
                draw_pencil_icon(painter, egui::pos2(x + 7.5, cy), fg);
                x += icon_w + gap;
            }
            ActionIcon::Share => {
                draw_share_icon(painter, egui::pos2(x + 7.5, cy), fg);
                x += icon_w + gap;
            }
            ActionIcon::Download => {
                draw_download_icon(painter, egui::pos2(x + 7.5, cy), fg);
                x += icon_w + gap;
            }
            ActionIcon::Trash => {
                draw_trash_icon(painter, egui::pos2(x + 7.5, cy), fg);
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

/// A clickable section chevron: points down when open, right when collapsed.
/// Returns the click response so the caller can toggle the section.
pub fn chevron_toggle(
    ui: &mut egui::Ui,
    id_salt: &str,
    open: bool,
    color: Color32,
) -> egui::Response {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());
    let resp = ui
        .interact(rect, ui.id().with(("chevron", id_salt)), egui::Sense::click())
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    if resp.hovered() {
        ui.painter().rect_filled(rect, CornerRadius::same(4), HOVER);
    }
    let c = rect.center();
    let color = if resp.hovered() { TEXT } else { color };
    if open {
        let p1 = c + egui::vec2(-3.5, -1.5);
        let p2 = c + egui::vec2(0.0, 2.0);
        let p3 = c + egui::vec2(3.5, -1.5);
        ui.painter().line_segment([p1, p2], Stroke::new(1.5, color));
        ui.painter().line_segment([p2, p3], Stroke::new(1.5, color));
    } else {
        let p1 = c + egui::vec2(-1.5, -3.5);
        let p2 = c + egui::vec2(2.0, 0.0);
        let p3 = c + egui::vec2(-1.5, 3.5);
        ui.painter().line_segment([p1, p2], Stroke::new(1.5, color));
        ui.painter().line_segment([p2, p3], Stroke::new(1.5, color));
    }
    resp
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

/// A working back/forward arrow: a 26x26 hit area that shows a hover pill
/// and dims when disabled. Returns the click response.
pub fn nav_arrow_button(ui: &mut egui::Ui, left: bool, enabled: bool) -> egui::Response {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(26.0, 26.0), egui::Sense::hover());
    let resp = ui
        .interact(
            rect,
            ui.id().with(("nav-arrow", left)),
            egui::Sense::click(),
        )
        .on_hover_cursor(if enabled {
            egui::CursorIcon::PointingHand
        } else {
            egui::CursorIcon::Default
        });
    let hovered = enabled && resp.hovered();
    let color = if enabled {
        if hovered {
            TEXT
        } else {
            MUTED
        }
    } else {
        BORDER
    };
    if hovered {
        ui.painter().rect_filled(rect, CornerRadius::same(7), HOVER);
    }
    draw_nav_arrow_at(ui.painter(), rect.center(), left, color);
    resp.on_hover_text(if left { "Back" } else { "Forward" })
}

/// Draw a left or right navigation arrow (`<-` / `->`) as a sized widget.
pub fn draw_nav_arrow(ui: &mut egui::Ui, left: bool, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(20.0, 20.0), egui::Sense::hover());
    draw_nav_arrow_at(ui.painter(), rect.center(), left, color);
}

/// Paint a navigation arrow centred at `c`.
fn draw_nav_arrow_at(painter: &egui::Painter, c: egui::Pos2, left: bool, color: Color32) {
    let dir = if left { -1.0 } else { 1.0 };
    let head = c + egui::vec2(dir * 5.0, 0.0);
    let tail = c + egui::vec2(-dir * 5.0, 0.0);
    painter.line_segment([tail, head], Stroke::new(1.6, color));
    painter.line_segment(
        [head, head + egui::vec2(-dir * 3.8, -3.8)],
        Stroke::new(1.6, color),
    );
    painter.line_segment(
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
    draw_kebab_at(ui.painter(), rect.center(), color);
}

/// Paint a 3-vertical-dots ("more") icon centred at `c`.
pub fn draw_kebab_at(painter: &egui::Painter, c: egui::Pos2, color: Color32) {
    for dy in [-4.5_f32, 0.0, 4.5] {
        painter.circle_filled(c + egui::vec2(0.0, dy), 1.4, color);
    }
}

/// A square icon-only button (26x26) with hover/pressed chrome. The glyph is
/// painted by `paint`, so no font coverage is needed.
pub fn icon_button(
    ui: &mut egui::Ui,
    id_salt: &str,
    hover_text: &str,
    active: bool,
    paint: impl Fn(&egui::Painter, egui::Pos2, Color32),
) -> egui::Response {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(28.0, 28.0), egui::Sense::hover());
    let resp = ui
        .interact(rect, ui.id().with(("icon-btn", id_salt)), egui::Sense::click())
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    let hovered = resp.hovered();
    let pressed = hovered && ui.input(|i| i.pointer.primary_down());
    if hovered || active {
        let bg = if pressed {
            Color32::from_rgb(0xE2, 0xE5, 0xEA)
        } else if hovered {
            HOVER
        } else {
            ACCENT_SOFT
        };
        ui.painter().rect_filled(rect, CornerRadius::same(7), bg);
    }
    let color = if active || hovered { TEXT } else { MUTED };
    paint(ui.painter(), rect.center(), color);
    let resp = resp.on_hover_text(hover_text);
    resp
}

/// Paint a "sidebar / panel" icon: a rounded rectangle with a left divider.
pub fn draw_sidebar_icon(painter: &egui::Painter, center: egui::Pos2, color: Color32) {
    let rect = egui::Rect::from_center_size(center, egui::vec2(14.0, 11.0));
    painter.rect_stroke(
        rect,
        CornerRadius::same(2),
        Stroke::new(1.3, color),
        egui::StrokeKind::Middle,
    );
    let x = rect.left() + 4.6;
    painter.line_segment(
        [egui::pos2(x, rect.top() + 1.0), egui::pos2(x, rect.bottom() - 1.0)],
        Stroke::new(1.3, color),
    );
}

/// An icon-only "more" button that opens a menu. Drawn as three dots so it
/// does not depend on a font glyph, and it really opens the menu (the old
/// static kebab glyphs in the details bar did nothing when clicked).
pub fn overflow_menu(
    ui: &mut egui::Ui,
    id_salt: &str,
    hover_text: &str,
    add: impl FnOnce(&mut egui::Ui),
) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(26.0, 26.0), egui::Sense::hover());
    let resp = ui
        .interact(rect, ui.id().with(("overflow", id_salt)), egui::Sense::click())
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(hover_text);
    if resp.hovered() {
        ui.painter().rect_filled(rect, CornerRadius::same(7), HOVER);
    }
    let color = if resp.hovered() { TEXT } else { MUTED };
    draw_kebab_at(ui.painter(), rect.center(), color);
    egui::Popup::menu(&resp).show(|ui| add(ui));
}

/// Draw a download icon: an arrow pointing into a tray ("export to file").
pub fn draw_download_icon(painter: &egui::Painter, center: egui::Pos2, color: Color32) {
    // Arrow shaft + head.
    let top = center + egui::vec2(0.0, -5.5);
    let tip = center + egui::vec2(0.0, 2.0);
    painter.line_segment([top, tip], Stroke::new(1.5, color));
    painter.line_segment([tip, tip + egui::vec2(-2.6, -2.6)], Stroke::new(1.5, color));
    painter.line_segment([tip, tip + egui::vec2(2.6, -2.6)], Stroke::new(1.5, color));
    // Tray (open at the top).
    let tray = egui::Rect::from_min_max(
        center + egui::vec2(-5.0, 3.0),
        center + egui::vec2(5.0, 6.0),
    );
    painter.line_segment([tray.left_top(), tray.left_bottom()], Stroke::new(1.5, color));
    painter.line_segment([tray.left_bottom(), tray.right_bottom()], Stroke::new(1.5, color));
    painter.line_segment([tray.right_bottom(), tray.right_top()], Stroke::new(1.5, color));
}

/// Draw a waste-bin ("delete") icon.
pub fn draw_trash_icon(painter: &egui::Painter, center: egui::Pos2, color: Color32) {
    let stroke = Stroke::new(1.4, color);
    // Lid.
    painter.line_segment(
        [center + egui::vec2(-5.5, -3.5), center + egui::vec2(5.5, -3.5)],
        stroke,
    );
    // Handle.
    painter.line_segment(
        [center + egui::vec2(-2.0, -3.5), center + egui::vec2(-2.0, -5.0)],
        stroke,
    );
    painter.line_segment(
        [center + egui::vec2(-2.0, -5.0), center + egui::vec2(2.0, -5.0)],
        stroke,
    );
    painter.line_segment(
        [center + egui::vec2(2.0, -5.0), center + egui::vec2(2.0, -3.5)],
        stroke,
    );
    // Body, tapering slightly.
    let body = [
        center + egui::vec2(-4.2, -3.5),
        center + egui::vec2(-3.2, 5.5),
        center + egui::vec2(3.2, 5.5),
        center + egui::vec2(4.2, -3.5),
    ];
    painter.add(egui::Shape::line(body.to_vec(), stroke));
    // Two ribs.
    painter.line_segment(
        [center + egui::vec2(-1.4, -1.4), center + egui::vec2(-1.1, 3.4)],
        Stroke::new(1.1, color),
    );
    painter.line_segment(
        [center + egui::vec2(1.4, -1.4), center + egui::vec2(1.1, 3.4)],
        Stroke::new(1.1, color),
    );
}

/// Shorten `text` to `max_width` by replacing its middle with an ellipsis.
///
/// End-truncation would hide the extension of a long file name; keeping both
/// ends leaves something like `1PasswordExport…151905.1pux` readable.
pub fn truncate_middle(ui: &egui::Ui, text: &str, font: FontId, max_width: f32) -> String {
    let measure = |candidate: &str| {
        ui.painter()
            .layout_no_wrap(candidate.to_owned(), font.clone(), TEXT)
            .size()
            .x
    };
    truncate_middle_with(text, max_width, measure)
}

/// The measuring-free core of [`truncate_middle`], so the shortening policy
/// can be unit-tested without a live `Ui`.
pub fn truncate_middle_with(
    text: &str,
    max_width: f32,
    measure: impl Fn(&str) -> f32,
) -> String {
    if max_width <= 0.0 || measure(text) <= max_width {
        return text.to_owned();
    }
    let chars: Vec<char> = text.chars().collect();
    // Binary search the largest number of kept characters that still fits.
    let build = |keep: usize| -> String {
        // Favour the tail so extensions and numeric suffixes stay visible.
        let head = keep * 2 / 5;
        let tail = keep - head;
        let mut out: String = chars[..head].iter().collect();
        out.push('…');
        if tail > 0 {
            out.extend(&chars[chars.len() - tail..]);
        }
        out
    };
    let (mut lo, mut hi) = (0usize, chars.len().saturating_sub(1));
    let mut best = build(0);
    while lo <= hi {
        let mid = (lo + hi) / 2;
        let candidate = build(mid);
        if measure(&candidate) <= max_width {
            best = candidate;
            lo = mid + 1;
        } else if mid == 0 {
            break;
        } else {
            hi = mid - 1;
        }
    }
    best
}

/// Draw a paperclip — the "this entry has attachments" marker.
///
/// Drawn as a slanted outlined capsule with an inner wire (the conventional
/// paperclip rendering) rather than a lock-like stem + loop, which read as an
/// "8" at badge sizes. `size` is the icon's overall width in points.
pub fn draw_paperclip_icon(
    painter: &egui::Painter,
    center: egui::Pos2,
    size: f32,
    color: Color32,
) {
    let s = size / 16.0;
    let ang = 40f32.to_radians();
    let dir = egui::vec2(ang.cos(), -ang.sin());
    let perp = egui::vec2(-dir.y, dir.x);
    let half = 4.6 * s;
    let radius = 2.3 * s;
    let stroke = Stroke::new((1.4 * s).max(1.0), color);
    let top = center + dir * half;
    let bottom = center - dir * half;

    let mut outline = Vec::with_capacity(28);
    for i in 0..=12 {
        let t = i as f32 / 12.0 * std::f32::consts::PI;
        outline.push(top + (perp * t.cos() + dir * t.sin()) * radius);
    }
    for i in 0..=12 {
        let t = i as f32 / 12.0 * std::f32::consts::PI;
        outline.push(bottom + (-perp * t.cos() - dir * t.sin()) * radius);
    }
    painter.add(egui::Shape::closed_line(outline, stroke));
    // The wire that runs through the middle of a real clip.
    painter.line_segment(
        [center - dir * (half * 0.45), center + dir * (half * 0.95)],
        Stroke::new((1.2 * s).max(0.9), color),
    );
}

/// An inline paperclip + count marker in a list/table row.
pub fn draw_attachment_badge(ui: &mut egui::Ui, count: usize, color: Color32) {
    let label = if count > 1 { count.to_string() } else { String::new() };
    let font = FontId::new(11.0, FontFamily::Proportional);
    let galley = ui.painter().layout_no_wrap(label.clone(), font, color);
    let icon = 13.0;
    let text_w = if label.is_empty() { 0.0 } else { galley.size().x + 3.0 };
    let (rect, resp) =
        ui.allocate_exact_size(egui::vec2(icon + text_w + 2.0, 16.0), egui::Sense::hover());
    let center = egui::pos2(rect.left() + icon / 2.0 + 1.0, rect.center().y);
    draw_paperclip_icon(ui.painter(), center, icon, color);
    if !label.is_empty() {
        ui.painter().galley(
            egui::pos2(center.x + icon / 2.0 + 1.0, rect.center().y - galley.size().y / 2.0),
            galley,
            color,
        );
    }
    let text = if count == 1 {
        "1 attachment".to_owned()
    } else {
        format!("{count} attachments")
    };
    resp.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Label, true, text.as_str()));
    resp.on_hover_text(text);
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
