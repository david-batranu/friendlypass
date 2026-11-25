//! Icon rendering: database custom icons, website favicons (fetched directly
//! from the site and cached), deterministic letter avatars, and generic group
//! glyphs. The KeePass standard icon set is no longer shipped or displayed;
//! the KDBX `IconID` values are still read and written back untouched.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eframe::egui;
use eframe::egui::{Color32, ColorImage, Context, TextureHandle, TextureOptions};
use keepass::db::{CustomDataValue, EntryRef, Icon};

/// Target rasterization resolution for SVG website icons (crisp at 52pt details header).
const SVG_RASTER_SIZE: u32 = 128;

/// Cap downloaded HTML/icon payloads so a misbehaving server cannot exhaust memory.
const MAX_DOWNLOAD_BYTES: u64 = 1024 * 1024;

/// Entry custom-data key for an optional single-glyph avatar symbol.
pub const SYMBOL_CUSTOM_DATA_KEY: &str = "friendlypass.symbol";

/// White-text avatar colours, each with a WCAG-AA contrast ratio (≥ 4.5:1)
/// against white and visually distinct from the others in light and dark mode.
pub const AVATAR_PALETTE: [Color32; 10] = [
    Color32::from_rgb(0x43, 0x38, 0xCA), // indigo
    Color32::from_rgb(0x0E, 0x74, 0x90), // teal
    Color32::from_rgb(0xB9, 0x1C, 0x1C), // red
    Color32::from_rgb(0x15, 0x80, 0x3D), // green
    Color32::from_rgb(0x6D, 0x28, 0xD9), // violet
    Color32::from_rgb(0xA2, 0x1C, 0xAF), // fuchsia
    Color32::from_rgb(0xB4, 0x53, 0x09), // amber
    Color32::from_rgb(0x9D, 0x17, 0x4D), // pink
    Color32::from_rgb(0x3F, 0x62, 0x12), // olive
    Color32::from_rgb(0x37, 0x41, 0x51), // slate
];

/// Glyphs offered by the entry editor's symbol picker. Every entry is checked
/// by a unit test against egui's default fonts, so none render as tofu.
pub const SYMBOLS: &[&str] = &[
    "§", "¶", "†", "‡", "•", "…", "‰", "©", "®", "™", "№", "€", "£", "¥", "¢", "₹",
    "∂", "∆", "∏", "∑", "−", "√", "∞", "∫", "≈", "≠", "≤", "≥", "±", "×", "÷", "°",
    "µ", "¼", "½", "¾", "Ω", "π", "λ", "Σ", "α", "β", "γ", "δ", "◊",
];

/// What an avatar square shows: a letter (or symbol glyph) on a deterministic
/// colour derived from the entry title.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Avatar {
    /// The first grapheme of the title (fallback username, then "?"), uppercased.
    pub letter: String,
    pub color: Color32,
    /// Optional glyph from `friendlypass.symbol`; replaces the letter.
    pub symbol: Option<String>,
}

impl Avatar {
    /// The text painted on the square.
    pub fn text(&self) -> &str {
        self.symbol.as_deref().unwrap_or(&self.letter)
    }
}

/// Something drawable: a custom database icon, a website favicon (with an
/// avatar shown while it loads or when it cannot be fetched), or a painted
/// avatar/folder/trash glyph.
#[derive(Clone)]
pub enum IconSpec {
    Custom {
        key: String,
        bytes: Vec<u8>,
        fallback: Avatar,
    },
    Website {
        origin: String,
        avatar: Avatar,
    },
    Avatar(Avatar),
    Folder,
    Trash,
}

/// Stable FNV-1a hash; unlike `DefaultHasher` its output is fixed across
/// processes and Rust releases, so an avatar keeps its colour forever.
fn stable_hash(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// The palette colour for a seed string (usually the entry title).
pub fn avatar_color(seed: &str) -> Color32 {
    let index = (stable_hash(seed) % AVATAR_PALETTE.len() as u64) as usize;
    AVATAR_PALETTE[index]
}

/// The first grapheme cluster of `text`, uppercased. Returns `None` for
/// whitespace-only input.
fn first_grapheme_upper(text: &str) -> Option<String> {
    use unicode_segmentation::UnicodeSegmentation;
    let trimmed = text.trim();
    let grapheme = UnicodeSegmentation::graphemes(trimmed, true).next()?;
    let upper = grapheme.to_uppercase();
    (!upper.is_empty()).then_some(upper)
}

/// The single glyph stored in `friendlypass.symbol`, if any. Only the first
/// grapheme is used so a malformed (multi-character) value cannot overflow
/// the avatar square.
pub fn entry_symbol(entry: &EntryRef<'_>) -> Option<String> {
    let value = entry.custom_data.get(SYMBOL_CUSTOM_DATA_KEY)?.value.as_ref()?;
    let raw = match value {
        CustomDataValue::String(s) => s.as_str(),
        CustomDataValue::Binary(_) => return None,
    };
    use unicode_segmentation::UnicodeSegmentation;
    let glyph = UnicodeSegmentation::graphemes(raw.trim(), true).next()?;
    (!glyph.is_empty()).then(|| glyph.to_owned())
}

/// Build the avatar for an entry from its title, username and optional symbol.
/// The colour is hashed from the title, falling back to the username when the
/// title is empty.
pub fn avatar_for(title: &str, username: &str, symbol: Option<&str>) -> Avatar {
    let title = title.trim();
    let username = username.trim();
    let seed = if !title.is_empty() {
        title
    } else if !username.is_empty() {
        username
    } else {
        "?"
    };
    let symbol = symbol.and_then(|raw| {
        use unicode_segmentation::UnicodeSegmentation;
        UnicodeSegmentation::graphemes(raw.trim(), true)
            .next()
            .filter(|glyph| !glyph.is_empty())
            .map(str::to_owned)
    });
    Avatar {
        letter: first_grapheme_upper(seed).unwrap_or_else(|| "?".to_owned()),
        color: avatar_color(seed),
        symbol,
    }
}

/// Resolve the icon of a group: a generic folder, or a trash glyph for the
/// recycle bin. The group's KDBX icon (standard or custom) is not displayed
/// but is preserved in the database.
pub fn group_icon_spec(db: &keepass::db::Database, group: keepass::db::GroupId) -> IconSpec {
    if db.recycle_bin().map(|bin| bin.id()) == Some(group) {
        IconSpec::Trash
    } else {
        IconSpec::Folder
    }
}

/// Resolve the icon of an entry. A database custom icon always wins. Otherwise
/// the website favicon is used when the URL yields a site origin, with a letter
/// avatar as the fallback (loading, offline, or no URL).
pub fn entry_icon_spec(
    db: &keepass::db::Database,
    entry: &EntryRef<'_>,
    title: &str,
    username: &str,
    url: &str,
) -> IconSpec {
    let avatar = avatar_for(title, username, entry_symbol(entry).as_deref());
    if let Some(Icon::Custom(id)) = entry.icon() {
        if let Some(ci) = db.custom_icon(*id) {
            return IconSpec::Custom {
                key: format!("custom-{id}"),
                bytes: ci.data.clone(),
                fallback: avatar,
            };
        }
    }
    if let Some(origin) = normalize_site_origin(url) {
        IconSpec::Website { origin, avatar }
    } else {
        IconSpec::Avatar(avatar)
    }
}

/// A custom icon chosen in the entry editor, used for the live preview.
pub fn custom_icon_spec(key: String, bytes: Vec<u8>, fallback: Avatar) -> IconSpec {
    IconSpec::Custom {
        key,
        bytes,
        fallback,
    }
}

/// Extract a normalized `(scheme://host[:port])` origin from an entry URL.
/// Bare hostnames such as `"github.com/login"` default to `https://`, while
/// `localhost` and `127.0.0.1` default to `http://`.
pub fn normalize_site_origin(raw_url: &str) -> Option<String> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() || trimmed.contains(' ') {
        return None;
    }
    let (scheme, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        ("http", r)
    } else if trimmed.contains("://") {
        return None;
    } else {
        let host_preview = trimmed.split(['/', '?', '#']).next().unwrap_or("");
        let host_only = host_preview.split(':').next().unwrap_or("");
        let scheme = if host_only.eq_ignore_ascii_case("localhost") || host_only == "127.0.0.1" {
            "http"
        } else {
            "https"
        };
        (scheme, trimmed)
    };

    let authority = rest.split(['/', '?', '#']).next()?.trim();
    let host_port = authority.rsplit('@').next()?.trim();
    if host_port.is_empty() {
        return None;
    }
    let host = host_port.split(':').next().unwrap_or("");
    let valid_host = host.eq_ignore_ascii_case("localhost")
        || (host.contains('.')
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-')));
    if !valid_host {
        return None;
    }
    Some(format!("{scheme}://{}", host_port.to_ascii_lowercase()))
}

/// Decode SVG or raster (PNG/JPEG/ICO/WebP/BMP) bytes into an egui `ColorImage`.
pub fn decode_image_bytes(bytes: &[u8]) -> Option<ColorImage> {
    if looks_like_svg(bytes) {
        if let Some(img) = decode_svg_bytes(bytes) {
            return Some(img);
        }
    }
    if let Ok(dyn_img) = image::load_from_memory(bytes) {
        let img = dyn_img.to_rgba8();
        if img.width() > 0 && img.height() > 0 {
            let size = [img.width() as usize, img.height() as usize];
            return Some(ColorImage::from_rgba_unmultiplied(size, img.as_raw()));
        }
    }
    decode_svg_bytes(bytes)
}

/// Decode and rasterize an SVG document into an RGBA `ColorImage`.
pub fn decode_svg_bytes(bytes: &[u8]) -> Option<ColorImage> {
    let opt = resvg::usvg::Options::default();
    let tree = resvg::usvg::Tree::from_data(bytes, &opt).ok()?;
    let size = tree.size();
    let w = size.width();
    let h = size.height();
    if w <= 0.0 || h <= 0.0 {
        return None;
    }
    let target = SVG_RASTER_SIZE;
    let scale = (target as f32 / w).min(target as f32 / h);
    let mut pixmap = resvg::tiny_skia::Pixmap::new(target, target)?;
    let tx = (target as f32 - w * scale) * 0.5;
    let ty = (target as f32 - h * scale) * 0.5;
    let transform = resvg::tiny_skia::Transform::from_scale(scale, scale).post_translate(tx, ty);
    resvg::render(&tree, transform, &mut pixmap.as_mut());
    Some(ColorImage::from_rgba_premultiplied(
        [target as usize, target as usize],
        pixmap.data(),
    ))
}

fn looks_like_svg(bytes: &[u8]) -> bool {
    let prefix = &bytes[..bytes.len().min(512)];
    let text = String::from_utf8_lossy(prefix);
    let trimmed = text.trim_start();
    trimmed.starts_with("<svg")
        || (trimmed.starts_with("<?xml") && text.contains("<svg"))
        || (trimmed.starts_with("<!DOCTYPE svg") || text.contains("http://www.w3.org/2000/svg"))
}

/// Parse an HTML document's `<link rel="...">` tags for icon URLs, returning
/// SVG icons first and raster favicons second.
pub fn parse_html_icon_links(html: &str, origin: &str) -> (Vec<String>, Vec<String>) {
    let mut svgs = Vec::new();
    let mut favicons = Vec::new();
    let lower = html.to_ascii_lowercase();
    let mut search_from = 0;

    while let Some(pos) = lower[search_from..].find("<link") {
        let start = search_from + pos;
        let Some(end_rel) = lower[start..].find('>') else {
            break;
        };
        let tag = &html[start..start + end_rel + 1];
        search_from = start + end_rel + 1;

        let Some(rel) = extract_html_attr(tag, "rel") else {
            continue;
        };
        let rel_lower = rel.to_ascii_lowercase();
        let is_icon = rel_lower
            .split_whitespace()
            .any(|tok| tok == "icon" || tok == "mask-icon" || tok == "apple-touch-icon")
            || rel_lower.contains("shortcut icon");
        if !is_icon {
            continue;
        }
        let Some(href) = extract_html_attr(tag, "href") else {
            continue;
        };
        let Some(resolved) = resolve_icon_href(origin, href.trim()) else {
            continue;
        };
        let mime = extract_html_attr(tag, "type")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let href_path = href.split(['?', '#']).next().unwrap_or("").to_ascii_lowercase();
        let is_svg = mime.contains("svg")
            || href_path.ends_with(".svg")
            || rel_lower.split_whitespace().any(|t| t == "mask-icon");
        if is_svg {
            if !svgs.contains(&resolved) {
                svgs.push(resolved);
            }
        } else if !favicons.contains(&resolved) {
            favicons.push(resolved);
        }
    }
    (svgs, favicons)
}

fn extract_html_attr<'a>(tag: &'a str, attr_name: &str) -> Option<&'a str> {
    let lower = tag.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut pos = 0;
    while let Some(found) = lower[pos..].find(attr_name) {
        let idx = pos + found;
        let before_ok = idx == 0 || bytes[idx - 1].is_ascii_whitespace() || bytes[idx - 1] == b'<';
        let mut after = idx + attr_name.len();
        while after < bytes.len() && bytes[after].is_ascii_whitespace() {
            after += 1;
        }
        if before_ok && after < bytes.len() && bytes[after] == b'=' {
            after += 1;
            while after < bytes.len() && bytes[after].is_ascii_whitespace() {
                after += 1;
            }
            if after >= bytes.len() {
                return None;
            }
            let quote = bytes[after];
            if quote == b'"' || quote == b'\'' {
                let val_start = after + 1;
                let end = tag[val_start..].find(quote as char)?;
                return Some(&tag[val_start..val_start + end]);
            } else {
                let val_start = after;
                let end = tag[val_start..]
                    .find(|c: char| c.is_ascii_whitespace() || c == '>')
                    .unwrap_or(tag.len() - val_start);
                return Some(&tag[val_start..val_start + end]);
            }
        }
        pos = idx + attr_name.len();
    }
    None
}

fn resolve_icon_href(origin: &str, href: &str) -> Option<String> {
    if href.is_empty() || href.starts_with("data:") {
        return None;
    }
    if href.starts_with("https://") || href.starts_with("http://") {
        return Some(href.to_owned());
    }
    if let Some(protocol_rel) = href.strip_prefix("//") {
        let scheme = origin.split("://").next().unwrap_or("https");
        return Some(format!("{scheme}://{protocol_rel}"));
    }
    let origin = origin.trim_end_matches('/');
    if href.starts_with('/') {
        Some(format!("{origin}{href}"))
    } else {
        Some(format!("{origin}/{href}"))
    }
}

/// Fetch a website's icon over HTTP(S), preferring SVG icons and falling back
/// to raster favicons.
pub fn fetch_website_icon(origin: &str) -> Option<(ColorImage, Vec<u8>, &'static str)> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_millis(3500)))
        .user_agent(concat!("friendlypass/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();

    let origin = origin.trim_end_matches('/');
    let mut svg_candidates = Vec::new();
    let mut raster_candidates = Vec::new();

    if let Some(html_bytes) = http_get_bytes(&agent, origin) {
        let html = String::from_utf8_lossy(&html_bytes);
        let (svgs, favs) = parse_html_icon_links(&html, origin);
        svg_candidates.extend(svgs);
        raster_candidates.extend(favs);
    }

    for path in ["/favicon.svg", "/icon.svg", "/logo.svg"] {
        let candidate = format!("{origin}{path}");
        if !svg_candidates.contains(&candidate) {
            svg_candidates.push(candidate);
        }
    }
    for path in ["/favicon.ico", "/favicon.png", "/apple-touch-icon.png"] {
        let candidate = format!("{origin}{path}");
        if !raster_candidates.contains(&candidate) {
            raster_candidates.push(candidate);
        }
    }

    let mut tried = HashSet::new();
    // 1. Prefer SVG candidates first.
    for url in &svg_candidates {
        if !tried.insert(url.clone()) {
            continue;
        }
        if let Some(bytes) = http_get_bytes(&agent, url) {
            if let Some(image) = decode_svg_bytes(&bytes).or_else(|| decode_image_bytes(&bytes)) {
                let ext = if looks_like_svg(&bytes) { "svg" } else { "img" };
                return Some((image, bytes, ext));
            }
        }
    }
    // 2. Fallback to favicon / raster candidates.
    for url in &raster_candidates {
        if !tried.insert(url.clone()) {
            continue;
        }
        if let Some(bytes) = http_get_bytes(&agent, url) {
            if let Some(image) = decode_image_bytes(&bytes) {
                let ext = if looks_like_svg(&bytes) { "svg" } else { "img" };
                return Some((image, bytes, ext));
            }
        }
    }
    None
}

fn http_get_bytes(agent: &ureq::Agent, url: &str) -> Option<Vec<u8>> {
    let resp = agent.get(url).call().ok()?;
    if resp.status().as_u16() >= 400 {
        return None;
    }
    let mut buf = Vec::new();
    resp.into_body()
        .into_reader()
        .take(MAX_DOWNLOAD_BYTES)
        .read_to_end(&mut buf)
        .ok()?;
    if buf.is_empty() {
        None
    } else {
        Some(buf)
    }
}

fn default_cache_dir() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("FRIENDLYPASS_ICON_CACHE_DIR") {
        let path = PathBuf::from(p);
        return (!path.as_os_str().is_empty()).then_some(path);
    }
    // Under cargo test, keep tests fast and deterministic unless a test
    // explicitly configures a cache directory or custom fetcher.
    if cfg!(test) {
        return None;
    }
    crate::config::config_path()
        .and_then(|p| p.parent().map(|d| d.join("favicons")))
}

fn sanitize_origin_key(origin: &str) -> String {
    origin
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-') { c } else { '_' })
        .collect()
}

fn load_cached_icon_from_disk(dir: &Path, origin: &str) -> Option<Result<ColorImage, ()>> {
    let key = sanitize_origin_key(origin);
    if dir.join(format!("{key}.miss")).exists() {
        return Some(Err(()));
    }
    for ext in ["svg", "img"] {
        let file = dir.join(format!("{key}.{ext}"));
        if let Ok(bytes) = std::fs::read(&file) {
            if let Some(img) = decode_image_bytes(&bytes) {
                return Some(Ok(img));
            }
        }
    }
    None
}

fn save_cached_icon_to_disk(dir: &Path, origin: &str, bytes: &[u8], ext: &str) {
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let key = sanitize_origin_key(origin);
    let _ = std::fs::remove_file(dir.join(format!("{key}.miss")));
    let path = dir.join(format!("{key}.{ext}"));
    let _ = std::fs::write(path, bytes);
}

fn save_cached_miss_to_disk(dir: &Path, origin: &str) {
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let key = sanitize_origin_key(origin);
    let _ = std::fs::write(dir.join(format!("{key}.miss")), b"");
}

#[derive(Default)]
struct AsyncSiteState {
    in_flight: HashSet<String>,
    completed: HashMap<String, Option<ColorImage>>,
}

/// Lazily-uploaded texture cache for standard, custom, and website icons.
pub struct IconCache {
    map: HashMap<String, TextureHandle>,
    failed_sites: HashSet<String>,
    async_sites: Arc<Mutex<AsyncSiteState>>,
    cache_dir: Option<PathBuf>,
    /// Whether background network fetches are enabled.
    pub network_enabled: bool,
}

impl Default for IconCache {
    fn default() -> Self {
        let network_enabled = std::env::var("FRIENDLYPASS_FETCH_ICONS")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        IconCache {
            map: HashMap::new(),
            failed_sites: HashSet::new(),
            async_sites: Arc::new(Mutex::new(AsyncSiteState::default())),
            cache_dir: default_cache_dir(),
            network_enabled,
        }
    }
}

impl IconCache {
    /// Override the on-disk favicon cache directory (used by tests and
    /// portable setups).
    pub fn with_cache_dir(mut self, dir: PathBuf) -> Self {
        self.cache_dir = Some(dir);
        self
    }

    /// Set the on-disk favicon cache directory on an existing cache.
    pub fn set_cache_dir(&mut self, dir: Option<PathBuf>) {
        self.cache_dir = dir;
    }

    /// Number of website origins currently in flight or cached in memory.
    pub fn is_site_cached_or_failed(&self, origin: &str) -> bool {
        let tex_key = format!("site-{origin}");
        self.map.contains_key(&tex_key) || self.failed_sites.contains(origin)
    }

    pub fn texture(&mut self, ctx: &Context, key: &str, bytes: &[u8]) -> Option<TextureHandle> {
        if let Some(t) = self.map.get(key) {
            return Some(t.clone());
        }
        let image = decode_image_bytes(bytes)?;
        let tex = ctx.load_texture(key, image, TextureOptions::LINEAR);
        self.map.insert(key.to_owned(), tex.clone());
        Some(tex)
    }

    /// Resolve a website icon texture by origin (`https://domain`), checking:
    /// 1. in-memory GPU texture cache
    /// 2. completed background fetch queue
    /// 3. on-disk cache (`favicons/`)
    /// 4. spawning at most one background fetch thread per unique origin.
    pub fn website(&mut self, ctx: &Context, origin: &str) -> Option<TextureHandle> {
        let tex_key = format!("site-{origin}");
        if let Some(t) = self.map.get(&tex_key) {
            return Some(t.clone());
        }
        if self.failed_sites.contains(origin) {
            return None;
        }

        // Check if a background worker finished fetching this origin.
        if let Ok(mut state) = self.async_sites.lock() {
            if let Some(done) = state.completed.remove(origin) {
                state.in_flight.remove(origin);
                match done {
                    Some(image) => {
                        let tex = ctx.load_texture(&tex_key, image, TextureOptions::LINEAR);
                        self.map.insert(tex_key, tex.clone());
                        return Some(tex);
                    }
                    None => {
                        self.failed_sites.insert(origin.to_owned());
                        return None;
                    }
                }
            }
            if state.in_flight.contains(origin) {
                return None;
            }
        }

        // Check on-disk cache before hitting the network.
        if let Some(dir) = &self.cache_dir {
            if let Some(cached) = load_cached_icon_from_disk(dir, origin) {
                match cached {
                    Ok(image) => {
                        let tex = ctx.load_texture(&tex_key, image, TextureOptions::LINEAR);
                        self.map.insert(tex_key, tex.clone());
                        return Some(tex);
                    }
                    Err(()) => {
                        self.failed_sites.insert(origin.to_owned());
                        return None;
                    }
                }
            }
        }

        if !self.network_enabled {
            return None;
        }
        // Avoid background network traffic for synthetic `example.com` /
        // `example.org` domains during unit tests unless explicitly directed
        // at a local test server (`http://127.0.0.1:...` or `http://localhost:...`).
        if (origin.ends_with("://example.com") || origin.ends_with("://example.org"))
            && self.cache_dir.is_none()
        {
            self.failed_sites.insert(origin.to_owned());
            return None;
        }

        if let Ok(mut state) = self.async_sites.lock() {
            if !state.in_flight.insert(origin.to_owned()) {
                return None;
            }
        }

        let origin_owned = origin.to_owned();
        let shared = Arc::clone(&self.async_sites);
        let cache_dir = self.cache_dir.clone();
        let ctx_clone = ctx.clone();

        std::thread::spawn(move || {
            let fetched = fetch_website_icon(&origin_owned);
            let image = match fetched {
                Some((img, bytes, ext)) => {
                    if let Some(dir) = &cache_dir {
                        save_cached_icon_to_disk(dir, &origin_owned, &bytes, ext);
                    }
                    Some(img)
                }
                None => {
                    if let Some(dir) = &cache_dir {
                        save_cached_miss_to_disk(dir, &origin_owned);
                    }
                    None
                }
            };
            if let Ok(mut state) = shared.lock() {
                state.completed.insert(origin_owned, image);
            }
            ctx_clone.request_repaint();
        });

        None
    }

}

/// Render an icon (16x16) into the current UI, if it can be resolved.
pub fn draw_icon(ui: &mut eframe::egui::Ui, cache: &mut IconCache, spec: Option<&IconSpec>) {
    draw_icon_sized(ui, cache, spec, 16.0);
}

/// Draw an icon at a chosen size (entry rows and the details header). This is
/// the single rendering entry point for every icon in the app: database custom
/// icons, website favicons, letter avatars, folders and the recycle bin.
pub fn draw_icon_sized(
    ui: &mut eframe::egui::Ui,
    cache: &mut IconCache,
    spec: Option<&IconSpec>,
    size: f32,
) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let Some(spec) = spec else { return };
    let ctx = ui.ctx().clone();

    match spec {
        IconSpec::Custom {
            key,
            bytes,
            fallback,
        } => match cache.texture(&ctx, key, bytes) {
            Some(texture) => draw_texture(ui, &texture, rect),
            None => draw_avatar(ui, fallback, rect),
        },
        IconSpec::Website { origin, avatar } => match cache.website(&ctx, origin) {
            Some(texture) => draw_texture(ui, &texture, rect),
            None => draw_avatar(ui, avatar, rect),
        },
        IconSpec::Avatar(avatar) => draw_avatar(ui, avatar, rect),
        IconSpec::Folder => draw_folder(ui, rect, crate::theme::p().gold),
        IconSpec::Trash => draw_trash(ui, rect, crate::theme::p().muted),
    }
}

/// Paint a texture, preserving its aspect ratio inside `rect`.
fn draw_texture(ui: &eframe::egui::Ui, texture: &TextureHandle, rect: egui::Rect) {
    let [w, h] = texture.size();
    if w == 0 || h == 0 {
        return;
    }
    let scale = (rect.width() / w as f32).min(rect.height() / h as f32);
    let fit = egui::Rect::from_center_size(rect.center(), egui::vec2(w as f32 * scale, h as f32 * scale));
    ui.painter().image(
        texture.id(),
        fit,
        egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
        Color32::WHITE,
    );
}

/// Paint the letter/symbol avatar: a rounded square filled with the palette
/// colour and the glyph centred in white.
fn draw_avatar(ui: &eframe::egui::Ui, avatar: &Avatar, rect: egui::Rect) {
    let radius = (rect.width() * 0.22).round().max(2.0) as u8;
    ui.painter()
        .rect_filled(rect, egui::CornerRadius::same(radius), avatar.color);
    // Custom data (or a title starting with an exotic emoji) can name a glyph
    // that none of egui's default fonts contain. egui panics on tofu, so fall
    // back to the letter and finally to "?".
    let supports = |text: &str| {
        ui.ctx()
            .fonts_mut(|fonts| fonts.has_glyphs(&egui::FontId::proportional(16.0), text))
    };
    let text = if supports(avatar.text()) {
        avatar.text()
    } else if supports(&avatar.letter) {
        avatar.letter.as_str()
    } else {
        "?"
    };
    if text.is_empty() {
        return;
    }
    let mut font_size = rect.width() * 0.52;
    let max = rect.width() * 0.76;
    let galley = ui.painter().layout_no_wrap(
        text.to_owned(),
        egui::FontId::proportional(font_size),
        Color32::WHITE,
    );
    let width = galley.size().x.max(1.0);
    if width > max {
        font_size *= max / width;
    }
    let galley = ui.painter().layout_no_wrap(
        text.to_owned(),
        egui::FontId::proportional(font_size.max(1.0)),
        Color32::WHITE,
    );
    let pos = rect.center() - galley.size() / 2.0;
    ui.painter().galley(pos, galley, Color32::WHITE);
}

/// Paint a generic folder (tab + body), scaled to `rect`.
fn draw_folder(ui: &eframe::egui::Ui, rect: egui::Rect, color: Color32) {
    let s = rect.width();
    let painter = ui.painter();
    let tab = egui::Rect::from_min_max(
        rect.min + egui::vec2(s * 0.10, s * 0.18),
        rect.min + egui::vec2(s * 0.54, s * 0.36),
    );
    let body = egui::Rect::from_min_max(
        rect.min + egui::vec2(s * 0.08, s * 0.30),
        rect.min + egui::vec2(s * 0.92, s * 0.84),
    );
    let radius = ((s * 0.06).round() as u8).max(1);
    painter.rect_filled(tab, egui::CornerRadius::same(radius), color);
    painter.rect_filled(body, egui::CornerRadius::same(radius), color);
}

/// Paint a waste bin, scaled to `rect`.
fn draw_trash(ui: &eframe::egui::Ui, rect: egui::Rect, color: Color32) {
    let s = rect.width() / 16.0;
    let c = rect.center();
    let painter = ui.painter();
    let stroke = egui::Stroke::new((1.4 * s).max(1.0), color);
    painter.line_segment(
        [
            c + egui::vec2(-5.5 * s, -3.5 * s),
            c + egui::vec2(5.5 * s, -3.5 * s),
        ],
        stroke,
    );
    painter.line_segment(
        [
            c + egui::vec2(-2.0 * s, -3.5 * s),
            c + egui::vec2(-2.0 * s, -5.0 * s),
        ],
        stroke,
    );
    painter.line_segment(
        [
            c + egui::vec2(-2.0 * s, -5.0 * s),
            c + egui::vec2(2.0 * s, -5.0 * s),
        ],
        stroke,
    );
    painter.line_segment(
        [
            c + egui::vec2(2.0 * s, -5.0 * s),
            c + egui::vec2(2.0 * s, -3.5 * s),
        ],
        stroke,
    );
    let body = [
        c + egui::vec2(-4.2 * s, -3.5 * s),
        c + egui::vec2(-3.2 * s, 5.5 * s),
        c + egui::vec2(3.2 * s, 5.5 * s),
        c + egui::vec2(4.2 * s, -3.5 * s),
    ];
    painter.add(egui::Shape::line(body.to_vec(), stroke));
    painter.line_segment(
        [
            c + egui::vec2(-1.4 * s, -1.4 * s),
            c + egui::vec2(-1.1 * s, 3.4 * s),
        ],
        egui::Stroke::new((1.1 * s).max(0.8), color),
    );
    painter.line_segment(
        [
            c + egui::vec2(1.4 * s, -1.4 * s),
            c + egui::vec2(1.1 * s, 3.4 * s),
        ],
        egui::Stroke::new((1.1 * s).max(0.8), color),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const SAMPLE_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="#186ADE"/><circle cx="16" cy="16" r="8" fill="#FFFFFF"/></svg>"##;

    #[test]
    fn avatar_colors_are_deterministic_and_from_the_palette() {
        for title in ["GitHub", "Personal Email", "Home Wi-Fi", "", "?"] {
            let first = avatar_color(title);
            assert_eq!(first, avatar_color(title), "stable for {title:?}");
            assert!(
                AVATAR_PALETTE.contains(&first),
                "{title:?} picked a palette colour"
            );
        }
        // A fixed input keeps the same palette slot across runs/platforms, and
        // different titles spread over the palette.
        assert_eq!(avatar_color("GitHub"), AVATAR_PALETTE[4]);
        assert_ne!(avatar_color("GitHub"), avatar_color("Personal Email"));
        assert_eq!(AVATAR_PALETTE.len(), 10);
        // Every colour is WCAG-AA against white text (contrast ≥ 4.5:1).
        for color in AVATAR_PALETTE {
            let channel = |c: u8| {
                let c = f32::from(c) / 255.0;
                if c <= 0.039_28 {
                    c / 12.92
                } else {
                    ((c + 0.055) / 1.055).powf(2.4)
                }
            };
            let luminance = 0.2126 * channel(color.r())
                + 0.7152 * channel(color.g())
                + 0.0722 * channel(color.b());
            let contrast = 1.05 / (luminance + 0.05);
            assert!(contrast >= 4.5, "{color:?} has contrast {contrast:.2}");
        }
    }

    #[test]
    fn avatars_take_the_first_grapheme() {
        assert_eq!(avatar_for("GitHub", "", None).letter, "G");
        assert_eq!(avatar_for("élan", "", None).letter, "É");
        // Combining characters stay one grapheme.
        assert_eq!(avatar_for("e\u{301}lan", "", None).letter, "E\u{301}");
        // Emoji ZWJ sequences are a single grapheme.
        assert_eq!(avatar_for("👨‍👩‍👧 Family", "", None).letter, "👨‍👩‍👧");
        // Empty title falls back to the username, then "?".
        assert_eq!(avatar_for("", "david", None).letter, "D");
        assert_eq!(avatar_for("   ", "   ", None).letter, "?");
        // Symbols replace the letter, but only the first grapheme is kept.
        let avatar = avatar_for("Wi-Fi", "", Some("★extra"));
        assert_eq!(avatar.text(), "★");
    }

    #[test]
    fn symbol_glyphs_render_in_the_default_egui_fonts() {
        let ctx = egui::Context::default();
        ctx.begin_pass(egui::RawInput::default());
        for symbol in SYMBOLS {
            assert!(
                ctx.fonts_mut(|fonts| fonts.has_glyphs(
                    &egui::FontId::proportional(16.0),
                    symbol
                )),
                "symbol {symbol:?} is missing from egui's default fonts"
            );
        }
        let mut output = ctx.end_pass();
        output.textures_delta.clear();
    }

    #[test]
    fn entry_symbol_reads_and_ignores_malformed_custom_data() {
        use keepass::db::{CustomDataItem, CustomDataValue};
        let mut db = keepass::Database::new();
        let id = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected("Title", "Example");
            entry.id()
        };
        assert_eq!(db.entry(id).unwrap().id(), id);
        {
            let mut entry = db.entry_mut(id).unwrap();
            entry.custom_data.insert(
                SYMBOL_CUSTOM_DATA_KEY.into(),
                CustomDataItem {
                    value: Some(CustomDataValue::String("★".into())),
                    last_modification_time: None,
                },
            );
        }
        assert_eq!(
            entry_symbol(&db.entry(id).unwrap()).as_deref(),
            Some("★")
        );
        {
            let mut entry = db.entry_mut(id).unwrap();
            entry.custom_data.insert(
                SYMBOL_CUSTOM_DATA_KEY.into(),
                CustomDataItem {
                    value: Some(CustomDataValue::Binary(vec![1, 2, 3])),
                    last_modification_time: None,
                },
            );
        }
        assert_eq!(entry_symbol(&db.entry(id).unwrap()), None);
    }

    #[test]
    fn normalizes_site_origins() {
        assert_eq!(
            normalize_site_origin("https://GitHub.com/login?next=/dashboard"),
            Some("https://github.com".to_owned())
        );
        assert_eq!(
            normalize_site_origin("http://127.0.0.1:8123/account"),
            Some("http://127.0.0.1:8123".to_owned())
        );
        assert_eq!(
            normalize_site_origin("news.ycombinator.com/news"),
            Some("https://news.ycombinator.com".to_owned())
        );
        assert_eq!(
            normalize_site_origin("localhost:3000/app"),
            Some("http://localhost:3000".to_owned())
        );
        assert_eq!(normalize_site_origin(""), None);
        assert_eq!(normalize_site_origin("not a url"), None);
    }

    #[test]
    fn parses_html_link_tags_preferring_svg_over_favicon() {
        let html = r##"
            <!doctype html>
            <html>
              <head>
                <link rel="shortcut icon" href="/static/favicon.ico">
                <link rel="icon" type="image/png" href="https://cdn.example.com/icon-32.png">
                <link rel="icon" type="image/svg+xml" href="/assets/brand.svg">
                <link rel="mask-icon" href="pinned.svg" color="#186ade">
              </head>
            </html>
        "##;
        let (svgs, favs) = parse_html_icon_links(html, "https://example.com");
        assert_eq!(
            svgs,
            vec![
                "https://example.com/assets/brand.svg",
                "https://example.com/pinned.svg"
            ]
        );
        assert_eq!(
            favs,
            vec![
                "https://example.com/static/favicon.ico",
                "https://cdn.example.com/icon-32.png"
            ]
        );
    }

    #[test]
    fn decodes_svg_bytes_into_rgba_image() {
        let img = decode_image_bytes(SAMPLE_SVG.as_bytes()).expect("SVG rasterized");
        assert_eq!(img.size, [SVG_RASTER_SIZE as usize, SVG_RASTER_SIZE as usize]);
        // Center pixel is inside the white circle.
        let center = img.pixels[(SVG_RASTER_SIZE as usize / 2) * (SVG_RASTER_SIZE as usize + 1)];
        assert_eq!(center, eframe::egui::Color32::WHITE);
    }

    #[test]
    fn fetches_svg_when_available_and_falls_back_to_favicon() {
        // 1. Server offering both an SVG icon and a PNG favicon: SVG must win.
        let svg_hits = Arc::new(AtomicUsize::new(0));
        let fav_hits = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let origin = format!("http://{addr}");

        let svg_hits_srv = Arc::clone(&svg_hits);
        let fav_hits_srv = Arc::clone(&fav_hits);
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                let Ok((mut stream, _)) = listener.accept() else { break };
                let mut req = [0u8; 1024];
                let n = stream.read(&mut req).unwrap_or(0);
                let line = String::from_utf8_lossy(&req[..n]);
                let path = line
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");
                match path {
                    "/" => {
                        let body = r#"<html><head>
                            <link rel="icon" href="/favicon.png" type="image/png">
                            <link rel="icon" href="/brand.svg" type="image/svg+xml">
                        </head></html>"#;
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                    "/brand.svg" => {
                        svg_hits_srv.fetch_add(1, Ordering::SeqCst);
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            SAMPLE_SVG.len(),
                            SAMPLE_SVG
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                    "/favicon.png" => {
                        fav_hits_srv.fetch_add(1, Ordering::SeqCst);
                        let png = crate::brand::ICON_PNG;
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            png.len()
                        );
                        let _ = stream.write_all(header.as_bytes());
                        let _ = stream.write_all(png);
                    }
                    _ => {
                        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    }
                }
            }
        });

        let (img, _bytes, ext) = fetch_website_icon(&origin).expect("fetched website SVG");
        assert_eq!(ext, "svg", "preferred SVG over PNG favicon");
        assert_eq!(svg_hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            fav_hits.load(Ordering::SeqCst),
            0,
            "did not need to fetch the raster favicon once the SVG succeeded"
        );
        assert_eq!(img.size, [SVG_RASTER_SIZE as usize, SVG_RASTER_SIZE as usize]);
        let _ = handle.join();

        // 2. Server without any SVG: must fall back to /favicon.ico.
        let ico_hits = Arc::new(AtomicUsize::new(0));
        let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let origin2 = format!("http://{addr2}");
        let ico_hits_srv = Arc::clone(&ico_hits);
        let handle2 = std::thread::spawn(move || {
            for _ in 0..5 {
                let Ok((mut stream, _)) = listener2.accept() else { break };
                let mut req = [0u8; 1024];
                let n = stream.read(&mut req).unwrap_or(0);
                let line = String::from_utf8_lossy(&req[..n]);
                let path = line
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");
                match path {
                    "/" => {
                        let body = "<html><head><title>No SVG</title></head></html>";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                    "/favicon.ico" => {
                        ico_hits_srv.fetch_add(1, Ordering::SeqCst);
                        let png = crate::brand::ICON_PNG;
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            png.len()
                        );
                        let _ = stream.write_all(header.as_bytes());
                        let _ = stream.write_all(png);
                        break;
                    }
                    _ => {
                        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    }
                }
            }
        });

        let (_img2, _bytes2, ext2) =
            fetch_website_icon(&origin2).expect("fell back to /favicon.ico");
        assert_eq!(ext2, "img");
        assert_eq!(ico_hits.load(Ordering::SeqCst), 1);
        let _ = handle2.join();
    }
}
