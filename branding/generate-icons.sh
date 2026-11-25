#!/usr/bin/env bash
# Derive every friendlypass icon/logo asset from the single master artwork.
#
#   bash branding/generate-icons.sh
#
# Input:  branding/friendlypass-logo.jpg (2048x2048, no alpha)
# Output: branding/derived/friendlypass-mark.jpg      (mark: mascot only)
#         branding/derived/friendlypass-logo.jpg      (full artwork + wordmark)
#         packaging/macos/AppIcon.icns                (macOS app icon, 16..1024)
#         crates/friendlypass-gui/assets/app-icon.png (512 px squircle)
#         extension/src/icons/icon-{16,32,48,128}.png
#         ../../briefs/shots/logo-*.png               (review previews)
#
# Everything is rendered from the master directly (never from a previously
# generated asset), so repeated runs produce byte-identical files. The only
# required tools are ImageMagick 7 (`magick`) and macOS `iconutil`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MASTER="$ROOT/branding/friendlypass-logo.jpg"
DERIVED="$ROOT/branding/derived"
ICONSET_OUT="$ROOT/packaging/macos/AppIcon.icns"
GUI_ICON="$ROOT/crates/friendlypass-gui/assets/app-icon.png"
EXT_ICONS="$ROOT/extension/src/icons"
PREVIEW_DIR="${PREVIEW_DIR:-$(cd "$ROOT/../.." && pwd)/briefs/shots}"

# Crop boxes in the 2048x2048 master.
#   mark  — square around the mascot (shield, key, arms, feet); the 1597
#           bottom edge stops ~33 px above the wordmark, which starts at 1630.
#   tight — closer crop on the shield face for 16/32 px browser icons.
MARK_GEO="1360x1360+400+237"
TIGHT_GEO="1000x1000+525+370"

# Apple's macOS icon grid: 824 px rounded square inside a 1024 px canvas,
# with a 22.4% corner radius. The same ratio is used for every squircle.
APP_CONTENT=824
APP_CANVAS=1024
APP_CONTENT_PER_MILLE=$(( (APP_CONTENT * 1000 + APP_CANVAS / 2) / APP_CANVAS ))
GUI_SIZE=512
# Browser toolbar icons sit a little closer to the canvas edge so they stay
# legible at 16 px.
EXT_CONTENT=880 # per mille of the icon size
CORNER_PER_MILLE=224

command -v magick >/dev/null || { echo "error: ImageMagick 7 (magick) is required" >&2; exit 1; }
if [[ ! -f "$MASTER" ]]; then
    echo "error: missing master artwork: $MASTER" >&2
    exit 1
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/friendlypass-icons.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# PNG encoder settings shared by every output: strip metadata (including
# timestamps) and use maximum compression.
png() {
    local out="$1"
    shift
    magick "$@" -strip -define png:compression-level=9 \
        -define png:compression-filter=5 \
        -define png:exclude-chunks=date,time "$out"
}

# rounded_square SRC SIZE CONTENT_PER_MILLE OUT
# Downscale SRC to CONTENT square, mask it with a rounded rectangle, and centre
# it on a transparent SIZE x SIZE canvas.
rounded_square() {
    local src="$1" size="$2" content="$3" out="$4"
    local side radius offset
    side=$(( size * content / 1000 ))
    [[ "$side" -lt 1 ]] && side=1
    radius=$(( side * CORNER_PER_MILLE / 1000 ))
    [[ "$radius" -lt 1 ]] && radius=1
    offset=$(( (size - side) / 2 ))

    magick "$src" -filter Lanczos -resize "${side}x${side}" \
        -strip "$TMP/content.png"

    # Black canvas with a white rounded rectangle; used as the alpha mask.
    magick -size "${side}x${side}" xc:black -fill white \
        -draw "roundrectangle 0,0,$((side - 1)),$((side - 1)),${radius},${radius}" \
        -strip "$TMP/mask.png"

    magick "$TMP/content.png" "$TMP/mask.png" -alpha off \
        -compose CopyOpacity -composite "$TMP/masked.png"

    png "$out" -size "${size}x${size}" xc:none "$TMP/masked.png" \
        -geometry "+${offset}+${offset}" -compose over -composite
}

echo "== derived masters =="
mkdir -p "$DERIVED"
# The masters are committed as high-quality JPEG (the source is JPEG and the
# artwork keeps its background). They are reference/consumer assets; every
# icon below is rendered from the original master, not from these files.
magick "$MASTER" -crop "$MARK_GEO" +repage -strip \
    -sampling-factor 4:4:4 -quality 90 "$DERIVED/friendlypass-mark.jpg"
magick "$MASTER" -resize 1024x1024 -strip \
    -sampling-factor 4:4:4 -quality 90 "$DERIVED/friendlypass-logo.jpg"
echo "  mark  $MARK_GEO -> branding/derived/friendlypass-mark.jpg"
echo "  logo  full 2048 -> 1024 -> branding/derived/friendlypass-logo.jpg"

# Crop once at full resolution for the icon renders.
magick "$MASTER" -crop "$MARK_GEO" +repage -strip "$TMP/mark-full.png"
magick "$MASTER" -crop "$TIGHT_GEO" +repage -strip "$TMP/mark-tight.png"

echo "== macOS app icon =="
iconset="$TMP/AppIcon.iconset"
mkdir -p "$iconset"
# Render every resolution from the full-resolution crop instead of resizing
# an already-masked 1024 px image, so the small sizes stay crisp.
for spec in \
    "16 icon_16x16.png" \
    "32 icon_16x16@2x.png" \
    "32 icon_32x32.png" \
    "64 icon_32x32@2x.png" \
    "128 icon_128x128.png" \
    "256 icon_128x128@2x.png" \
    "256 icon_256x256.png" \
    "512 icon_256x256@2x.png" \
    "512 icon_512x512.png" \
    "1024 icon_512x512@2x.png"; do
    read -r px name <<<"$spec"
    # 824/1024 of the canvas, matching APP_CONTENT/APP_CANVAS.
    content=$APP_CONTENT_PER_MILLE
    rounded_square "$TMP/mark-full.png" "$px" "$content" "$iconset/$name"
done
iconutil --convert icns --output "$ICONSET_OUT" "$iconset"
echo "  packaging/macos/AppIcon.icns (16..1024, @2x included)"

echo "== GUI app icon =="
mkdir -p "$(dirname "$GUI_ICON")"
rounded_square "$TMP/mark-full.png" "$GUI_SIZE" \
    "$APP_CONTENT_PER_MILLE" "$GUI_ICON"
echo "  crates/friendlypass-gui/assets/app-icon.png (${GUI_SIZE}x${GUI_SIZE})"

echo "== extension icons =="
mkdir -p "$EXT_ICONS"
# 16/32 use the tighter shield-face crop; 48/128 use the full mark.
rounded_square "$TMP/mark-tight.png" 16 "$EXT_CONTENT" "$EXT_ICONS/icon-16.png"
rounded_square "$TMP/mark-tight.png" 32 "$EXT_CONTENT" "$EXT_ICONS/icon-32.png"
rounded_square "$TMP/mark-full.png" 48 "$EXT_CONTENT" "$EXT_ICONS/icon-48.png"
rounded_square "$TMP/mark-full.png" 128 "$EXT_CONTENT" "$EXT_ICONS/icon-128.png"
echo "  extension/src/icons/icon-{16,32,48,128}.png"

if [[ -d "$ROOT/android" ]]; then
    echo "== Android launcher icon =="
    # Adaptive icon (API 26+; minSdk 30 only needs the adaptive form): the artwork
    # supplies a colour background layer and the mark is a foreground PNG on a
    # 108 dp canvas. The visible safe zone is the middle 72/108 dp, so the mark
    # is drawn at 70% of the canvas with the same 22.4% corner radius as the
    # desktop icon. Sizes: mdpi..xxxhdpi = 108/162/216/324/432 px.
    ANDROID_RES="$ROOT/android/app/src/main/res"
    for spec in \
        "mdpi 108" \
        "hdpi 162" \
        "xhdpi 216" \
        "xxhdpi 324" \
        "xxxhdpi 432"; do
        read -r density px <<<"$spec"
        mkdir -p "$ANDROID_RES/mipmap-$density"
        rounded_square "$TMP/mark-full.png" "$px" 700 \
            "$ANDROID_RES/mipmap-$density/ic_launcher_foreground.png"
    done
    # Background colour sampled from the artwork (res/values/colors.xml).
    echo "  android/app/src/main/res/mipmap-{mdpi,hdpi,xhdpi,xxhdpi,xxxhdpi}/ic_launcher_foreground.png"
fi

echo "== previews =="
mkdir -p "$PREVIEW_DIR"
cp "$EXT_ICONS/icon-128.png" "$PREVIEW_DIR/logo-extension-128.png"
# Nearest-neighbour 8x so pixel edges are visible; on a light backdrop so the
# transparent rounded corners are visible too.
magick "$EXT_ICONS/icon-16.png" -filter point -resize 128x128 \
    -background '#f2f2f2' -alpha remove -alpha off \
    -strip -define png:compression-level=9 -define png:compression-filter=5 \
    "$PREVIEW_DIR/logo-extension-16-8x.png"
cp "$GUI_ICON" "$PREVIEW_DIR/logo-app-512.png"
echo "  $PREVIEW_DIR/logo-{extension-128,extension-16-8x,app-512}.png"

echo "done."
