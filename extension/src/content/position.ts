/**
 * Anchored menu positioning (WP6b).
 *
 * Pure geometry so the flip-above / viewport-clamp behaviour can be unit
 * tested in Chromium (and in Node for the arithmetic). `InlineMenu` measures
 * the field and the menu, then applies the result verbatim.
 */

export interface RectLike {
  top: number;
  left: number;
  right: number;
  bottom: number;
  width: number;
  height: number;
}

export interface SizeLike {
  width: number;
  height: number;
}

export interface MenuPositionOptions {
  /** Space between the field and the menu. */
  gap?: number;
  /** Minimum distance from every viewport edge. */
  margin?: number;
  /** Floor for the menu width. */
  minWidth?: number;
  /** Preferred/ceiling menu height. */
  preferredHeight?: number;
  /** Ceiling for the menu width. */
  maxWidth?: number;
}

export interface MenuPosition {
  top: number;
  left: number;
  width: number;
  maxHeight: number;
  placement: "above" | "below";
}

const DEFAULTS = {
  gap: 4,
  margin: 8,
  minWidth: 240,
  preferredHeight: 320,
  maxWidth: 420,
} as const;

function clamp(value: number, min: number, max: number): number {
  if (max < min) {
    return min;
  }
  return Math.min(Math.max(value, min), max);
}

/**
 * Place a menu relative to `anchor`.
 *
 * The menu opens below the field and flips above when it would cross the
 * viewport bottom (and there is more room above). Its height is capped to the
 * available space; its width follows the menu/field but never the viewport.
 */
export function computeMenuPosition(
  anchor: RectLike,
  menu: SizeLike,
  viewport: SizeLike,
  options: MenuPositionOptions = {},
): MenuPosition {
  const gap = options.gap ?? DEFAULTS.gap;
  const margin = options.margin ?? DEFAULTS.margin;
  const minWidth = options.minWidth ?? DEFAULTS.minWidth;
  const preferredHeight = options.preferredHeight ?? DEFAULTS.preferredHeight;
  const maxWidth = options.maxWidth ?? DEFAULTS.maxWidth;

  const spaceBelow = viewport.height - anchor.bottom - gap - margin;
  const spaceAbove = anchor.top - gap - margin;

  const wantedHeight = Math.min(
    Math.max(menu.height, 1),
    preferredHeight,
  );
  const flip = spaceBelow < Math.min(wantedHeight, 120) && spaceAbove > spaceBelow;

  const available = Math.max(0, flip ? spaceAbove : spaceBelow);
  const maxHeight = Math.max(
    72,
    Math.min(preferredHeight, available),
  );

  const height = Math.min(wantedHeight, maxHeight);
  const top =
    flip || spaceBelow < height
      ? Math.max(margin, anchor.top - gap - height)
      : anchor.bottom + gap;

  const widthCeiling = Math.max(minWidth, Math.min(maxWidth, viewport.width - margin * 2));
  const width = clamp(
    Math.max(menu.width, anchor.width, minWidth),
    Math.min(minWidth, widthCeiling),
    widthCeiling,
  );
  const left = clamp(
    anchor.left,
    margin,
    Math.max(margin, viewport.width - width - margin),
  );

  return {
    top: Math.round(top),
    left: Math.round(left),
    width: Math.round(width),
    maxHeight: Math.round(maxHeight),
    placement: flip || spaceBelow < height ? "above" : "below",
  };
}
