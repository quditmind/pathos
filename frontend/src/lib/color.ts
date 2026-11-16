// Colour helpers for user-chosen hex colours (tags, assets, classifications):
// derive tinted backgrounds and text colours with WCAG AA contrast in both
// themes.

export type Rgb = [number, number, number];

export const HEX_RE = /^#[0-9a-f]{6}$/i;

export function isHexColor(v: string | null | undefined): v is `#${string}` {
  return !!v && HEX_RE.test(v);
}

export function hexToRgb(hex: string): Rgb {
  const n = parseInt(hex.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

export function rgbToHex([r, g, b]: Rgb): string {
  return `#${[r, g, b].map((v) => Math.round(Math.max(0, Math.min(255, v))).toString(16).padStart(2, "0")).join("")}`;
}

function channel(c: number) {
  const s = c / 255;
  return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
}

export function luminance(rgb: Rgb): number {
  return 0.2126 * channel(rgb[0]) + 0.7152 * channel(rgb[1]) + 0.0722 * channel(rgb[2]);
}

export function contrastRatio(a: Rgb, b: Rgb): number {
  const [l1, l2] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (l1 + 0.05) / (l2 + 0.05);
}

/** Linear mix: t=0 → a, t=1 → b. */
export function mix(a: Rgb, b: Rgb, t: number): Rgb {
  return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];
}

/** Theme surfaces (keep in sync with index.css --surface). */
export const SURFACE_LIGHT: Rgb = [255, 255, 255];
export const SURFACE_DARK: Rgb = [0x15, 0x1b, 0x23];
/** Alpha of the tinted chip background. */
export const TINT = 0.14;

/**
 * Moves the colour towards black (light theme) or white (dark theme) until it
 * reaches `min` contrast against `bg`.
 */
export function readableOn(color: Rgb, bg: Rgb, dark: boolean, min = 4.5): Rgb {
  const target: Rgb = dark ? [255, 255, 255] : [0, 0, 0];
  for (let t = 0; t <= 1.0001; t += 0.05) {
    // Round first: the result is serialised as hex.
    const c = mix(color, target, t).map(Math.round) as Rgb;
    if (contrastRatio(c, bg) >= min) return c;
  }
  return target;
}

/** Style values for a chip in a user colour: background tint, ring and readable text per theme. */
export function chipColors(hex: string) {
  const c = hexToRgb(hex);
  const bgLight = mix(SURFACE_LIGHT, c, TINT);
  const bgDark = mix(SURFACE_DARK, c, TINT);
  return {
    background: `rgba(${c[0]}, ${c[1]}, ${c[2]}, ${TINT})`,
    ring: `rgba(${c[0]}, ${c[1]}, ${c[2]}, 0.35)`,
    fgLight: rgbToHex(readableOn(c, bgLight, false)),
    fgDark: rgbToHex(readableOn(c, bgDark, true)),
    bgLight: rgbToHex(bgLight),
    bgDark: rgbToHex(bgDark),
  };
}
