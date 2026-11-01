export type ThemePref = 'system' | 'dark' | 'light';
const KEY = 'safepeek.theme';
export const THEMES: [ThemePref, string][] = [['system', 'Match Windows'], ['dark', 'Dark'], ['light', 'Light']];

/** Appearance is a per-device display preference; it is kept in the renderer's own storage and never affects analysis. Storage can be unavailable, so every access is guarded. */
export function loadTheme(): ThemePref {
  try { const v = window.localStorage.getItem(KEY); return v === 'dark' || v === 'light' || v === 'system' ? v : 'system'; } catch { return 'system'; }
}
export function resolveTheme(p: ThemePref, prefersLight: boolean): 'dark' | 'light' { return p === 'system' ? (prefersLight ? 'light' : 'dark') : p; }
export function applyTheme(p: ThemePref = loadTheme()): void {
  const light = typeof window.matchMedia === 'function' && window.matchMedia('(prefers-color-scheme: light)').matches;
  document.documentElement.dataset.theme = resolveTheme(p, light);
}
export function saveTheme(p: ThemePref): void {
  try { window.localStorage.setItem(KEY, p); } catch { /* preference simply is not remembered */ }
  applyTheme(p);
}
