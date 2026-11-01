/** Pure input validation for IPC (no electron import, so it is unit-testable). Everything coming from the renderer is untrusted. */
export const ID_RE = /^[A-Za-z0-9-]{8,64}$/;
export const FOLDER_ID_RE = /^[A-Za-z0-9-]{1,64}$/; // folder ids are UUIDs, or the fixed id "downloads"

export const idOf = (v: unknown): string => { if (typeof v !== 'string' || !ID_RE.test(v)) throw new Error('Invalid id'); return v; };
export const folderIdOf = (v: unknown): string => { if (typeof v !== 'string' || !FOLDER_ID_RE.test(v)) throw new Error('Invalid folder id'); return v; };
/** Only a real boolean `true` confirms anything. "true", 1, {} etc. are rejected. */
export const confirmed = (v: unknown): boolean => v === true;
export const limitOf = (v: unknown, def = 500, max = 2000): number => (typeof v === 'number' && Number.isFinite(v) ? Math.max(1, Math.min(Math.floor(v), max)) : def);

export interface AppSettingsShape { startWithWindows: boolean; minimizeToTray: boolean; notifications: boolean; downloadsFolder: string; customFolders: string[] }
const DEFAULT_APP_SETTINGS: AppSettingsShape = { startWithWindows: false, minimizeToTray: true, notifications: true, downloadsFolder: '', customFolders: [] };
/** Known keys only, wrong types fall back to defaults, strings are length-capped. Anything else is dropped. */
export function normalizeAppSettings(x: unknown): AppSettingsShape {
  if (typeof x !== 'object' || x === null || Array.isArray(x)) throw new Error('Invalid settings');
  const o = x as Record<string, unknown>; const d = DEFAULT_APP_SETTINGS;
  const str = (v: unknown) => (typeof v === 'string' && v.length <= 1024 && !v.includes('\0') ? v : '');
  return {
    startWithWindows: typeof o.startWithWindows === 'boolean' ? o.startWithWindows : d.startWithWindows,
    minimizeToTray: typeof o.minimizeToTray === 'boolean' ? o.minimizeToTray : d.minimizeToTray,
    notifications: typeof o.notifications === 'boolean' ? o.notifications : d.notifications,
    downloadsFolder: str(o.downloadsFolder),
    customFolders: Array.isArray(o.customFolders) ? o.customFolders.slice(0, 50).map(str).filter(Boolean) : []
  };
}

/** Only SafePeek's own UI may call the IPC handlers: the bundled file:// page, or the Vite dev server in development. */
export function isTrustedUrl(url: string, dev: boolean): boolean {
  if (dev && (url === 'http://localhost:5173' || url.startsWith('http://localhost:5173/'))) return true;
  return /^file:\/\/\/.*\/dist\/index\.html(?:[?#].*)?$/i.test(url.replace(/\\/g, '/'));
}
