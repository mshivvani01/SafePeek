import path from 'node:path';

/** Extensible list of incomplete-download extensions. Add new ones here only. */
export const TEMP_EXTENSIONS = ['.crdownload', '.tmp', '.part', '.partial', '.download', '.opdownload'];
/** Filenames that are never real user files (Office lock files, OS metadata). */
export const IGNORED_NAME_PATTERNS: RegExp[] = [/^~\$/, /^\.~lock\./, /^desktop\.ini$/i, /^thumbs\.db$/i];

export interface StabilityOptions { intervalMs: number; requiredStableChecks: number; timeoutMs: number }
export const DEFAULT_STABILITY: StabilityOptions = { intervalMs: 1000, requiredStableChecks: 2, timeoutMs: 10 * 60_000 };

export const MAX_STORED_FILES = 2000;
export const MAX_STORED_EVENTS = 500;

export function isTemporaryFile(filePath: string): boolean {
  const base = path.basename(filePath);
  return TEMP_EXTENSIONS.includes(path.extname(base).toLowerCase()) || IGNORED_NAME_PATTERNS.some((r) => r.test(base));
}
