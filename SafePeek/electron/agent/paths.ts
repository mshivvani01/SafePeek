import path from 'node:path';

const DEVICE_PREFIX = /^[\\/]{2}[?.][\\/]/;      // \\?\C:\x  and  \\.\PhysicalDrive0 (Win32 device namespace)
const UNC_PREFIX = /^[\\/]{2}[^\\/?.]/;          // \\server\share
const DRIVE_PREFIX = /^[A-Za-z]:[\\/]/;

/** Absolute, no NUL bytes, no traversal segments, no Win32 device-namespace paths, no NTFS alternate data streams. Never touches the shell or executes anything. */
export function validatePath(p: unknown): string {
  if (typeof p !== 'string' || p.length === 0 || p.length > 1024 || p.includes('\0')) throw new Error('Invalid path');
  if (DEVICE_PREFIX.test(p)) throw new Error('Device paths are not allowed');
  const winAbs = DRIVE_PREFIX.test(p) || UNC_PREFIX.test(p);
  if (!path.isAbsolute(p) && !winAbs) throw new Error('Path must be absolute');
  if (!path.isAbsolute(p)) throw new Error('Path must be absolute on this platform');
  if (p.split(/[\\/]/).includes('..')) throw new Error('Path traversal rejected');
  if (DRIVE_PREFIX.test(p) && p.slice(2).includes(':')) throw new Error('Alternate data streams are not allowed');
  return path.normalize(p);
}
/** True for \\server\share style paths (network locations). Allowed for files SafePeek already tracks; refused for newly added monitored folders. */
export const isUncPath = (p: string): boolean => !DEVICE_PREFIX.test(p) && UNC_PREFIX.test(p);
/** Case-insensitive on Windows. Used for dedup keys. */
export const pathKey = (p: string) => (process.platform === 'win32' ? path.normalize(p).toLowerCase() : path.normalize(p));
export function isInside(parent: string, child: string): boolean {
  const rel = path.relative(parent, child);
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
}
export const isRootDir = (p: string) => path.parse(p).root === path.normalize(p);
