import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { isUncPath, validatePath } from '../electron/agent/paths';
import { folderIdOf, idOf, isTrustedUrl, limitOf, normalizeAppSettings } from '../electron/ipc/validate';
import { resolveInside, sanitizeFileName } from '../electron/protection/quarantineService';
import { decideOpen } from '../electron/protection/openSafety';

describe('Phase 7A path validation', () => {
  const bad: [string, string][] = [
    ['relative path', 'Downloads/x.exe'], ['dot-dot', '/home/u/../../etc/passwd'], ['windows dot-dot', 'C:\\Users\\u\\..\\..\\Windows\\x'], ['NUL byte', '/tmp/a\0b'],
    ['empty', ''], ['too long', '/' + 'a'.repeat(1100)], ['Win32 device namespace', '\\\\?\\C:\\Windows\\System32\\x'], ['Win32 device (dot)', '\\\\.\\PhysicalDrive0'], ['NTFS alternate data stream', 'C:\\Users\\u\\a.txt:evil.exe']
  ];
  for (const [name, p] of bad) it(`rejects ${name}`, () => expect(() => validatePath(p)).toThrow());
  it('rejects non-strings', () => { for (const v of [null, undefined, 5, {}, ['/tmp/a']]) expect(() => validatePath(v)).toThrow(); });
  it('accepts a normal absolute path and normalizes it', () => { const p = path.resolve('/tmp/x/./y.txt'); expect(validatePath(p)).toBe(path.normalize(p)); });
  it('recognizes UNC paths (refused for newly monitored folders) but not device paths as UNC', () => { expect(isUncPath('\\\\server\\share\\f')).toBe(true); expect(isUncPath('\\\\?\\C:\\x')).toBe(false); expect(isUncPath('C:\\x')).toBe(false); });
});

describe('Phase 7A malicious file names', () => {
  const hostile = ['..\\..\\evil.exe', '../../etc/passwd', 'a/b/c.exe', 'CON', 'nul.txt', 'COM1.pdf', 'file\u202Efdp.exe', 'x:y.exe', '   ', '...', '', 'a'.repeat(300) + '.exe', 'name\0.exe', '<>:"|?*.txt'];
  for (const n of hostile) it(`sanitizeFileName(${JSON.stringify(n.slice(0, 24))}) is a single safe segment`, () => {
    const s = sanitizeFileName(n);
    expect(s).toBeTruthy(); expect(s).toBe(path.basename(s)); expect(s).not.toMatch(/[\\/\0<>:"|?*\u202E]/); expect(s).not.toBe('..'); expect(s.length).toBeLessThanOrEqual(80);
    expect(/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i.test(s)).toBe(false);
  });
  it('resolveInside refuses anything that is not one plain segment', () => {
    const dir = path.resolve('/tmp/vault');
    for (const n of ['..', '.', '../x', 'a/b', 'a\\b', '', '/etc/passwd']) expect(() => resolveInside(dir, n)).toThrow();
    expect(resolveInside(dir, 'ok.quarantine')).toBe(path.join(dir, 'ok.quarantine'));
  });
});

describe('Phase 7A IPC input validation', () => {
  it('ids must match the strict id pattern', () => {
    for (const v of ['../x', 'a', '', 'x'.repeat(65), 'ok id 12345', 'id/12345678', null, 5, {}, ['abcdefgh']]) expect(() => idOf(v)).toThrow();
    expect(idOf('123e4567-e89b-12d3-a456-426614174000')).toBeTruthy();
  });
  it('folder ids accept the fixed "downloads" id and uuids only', () => { expect(folderIdOf('downloads')).toBe('downloads'); for (const v of ['../', 'a b', '', 7, null]) expect(() => folderIdOf(v)).toThrow(); });
  it('limit is clamped and non-numbers fall back', () => { expect(limitOf(NaN)).toBe(500); expect(limitOf('9')).toBe(500); expect(limitOf(-5)).toBe(1); expect(limitOf(1e9)).toBe(2000); expect(limitOf(25.9)).toBe(25); });
  it('app settings keep known keys only and coerce wrong types', () => {
    const s = normalizeAppSettings({ notifications: 'yes', minimizeToTray: false, evil: { __proto__: 1 }, downloadsFolder: 5, customFolders: ['C:\\a', 3, 'x\0y', 'D:\\b'] });
    expect(s).toEqual({ startWithWindows: false, minimizeToTray: false, notifications: true, downloadsFolder: '', customFolders: ['C:\\a', 'D:\\b'] });
    for (const v of [null, 'x', 5, [1]]) expect(() => normalizeAppSettings(v)).toThrow();
  });
  it('only SafePeek\'s own page is a trusted IPC sender', () => {
    expect(isTrustedUrl('file:///C:/Program%20Files/SafePeek/resources/app/dist/index.html', false)).toBe(true);
    expect(isTrustedUrl('file:///home/u/app/dist/index.html#/files', false)).toBe(true);
    expect(isTrustedUrl('http://localhost:5173/', false)).toBe(false); // dev server only in development
    expect(isTrustedUrl('http://localhost:5173/', true)).toBe(true);
    for (const u of ['https://evil.example/', 'file:///C:/Users/u/Downloads/evil.html', 'http://localhost:5174/', 'about:blank', 'data:text/html,x', 'http://localhost:5173.evil.com/']) expect(isTrustedUrl(u, true)).toBe(false);
  });
});

describe('Phase 7A open decision matrix', () => {
  const on = { requireConfirmHighRisk: true };
  const req = (st: Parameters<typeof decideOpen>[0], o = {}, s = on) => decideOpen(st, false, s, o).requiresConfirmation;
  it('SAFE and LOW_RISK open normally', () => { expect(req('SAFE')).toBe(false); expect(req('LOW_RISK')).toBe(false); });
  it('SUSPICIOUS, UNKNOWN and undefined need confirmation', () => { expect(req('SUSPICIOUS')).toBe(true); expect(req('UNKNOWN')).toBe(true); expect(req(undefined)).toBe(true); });
  it('HIGH_RISK needs confirmation (unless the user relaxed it); CRITICAL always does', () => { expect(req('HIGH_RISK')).toBe(true); expect(req('HIGH_RISK', {}, { requireConfirmHighRisk: false })).toBe(false); expect(req('CRITICAL', {}, { requireConfirmHighRisk: false })).toBe(true); });
  it('executables/scripts need confirmation even when SAFE', () => { expect(req('SAFE', { executable: true })).toBe(true); expect(req('LOW_RISK', { executable: true }, { requireConfirmHighRisk: false })).toBe(true); });
  it('a verdict is treated as UNKNOWN while the pipeline is still running', () => { const d = decideOpen('SAFE', false, on, { pipelineBusy: true }); expect(d.requiresConfirmation).toBe(true); expect(d.level).toBe('UNKNOWN'); });
  it('quarantined files can never be opened', () => { const d = decideOpen('SAFE', true, on); expect(d.allowed).toBe(false); });
});
