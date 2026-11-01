import { afterEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { QuarantineService, QUARANTINE_SUFFIX, resolveInside, safeMove, sanitizeFileName, sha256File } from '../electron/protection';
import type { QuarantineInput, QuarantinedFile } from '../electron/protection';
import { rm, tmp } from './helpers/phase6';

const dirs: string[] = []; const T = () => { const d = tmp('sp6q-'); dirs.push(d); return d; };
afterEach(() => { vi.restoreAllMocks(); dirs.splice(0).forEach(rm); });
const mk = (root: string, extra: Partial<ConstructorParameters<typeof QuarantineService>[0]> = {}) => {
  const dl = path.join(root, 'Downloads'); fs.mkdirSync(dl, { recursive: true });
  const q = new QuarantineService({ dir: path.join(root, 'q', 'files'), log: () => undefined, fallbackRestoreDir: dl, ...extra }); return { q, dl, vault: path.join(root, 'q', 'files') };
};
const input = (p: string, o: Partial<QuarantineInput> = {}): QuarantineInput => ({ fileId: 'f-' + path.basename(p), path: p, sha256: null, detectedType: 'Windows executable (PE)', status: 'HIGH_RISK', score: 82, reason: 'test', automatic: false, ...o });
const put = (dir: string, name: string, data = 'MZ-test-bytes') => { const p = path.join(dir, name); fs.writeFileSync(p, data); return p; };
const val = <T,>(r: { ok: boolean; value?: T; error?: string; code?: string }): T => { if (!r.ok) throw new Error(`${r.code}: ${r.error}`); return r.value!; };

describe('quarantine: physical move + metadata', () => {
  it('moves the real file into the vault, records metadata, and leaves nothing at the original path', async () => {
    const { q, dl, vault } = mk(T()); const p = put(dl, 'invoice.pdf.exe'); const sha = await sha256File(p);
    const item = val(await q.quarantine(input(p)));
    expect(fs.existsSync(p)).toBe(false); expect(fs.readFileSync(item.quarantinePath, 'utf8')).toBe('MZ-test-bytes');
    expect(path.dirname(item.quarantinePath)).toBe(vault); expect(path.basename(item.quarantinePath)).toMatch(new RegExp(`^${sha.slice(0, 16)}_[0-9a-f]{8}_invoice\\.pdf\\.exe\\${QUARANTINE_SUFFIX}$`));
    expect(item).toMatchObject({ originalPath: p, originalName: 'invoice.pdf.exe', sha256: sha, size: 13, riskStatus: 'HIGH_RISK', riskScore: 82, detectedType: 'Windows executable (PE)', state: 'QUARANTINED', automatic: false, reason: 'test' });
    expect(new Date(item.quarantinedAt).getTime()).not.toBeNaN(); expect(q.activeCount()).toBe(1); expect(q.activeByFile(item.fileId)!.id).toBe(item.id);
  });
  it('the internal name has a non-launchable suffix, so the shell cannot associate it with a program', async () => {
    const { q, dl } = mk(T()); const item = val(await q.quarantine(input(put(dl, 'setup.exe')))); expect(item.quarantinePath.endsWith('.quarantine')).toBe(true); expect(path.extname(item.quarantinePath)).toBe('.quarantine');
  });
  it('metadata persists across restarts', async () => {
    const root = T(); const { q, dl } = mk(root); const item = val(await q.quarantine(input(put(dl, 'a.exe')))); await q.flush();
    const q2 = new QuarantineService({ dir: path.join(root, 'q', 'files'), log: () => undefined }); expect(q2.get(item.id)).toMatchObject({ originalName: 'a.exe', state: 'QUARANTINED' }); expect(q2.list()).toHaveLength(1);
  });
  it('same name + same content from different folders do not collide', async () => {
    const root = T(); const { q, dl } = mk(root); const d2 = path.join(root, 'Other'); fs.mkdirSync(d2);
    const a = val(await q.quarantine(input(put(dl, 'dup.exe', 'same')))); const b = val(await q.quarantine(input(put(d2, 'dup.exe', 'same'))));
    expect(a.quarantinePath).not.toBe(b.quarantinePath); expect(fs.existsSync(a.quarantinePath) && fs.existsSync(b.quarantinePath)).toBe(true); expect(q.activeCount()).toBe(2);
  });
  it('missing original path: fails cleanly, records nothing', async () => {
    const { q, dl } = mk(T()); const r = await q.quarantine(input(path.join(dl, 'gone.exe'))); expect(r).toMatchObject({ ok: false, code: 'SOURCE_MISSING' }); expect(q.list()).toHaveLength(0);
  });
  it.each([['relative path', 'downloads/a.exe'], ['traversal', '/tmp/x/../../etc/passwd'], ['NUL byte', '/tmp/a\0.exe'], ['empty', ''], ['too long', '/' + 'a'.repeat(2000)]])('invalid path (%s) is rejected before touching the disk', async (_n, p) => {
    const { q } = mk(T()); const r = await q.quarantine(input(p)); expect(r).toMatchObject({ ok: false, code: 'INVALID_PATH' }); expect(q.list()).toHaveLength(0);
  });
  it('refuses symbolic links (the link target is never moved) and directories', async () => {
    const root = T(); const { q, dl } = mk(root); const target = put(root, 'target.txt', 'precious'); const link = path.join(dl, 'link.exe'); fs.symlinkSync(target, link);
    expect(await q.quarantine(input(link))).toMatchObject({ ok: false, code: 'SYMLINK' }); expect(fs.readFileSync(target, 'utf8')).toBe('precious'); expect(fs.existsSync(link)).toBe(true);
    const sub = path.join(dl, 'folder.exe'); fs.mkdirSync(sub); expect(await q.quarantine(input(sub))).toMatchObject({ ok: false, code: 'NOT_A_FILE' });
  });
  it('refuses a quarantine folder that is a symlink (attack: redirect the vault) and files already inside the vault', async () => {
    const root = T(); const evil = path.join(root, 'evil-target'); fs.mkdirSync(evil); const vault = path.join(root, 'q', 'files'); fs.mkdirSync(path.dirname(vault)); fs.symlinkSync(evil, vault);
    const { q, dl } = mk(root); const p = put(dl, 'a.exe'); expect(await q.quarantine(input(p))).toMatchObject({ ok: false, code: 'VAULT_UNAVAILABLE' }); expect(fs.existsSync(p)).toBe(true); expect(fs.readdirSync(evil)).toHaveLength(0);
    const root2 = T(); const m = mk(root2); val(await m.q.quarantine(input(put(m.dl, 'x.exe')))); const inside = fs.readdirSync(m.vault)[0]; expect(await m.q.quarantine(input(path.join(m.vault, inside)))).toMatchObject({ ok: false, code: 'ALREADY_IN_QUARANTINE' });
  });
  it('failed move: reports failure, records nothing, source untouched', async () => {
    const { q, dl } = mk(T(), { move: async () => { throw Object.assign(new Error('locked'), { code: 'EBUSY' }); } }); const p = put(dl, 'busy.exe');
    const r = await q.quarantine(input(p)); expect(r).toMatchObject({ ok: false, code: 'MOVE_FAILED' }); expect((r as { error: string }).error).toMatch(/in use/i); expect(fs.existsSync(p)).toBe(true); expect(q.list()).toHaveLength(0);
  });
  it('a move that "succeeds" without producing a verified file is not reported as quarantined', async () => {
    const { q, dl } = mk(T(), { move: async () => undefined }); const r = await q.quarantine(input(put(dl, 'ghost.exe'))); expect(r).toMatchObject({ ok: false, code: 'VERIFY_FAILED' }); expect(q.list()).toHaveLength(0);
  });
  it('simultaneous quarantine requests for one file produce exactly one entry', async () => {
    const { q, dl } = mk(T()); const p = put(dl, 'race.exe'); const [a, b] = await Promise.all([q.quarantine(input(p)), q.quarantine(input(p))]);
    expect([a.ok, b.ok].sort()).toEqual([false, true]); expect(q.list()).toHaveLength(1);
  });
});

describe('moving across drives (EXDEV)', () => {
  it('falls back to copy + verify + delete and leaves no source', async () => {
    const root = T(); const src = put(root, 's.bin', 'payload'); const dst = path.join(root, 'd.bin'); const real = fs.promises.rename;
    vi.spyOn(fs.promises, 'rename').mockImplementationOnce(async () => { throw Object.assign(new Error('x'), { code: 'EXDEV' }); }).mockImplementation(real);
    await safeMove(src, dst); expect(fs.existsSync(src)).toBe(false); expect(fs.readFileSync(dst, 'utf8')).toBe('payload');
  });
  it('if the source cannot be removed after copying, the copy is rolled back and an error is thrown', async () => {
    const root = T(); const src = put(root, 's.bin', 'payload'); const dst = path.join(root, 'd.bin');
    vi.spyOn(fs.promises, 'rename').mockRejectedValue(Object.assign(new Error('x'), { code: 'EXDEV' })); vi.spyOn(fs.promises, 'unlink').mockRejectedValueOnce(Object.assign(new Error('denied'), { code: 'EPERM' }));
    await expect(safeMove(src, dst)).rejects.toThrow(/denied/); expect(fs.existsSync(src)).toBe(true); expect(fs.existsSync(dst)).toBe(false);
  });
  it('never overwrites an existing destination', async () => {
    const root = T(); const src = put(root, 's.bin', 'new'); const dst = put(root, 'd.bin', 'old'); await expect(safeMove(src, dst)).rejects.toThrow(/exists/); expect(fs.readFileSync(dst, 'utf8')).toBe('old'); expect(fs.existsSync(src)).toBe(true);
  });
});

describe('file name sanitization and path containment', () => {
  it.each([
    ['../../evil.exe', 'evil.exe'], ['..\\..\\evil.exe', 'evil.exe'], ['C:\\Windows\\System32\\cmd.exe', 'cmd.exe'], ['/etc/passwd', 'passwd'], ['a<b>c:d"e|f?g*.txt', 'a_b_c_d_e_f_g_.txt'],
    ['invoice\u202Egnp.exe', 'invoicegnp.exe'], ['ctrl\u0001\u0000name.txt', 'ctrlname.txt'], ['...', '_file'], ['..', '_file'], ['', '_file'], ['CON', '_CON'], ['nul.txt', '_nul.txt'], ['  trailing. ', 'trailing']
  ])('sanitizes %j', (input, expected) => { expect(sanitizeFileName(input)).toBe(expected); });
  it('limits length while keeping the extension, and never yields a separator', () => { const n = sanitizeFileName('a'.repeat(300) + '.pdf'); expect(n.length).toBeLessThanOrEqual(80); expect(n.endsWith('.pdf')).toBe(true); for (const h of ['a/b', 'a\\b', '../x', '..\\x']) expect(sanitizeFileName(h)).not.toMatch(/[\\/]/); });
  it('resolveInside accepts one plain segment and rejects everything that could escape', () => {
    const d = path.resolve(tmp()); dirs.push(d); expect(resolveInside(d, 'ok.quarantine')).toBe(path.join(d, 'ok.quarantine'));
    for (const bad of ['../x', '..', '.', '', 'a/b', 'a\\b', '/abs/path', '..\\x', 'x/../y']) expect(() => resolveInside(d, bad), bad).toThrow();
  });
  it('a hostile original name from a stored record cannot choose the vault location', async () => {
    const root = T(); const { q, dl, vault } = mk(root); const p = put(dl, '..%2F..%2Fevil.exe'); const item = val(await q.quarantine(input(p)));
    expect(path.dirname(item.quarantinePath)).toBe(vault); expect(fs.readdirSync(vault)).toHaveLength(1); expect(fs.existsSync(path.join(root, 'evil.exe'))).toBe(false);
  });
});

describe('restore', () => {
  const quarantined = async (root: string, name = 'invoice.pdf.exe', o: Partial<QuarantineInput> = {}) => { const m = mk(root); const p = put(m.dl, name); const item = val(await m.q.quarantine(input(p, o))); return { ...m, p, item }; };
  it('HIGH_RISK needs explicit confirmation; without it nothing moves', async () => {
    const { q, p, item } = await quarantined(T()); expect(await q.restore(item.id, { confirmed: false })).toMatchObject({ ok: false, code: 'CONFIRMATION_REQUIRED' }); expect(fs.existsSync(p)).toBe(false); expect(q.get(item.id)!.state).toBe('QUARANTINED');
    expect(await q.restore(item.id, {} as never)).toMatchObject({ ok: false, code: 'CONFIRMATION_REQUIRED' });
  });
  it('confirmed restore returns the file to its original path, updates metadata, and calls the re-analysis hook', async () => {
    const root = T(); const seen: QuarantinedFile[] = []; const m = mk(root, { onRestored: (x) => seen.push(x) }); const p = put(m.dl, 'a.exe'); const item = val(await m.q.quarantine(input(p)));
    const r = val(await m.q.restore(item.id, { confirmed: true })); expect(fs.readFileSync(p, 'utf8')).toBe('MZ-test-bytes'); expect(r.state).toBe('RESTORED'); expect(r.restoredPath).toBe(p); expect(r.restoredAt).toBeTruthy(); expect(fs.readdirSync(m.vault)).toHaveLength(0);
    expect(seen).toHaveLength(1); expect(m.q.wasRestored(item.sha256)).toBe(true); expect(m.q.activeCount()).toBe(0);
  });
  it('SAFE/LOW files can be restored without the extra confirmation', async () => { const { q, item } = await quarantined(T(), 'notes.txt', { status: 'SAFE', score: 0 }); expect((await q.restore(item.id, { confirmed: false })).ok).toBe(true); });
  it('restoring twice is rejected', async () => { const { q, item } = await quarantined(T()); await q.restore(item.id, { confirmed: true }); expect(await q.restore(item.id, { confirmed: true })).toMatchObject({ ok: false, code: 'NOT_QUARANTINED' }); });
  it('never overwrites a different file that now occupies the original path', async () => {
    const { q, p, item } = await quarantined(T()); fs.writeFileSync(p, 'someone else'); const r = val(await q.restore(item.id, { confirmed: true }));
    expect(fs.readFileSync(p, 'utf8')).toBe('someone else'); expect(path.basename(r.restoredPath!)).toBe('invoice.pdf (restored).exe'); expect(fs.readFileSync(r.restoredPath!, 'utf8')).toBe('MZ-test-bytes');
  });
  it('original folder missing: clear error, or restore to the Downloads fallback when the user chooses it', async () => {
    const root = T(); const m = mk(root); const sub = path.join(root, 'Gone'); fs.mkdirSync(sub); const p = put(sub, 'a.exe'); const item = val(await m.q.quarantine(input(p))); fs.rmSync(sub, { recursive: true });
    expect(await m.q.restore(item.id, { confirmed: true })).toMatchObject({ ok: false, code: 'ORIGINAL_FOLDER_MISSING' }); expect(m.q.get(item.id)!.state).toBe('QUARANTINED');
    const r = val(await m.q.restore(item.id, { confirmed: true, useFallbackFolder: true })); expect(path.dirname(r.restoredPath!)).toBe(m.dl);
  });
  it('a symlinked original folder is not trusted as a destination', async () => {
    const root = T(); const m = mk(root); const real = path.join(root, 'real'); fs.mkdirSync(real); const link = path.join(root, 'Link'); fs.symlinkSync(real, link); const p = put(real, 'a.exe'); const item = val(await m.q.quarantine(input(p)));
    m.q['store'].data.items[0].originalPath = path.join(link, 'a.exe'); expect(await m.q.restore(item.id, { confirmed: true })).toMatchObject({ ok: false, code: 'ORIGINAL_FOLDER_MISSING' });
  });
  it('tampered metadata cannot make restore move an arbitrary file out of the system', async () => {
    const root = T(); const { q, item } = await quarantined(root); const victim = put(root, 'victim.txt', 'do not touch'); q['store'].data.items[0].quarantinePath = victim;
    expect(await q.restore(item.id, { confirmed: true })).toMatchObject({ ok: false, code: 'UNSAFE_SOURCE' }); expect(fs.readFileSync(victim, 'utf8')).toBe('do not touch');
  });
  it('tampered original path (traversal) is rejected', async () => { const { q, item } = await quarantined(T()); q['store'].data.items[0].originalPath = '/tmp/../etc/cron.d/x'; expect(await q.restore(item.id, { confirmed: true })).toMatchObject({ ok: false, code: 'INVALID_PATH' }); });
  it('integrity: a modified quarantined file is not restored', async () => { const { q, item } = await quarantined(T()); fs.appendFileSync(item.quarantinePath, 'tamper'); expect(await q.restore(item.id, { confirmed: true })).toMatchObject({ ok: false, code: 'INTEGRITY_MISMATCH' }); });
  it('missing quarantined file is reported', async () => { const { q, item } = await quarantined(T()); fs.rmSync(item.quarantinePath); expect(await q.restore(item.id, { confirmed: true })).toMatchObject({ ok: false, code: 'QUARANTINE_FILE_MISSING' }); });
  it('failed restore move keeps the file quarantined', async () => {
    const root = T(); let fail = false; const m = mk(root, { move: async (a, b) => { if (fail) throw new Error('disk full'); return safeMove(a, b); } }); const item = val(await m.q.quarantine(input(put(m.dl, 'a.exe')))); fail = true;
    expect(await m.q.restore(item.id, { confirmed: true })).toMatchObject({ ok: false, code: 'MOVE_FAILED' }); expect(m.q.get(item.id)!.state).toBe('QUARANTINED'); expect(fs.existsSync(item.quarantinePath)).toBe(true);
  });
  it('unknown ids are reported', async () => { const { q } = mk(T()); expect(await q.restore('nope', { confirmed: true })).toMatchObject({ ok: false, code: 'NOT_FOUND' }); });
});

describe('permanent deletion', () => {
  it('requires confirmation; deletes only the quarantined copy; keeps the metadata record as DELETED', async () => {
    const root = T(); const m = mk(root); const other = put(m.dl, 'keep.txt', 'mine'); const item = val(await m.q.quarantine(input(put(m.dl, 'bad.exe')))); fs.writeFileSync(path.join(m.vault, 'unrelated.dat'), 'x');
    expect(await m.q.remove(item.id, { confirmed: false })).toMatchObject({ ok: false, code: 'CONFIRMATION_REQUIRED' }); expect(fs.existsSync(item.quarantinePath)).toBe(true);
    const r = val(await m.q.remove(item.id, { confirmed: true })); expect(r.state).toBe('DELETED'); expect(r.deletedAt).toBeTruthy(); expect(fs.existsSync(item.quarantinePath)).toBe(false);
    expect(fs.readFileSync(other, 'utf8')).toBe('mine'); expect(fs.existsSync(path.join(m.vault, 'unrelated.dat'))).toBe(true); expect(m.q.activeCount()).toBe(0); expect(await m.q.remove(item.id, { confirmed: true })).toMatchObject({ ok: false, code: 'NOT_QUARANTINED' });
  });
  it('tampered metadata cannot make delete remove a file outside the vault', async () => {
    const root = T(); const m = mk(root); const item = val(await m.q.quarantine(input(put(m.dl, 'bad.exe')))); const victim = put(root, 'victim.txt', 'safe'); m.q['store'].data.items[0].quarantinePath = victim;
    expect(await m.q.remove(item.id, { confirmed: true })).toMatchObject({ ok: false, code: 'UNSAFE_SOURCE' }); expect(fs.readFileSync(victim, 'utf8')).toBe('safe');
    m.q['store'].data.items[0].quarantinePath = path.join(m.vault, '..', 'victim.txt'); expect(await m.q.remove(item.id, { confirmed: true })).toMatchObject({ ok: false, code: 'UNSAFE_SOURCE' });
  });
  it('an already-missing quarantined file is not an error', async () => { const m = mk(T()); const item = val(await m.q.quarantine(input(put(m.dl, 'a.exe')))); fs.rmSync(item.quarantinePath); expect((await m.q.remove(item.id, { confirmed: true })).ok).toBe(true); });
});
