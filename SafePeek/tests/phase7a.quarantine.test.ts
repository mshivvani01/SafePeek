import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { QuarantineService, safeMove, sha256File } from '../electron/protection/quarantineService';
import { rm, tmp } from './helpers/phase6';

const dirs: string[] = []; afterEach(() => { dirs.splice(0).forEach(rm); });
const mk = (move?: (a: string, b: string) => Promise<void>) => {
  const root = tmp('sp7q-'); dirs.push(root); const dl = path.join(root, 'Downloads'); fs.mkdirSync(dl); const logs: string[] = [];
  const q = new QuarantineService({ dir: path.join(root, 'quarantine', 'files'), log: (m) => logs.push(m), fallbackRestoreDir: dl, move });
  const put = (name: string, data: string | Buffer = 'payload ' + name) => { const p = path.join(dl, name); fs.writeFileSync(p, data); return p; };
  const input = (p: string, sha: string | null = null) => ({ fileId: 'file-' + path.basename(p), path: p, sha256: sha, detectedType: 'Windows executable', status: 'HIGH_RISK' as const, score: 77, reason: 'test', automatic: false });
  return { root, dl, q, put, input, logs, vault: path.join(root, 'quarantine', 'files'), meta: path.join(root, 'quarantine', 'quarantine.json') };
};

describe('Phase 7A quarantine', () => {
  it('moves the file physically, verifies the hash and persists metadata', async () => {
    const { q, put, input, vault, meta } = mk(); const p = put('a.exe', 'MZ abc'); const sha = await sha256File(p);
    const r = await q.quarantine(input(p, sha)); expect(r.ok).toBe(true);
    expect(fs.existsSync(p)).toBe(false); const item = (r as { value: { quarantinePath: string; sha256: string } }).value;
    expect(path.dirname(item.quarantinePath)).toBe(vault); expect(await sha256File(item.quarantinePath)).toBe(sha); expect(item.sha256).toBe(sha);
    expect(JSON.parse(fs.readFileSync(meta, 'utf8')).items).toHaveLength(1);
  });
  it('two files with the same name do not collide', async () => {
    const { q, put, input } = mk(); const a = put('same.exe', 'one'); expect((await q.quarantine(input(a))).ok).toBe(true); const b = put('same.exe', 'two'); expect((await q.quarantine(input(b))).ok).toBe(true);
    expect(new Set(q.list().map((x) => x.quarantinePath)).size).toBe(2);
  });
  it('a missing file fails cleanly and records nothing', async () => {
    const { q, dl, input } = mk(); const r = await q.quarantine(input(path.join(dl, 'nope.exe'))); expect(r).toMatchObject({ ok: false, code: 'SOURCE_MISSING' }); expect(q.list()).toHaveLength(0);
  });
  it('a failed move (locked / permission denied) is not reported as success and leaves the file in place', async () => {
    const { q, put, input, logs } = mk(async () => { throw Object.assign(new Error('EBUSY: resource busy or locked'), { code: 'EBUSY' }); }); const p = put('locked.exe');
    const r = await q.quarantine(input(p)); expect(r).toMatchObject({ ok: false, code: 'MOVE_FAILED' }); expect((r as { error: string }).error).toMatch(/in use|denied/i);
    expect(fs.existsSync(p)).toBe(true); expect(q.list()).toHaveLength(0); expect(logs.join('\n')).toMatch(/move failed/i);
  });
  it('a move that silently did nothing is caught by verification', async () => {
    const { q, put, input } = mk(async () => undefined); const p = put('ghost.exe'); const r = await q.quarantine(input(p));
    expect(r).toMatchObject({ ok: false, code: 'VERIFY_FAILED' }); expect(q.list()).toHaveLength(0);
  });
  it('refuses symlinks and directories', async () => {
    const { q, dl, put, input } = mk(); const real = put('real.txt'); const link = path.join(dl, 'link.txt');
    try { fs.symlinkSync(real, link); expect(await q.quarantine(input(link))).toMatchObject({ ok: false, code: 'SYMLINK' }); expect(fs.existsSync(real)).toBe(true); } catch (e) { if ((e as NodeJS.ErrnoException).code !== 'EPERM') throw e; }
    const d = path.join(dl, 'folder'); fs.mkdirSync(d); expect(await q.quarantine(input(d))).toMatchObject({ ok: false, code: 'NOT_A_FILE' });
  });
  it('refuses a path that reaches into the vault through a symlinked directory', async () => {
    const { q, put, input, root, vault, dl } = mk(); const p = put('x.exe'); await q.quarantine(input(p)); // creates the vault
    const inner = path.join(vault, fs.readdirSync(vault)[0]); const alias = path.join(root, 'alias');
    try { fs.symlinkSync(vault, alias, 'dir'); } catch (e) { if ((e as NodeJS.ErrnoException).code === 'EPERM') return; throw e; }
    expect(await q.quarantine(input(path.join(alias, path.basename(inner))))).toMatchObject({ ok: false }); expect(fs.existsSync(inner)).toBe(true); expect(dl).toBeTruthy();
  });
  it('rejects traversal and relative paths', async () => {
    const { q, input, dl } = mk(); for (const p of [dl + '/../../etc/passwd', dl + '/sub/../../x.exe', 'relative.exe', '']) expect(await q.quarantine(input(p))).toMatchObject({ ok: false, code: 'INVALID_PATH' });
  });
  it('a file that changed during the move is quarantined (safe direction), re-hashed and flagged', async () => {
    const { q, put, input } = mk(async (a, b) => { fs.appendFileSync(a, ' CHANGED'); await safeMove(a, b); }); const p = put('mut.exe', 'orig'); const sha0 = await sha256File(p);
    const r = await q.quarantine(input(p, sha0)); expect(r.ok).toBe(true); const it2 = (r as { value: { sha256: string; reason: string; quarantinePath: string } }).value;
    expect(it2.sha256).not.toBe(sha0); expect(it2.sha256).toBe(await sha256File(it2.quarantinePath)); expect(it2.reason).toMatch(/changed since it was analyzed/);
  });
  it('a file that changed since analysis is flagged in the quarantine record', async () => {
    const { q, put, input } = mk(); const p = put('old.exe', 'v1'); const stale = await sha256File(p); fs.writeFileSync(p, 'v2 different');
    const r = await q.quarantine(input(p, stale)); expect(r.ok).toBe(true); expect((r as { value: { reason: string } }).value.reason).toMatch(/changed/);
  });
});

describe('Phase 7A restore', () => {
  const quarantined = async (name = 'r.exe') => { const c = mk(); const p = c.put(name, 'MZ restore me'); const r = await c.q.quarantine(c.input(p)); return { ...c, p, item: (r as { value: { id: string; quarantinePath: string } }).value }; };
  it('requires confirmation for a risky file, then restores with a verified hash and never opens it', async () => {
    const { q, p, item } = await quarantined(); expect(await q.restore(item.id, { confirmed: false })).toMatchObject({ ok: false, code: 'CONFIRMATION_REQUIRED' });
    const r = await q.restore(item.id, { confirmed: true }); expect(r.ok).toBe(true); expect(fs.readFileSync(p, 'utf8')).toBe('MZ restore me'); expect(q.get(item.id)?.state).toBe('RESTORED'); expect(fs.existsSync(item.quarantinePath)).toBe(false);
  });
  it('never overwrites an existing file at the destination', async () => {
    const { q, p, item } = await quarantined(); fs.writeFileSync(p, 'someone else put a file here');
    const r = await q.restore(item.id, { confirmed: true }); expect(r.ok).toBe(true); expect(fs.readFileSync(p, 'utf8')).toBe('someone else put a file here'); expect((r as { value: { restoredPath: string } }).value.restoredPath).toMatch(/\(restored\)/);
  });
  it('detects a tampered quarantined file (hash mismatch) and does not restore it', async () => {
    const { q, item, p } = await quarantined(); fs.appendFileSync(item.quarantinePath, 'tamper'); expect(await q.restore(item.id, { confirmed: true })).toMatchObject({ ok: false, code: 'INTEGRITY_MISMATCH' }); expect(fs.existsSync(p)).toBe(false); expect(q.get(item.id)?.state).toBe('QUARANTINED');
  });
  it('a missing quarantined file is reported, not crashed on', async () => { const { q, item } = await quarantined(); fs.rmSync(item.quarantinePath); expect(await q.restore(item.id, { confirmed: true })).toMatchObject({ ok: false, code: 'QUARANTINE_FILE_MISSING' }); });
  it('offers the fallback folder when the original folder is gone, and only uses it when asked', async () => {
    const { q, item, dl, root } = await quarantined(); fs.rmSync(dl, { recursive: true, force: true });
    expect(await q.restore(item.id, { confirmed: true })).toMatchObject({ ok: false, code: 'ORIGINAL_FOLDER_MISSING' }); fs.mkdirSync(dl);
    const r = await q.restore(item.id, { confirmed: true, useFallbackFolder: true }); expect(r.ok).toBe(true); expect(path.dirname((r as { value: { restoredPath: string } }).value.restoredPath)).toBe(dl); expect(root).toBeTruthy();
  });
  it('refuses a restore whose destination is inside the quarantine folder (tampered metadata)', async () => {
    const { item, meta, root } = await quarantined(); const j = JSON.parse(fs.readFileSync(meta, 'utf8')); j.items[0].originalPath = path.join(root, 'quarantine', 'files', 'planted.exe'); fs.writeFileSync(meta, JSON.stringify(j));
    const q2 = new QuarantineService({ dir: path.join(root, 'quarantine', 'files'), log: () => undefined }); const r = await q2.restore(item.id, { confirmed: true }); expect(r).toMatchObject({ ok: false, code: 'UNSAFE_DESTINATION' });
  });
  it('a move failure on restore leaves the file in quarantine', async () => {
    const root = tmp('sp7q-'); dirs.push(root); const dl = path.join(root, 'D'); fs.mkdirSync(dl); let fail = false;
    const q = new QuarantineService({ dir: path.join(root, 'quarantine', 'files'), log: () => undefined, move: async (a, b) => { if (fail) throw Object.assign(new Error('EPERM'), { code: 'EPERM' }); await safeMove(a, b); } });
    const p = path.join(dl, 'a.exe'); fs.writeFileSync(p, 'x'); const r = await q.quarantine({ fileId: 'f-aaaaaaaa', path: p, sha256: null, detectedType: 'x', status: 'HIGH_RISK', score: 70, reason: 't', automatic: false });
    fail = true; const id = (r as { value: { id: string } }).value.id; expect(await q.restore(id, { confirmed: true })).toMatchObject({ ok: false, code: 'MOVE_FAILED' }); expect(q.get(id)?.state).toBe('QUARANTINED');
  });
});

describe('Phase 7A permanent delete', () => {
  it('requires explicit confirmation and deletes only the vault copy', async () => {
    const c = mk(); const keep = c.put('keep.txt'); const p = c.put('del.exe'); const r = await c.q.quarantine(c.input(p)); const it2 = (r as { value: { id: string; quarantinePath: string } }).value;
    expect(await c.q.remove(it2.id, { confirmed: false })).toMatchObject({ code: 'CONFIRMATION_REQUIRED' }); expect(fs.existsSync(it2.quarantinePath)).toBe(true);
    expect((await c.q.remove(it2.id, { confirmed: true })).ok).toBe(true); expect(fs.existsSync(it2.quarantinePath)).toBe(false); expect(fs.existsSync(keep)).toBe(true); expect(c.q.get(it2.id)?.state).toBe('DELETED');
    expect(await c.q.remove(it2.id, { confirmed: true })).toMatchObject({ code: 'NOT_QUARANTINED' }); // not twice
  });
  it('tampered metadata pointing outside the vault is refused and nothing outside is deleted', async () => {
    const c = mk(); const victim = c.put('victim.quarantine', 'precious'); const p = c.put('x.exe'); const r = await c.q.quarantine(c.input(p)); const id = (r as { value: { id: string } }).value.id;
    const j = JSON.parse(fs.readFileSync(c.meta, 'utf8')); j.items[0].quarantinePath = victim; fs.writeFileSync(c.meta, JSON.stringify(j));
    const q2 = new QuarantineService({ dir: c.vault, log: () => undefined }); expect(await q2.remove(id, { confirmed: true })).toMatchObject({ ok: false, code: 'UNSAFE_SOURCE' }); expect(fs.readFileSync(victim, 'utf8')).toBe('precious');
    const j2 = JSON.parse(fs.readFileSync(c.meta, 'utf8')); j2.items[0].quarantinePath = path.join(c.vault, '..', 'quarantine.json') ; fs.writeFileSync(c.meta, JSON.stringify(j2));
    const q3 = new QuarantineService({ dir: c.vault, log: () => undefined }); expect(await q3.remove(id, { confirmed: true })).toMatchObject({ ok: false }); expect(fs.existsSync(c.meta)).toBe(true);
  });
  it('an already-missing vault file is handled and metadata updated', async () => {
    const c = mk(); const r = await c.q.quarantine(c.input(c.put('m.exe'))); const it2 = (r as { value: { id: string; quarantinePath: string } }).value; fs.rmSync(it2.quarantinePath);
    expect((await c.q.remove(it2.id, { confirmed: true })).ok).toBe(true); expect(c.q.get(it2.id)?.state).toBe('DELETED');
  });
});

describe('Phase 7A quarantine metadata resilience', () => {
  it('malformed items are dropped, valid ones kept, the app does not crash', async () => {
    const c = mk(); const r = await c.q.quarantine(c.input(c.put('ok.exe'))); expect(r.ok).toBe(true);
    const j = JSON.parse(fs.readFileSync(c.meta, 'utf8')); j.items.push(null, 7, {}, { id: 1 }, { id: 'x', state: 'WEIRD' }); fs.writeFileSync(c.meta, JSON.stringify(j));
    const q2 = new QuarantineService({ dir: c.vault, log: () => undefined }); expect(q2.list()).toHaveLength(1); expect(q2.activeCount()).toBe(1);
  });
  it('a corrupt metadata file is set aside and the service starts empty', () => {
    const c = mk(); fs.mkdirSync(path.dirname(c.meta), { recursive: true }); fs.writeFileSync(c.meta, '{ not json'); const q2 = new QuarantineService({ dir: c.vault, log: () => undefined });
    expect(q2.list()).toEqual([]); expect(fs.readdirSync(path.dirname(c.meta)).some((n) => n.includes('.corrupt-'))).toBe(true);
  });
  it('the quarantine folder being a symlink is refused', async () => {
    const root = tmp('sp7q-'); dirs.push(root); const real = path.join(root, 'real'); fs.mkdirSync(real); fs.mkdirSync(path.join(root, 'quarantine'));
    try { fs.symlinkSync(real, path.join(root, 'quarantine', 'files'), 'dir'); } catch (e) { if ((e as NodeJS.ErrnoException).code === 'EPERM') return; throw e; }
    const q = new QuarantineService({ dir: path.join(root, 'quarantine', 'files'), log: () => undefined }); const p = path.join(root, 'a.exe'); fs.writeFileSync(p, 'x');
    expect(await q.quarantine({ fileId: 'f-aaaaaaaa', path: p, sha256: null, detectedType: 'x', status: 'HIGH_RISK', score: 70, reason: 't', automatic: false })).toMatchObject({ ok: false, code: 'VAULT_UNAVAILABLE' }); expect(fs.existsSync(p)).toBe(true);
  });
});
