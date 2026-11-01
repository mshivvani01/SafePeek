import fs from 'node:fs';
import { describeFsError } from '../util/fsErrors';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { isInside, pathKey, validatePath } from '../agent/paths';
import type { ThreatStatus } from '../threat/types';
import { JsonStore } from './jsonStore';
import type { ActionResult, QuarantinedFile } from './types';

const BIDI = /[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g;
const RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;
export const QUARANTINE_SUFFIX = '.quarantine';

/** Reduces any name (including hostile ones like "..\\..\\x.exe" or "a/b") to a single safe path segment. Never returns '', '.', '..' or a Windows reserved device name. */
export function sanitizeFileName(name: string, max = 80): string {
  let n = String(name ?? '').split(/[\\/]/).pop() ?? '';
  n = n.replace(/[\u0000-\u001F\u007F]/g, '').replace(BIDI, '').replace(/[<>:"|?*]/g, '_').replace(/\.{2,}/g, '.').replace(/^[. ]+|[. ]+$/g, '');
  if (!n || RESERVED.test(n)) n = `_${n || 'file'}`;
  if (n.length > max) { const ext = path.extname(n).slice(0, 12); n = n.slice(0, max - ext.length) + ext; }
  return n;
}
/** Resolves `name` as ONE segment inside `dir`; throws if the result could be anywhere else. */
export function resolveInside(dir: string, name: string): string {
  if (!name || name !== path.basename(name) || /[\\/]/.test(name) || name === '.' || name === '..') throw new Error('Unsafe file name');
  const full = path.resolve(dir, name);
  if (path.dirname(full) !== path.resolve(dir) || !isInside(dir, full)) throw new Error('Path escapes the quarantine folder');
  return full;
}
export function sha256File(p: string): Promise<string> {
  return new Promise((resolve, reject) => { const h = createHash('sha256'); const s = fs.createReadStream(p); s.on('data', (c) => h.update(c)); s.on('error', reject); s.on('end', () => resolve(h.digest('hex'))); });
}

export type MoveFn = (src: string, dst: string) => Promise<void>;
/** rename when possible; copy + verify + delete across drives (EXDEV). Never overwrites an existing destination. If anything fails, the source is left intact and a partial copy is removed. */
export const safeMove: MoveFn = async (src, dst) => {
  try { await fs.promises.lstat(dst); throw Object.assign(new Error('Destination already exists'), { code: 'EEXIST' }); } catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e; }
  try { await fs.promises.rename(src, dst); return; } catch (e) { if ((e as NodeJS.ErrnoException).code !== 'EXDEV') throw e; }
  const size = (await fs.promises.stat(src)).size;
  await fs.promises.copyFile(src, dst, fs.constants.COPYFILE_EXCL);
  try {
    if ((await fs.promises.stat(dst)).size !== size) throw new Error('Copy verification failed');
    await fs.promises.unlink(src);
  } catch (e) { await fs.promises.unlink(dst).catch(() => undefined); throw e; }
};

export interface QuarantineInput { fileId: string; path: string; sha256: string | null; detectedType: string; status: ThreatStatus; score: number; reason: string; automatic: boolean }
export interface QuarantineDeps { dir: string; log(m: string): void; move?: MoveFn; fallbackRestoreDir?: string; now?: () => string; onRestored?(q: QuarantinedFile): void }
interface QFile { version: 1; items: QuarantinedFile[] }
const isQFile = (x: unknown): x is QFile => typeof x === 'object' && x !== null && (x as QFile).version === 1 && Array.isArray((x as QFile).items);
const STATES = ['QUARANTINED', 'RESTORED', 'DELETED'];
const isQItem = (q: unknown): q is QuarantinedFile => { const o = q as QuarantinedFile; return !!o && typeof o === 'object' && typeof o.id === 'string' && typeof o.fileId === 'string' && typeof o.quarantinePath === 'string' && typeof o.originalPath === 'string' && typeof o.originalName === 'string' && typeof o.sha256 === 'string' && typeof o.quarantinedAt === 'string' && STATES.includes(o.state); };
const needsConfirm = (s: ThreatStatus) => s === 'SUSPICIOUS' || s === 'HIGH_RISK' || s === 'CRITICAL';
const fail = (code: string, error: string): { ok: false; code: string; error: string } => ({ ok: false, code, error });
const errText = (e: unknown) => describeFsError(e);

/**
 * Real, local quarantine. The file is PHYSICALLY moved into SafePeek's own folder under an internal name (<sha256-prefix>_<id>_<sanitized-name>.quarantine); the renderer
 * only ever passes ids/confirmation flags, never paths. Metadata is written only after the move was verified. Quarantined files are never opened, previewed or executed.
 */
export class QuarantineService {
  private store: JsonStore<QFile>; private lock: Promise<unknown> = Promise.resolve();
  constructor(private deps: QuarantineDeps) {
    this.store = new JsonStore<QFile>(path.join(path.dirname(deps.dir), 'quarantine.json'), () => ({ version: 1, items: [] }), isQFile, deps.log);
    const n = this.store.data.items.length;
    this.store.data.items = this.store.data.items.filter(isQItem);
    if (this.store.data.items.length < n) deps.log(`[SafePeek] Ignored ${n - this.store.data.items.length} malformed quarantine record(s)`);
  }
  private now = () => (this.deps.now ?? (() => new Date().toISOString()))();
  private mv: MoveFn = (a, b) => (this.deps.move ?? safeMove)(a, b);
  private serial<T>(fn: () => Promise<T>): Promise<T> { const r = this.lock.then(fn, fn); this.lock = r.catch(() => undefined); return r; }

  list(): QuarantinedFile[] { return [...this.store.data.items].sort((a, b) => b.quarantinedAt.localeCompare(a.quarantinedAt)); }
  get(id: string): QuarantinedFile | undefined { return this.store.data.items.find((q) => q.id === id); }
  activeCount(): number { return this.store.data.items.filter((q) => q.state === 'QUARANTINED').length; }
  activeByFile(fileId: string): QuarantinedFile | undefined { return this.store.data.items.find((q) => q.fileId === fileId && q.state === 'QUARANTINED'); }
  wasRestored(sha256: string | null): boolean { return !!sha256 && this.store.data.items.some((q) => q.state === 'RESTORED' && q.sha256 === sha256); }
  /** True for the quarantine folder itself and anything inside it (used to keep it out of folder monitoring). */
  isQuarantinePath(p: string): boolean { try { const r = path.resolve(p); const d = path.resolve(this.deps.dir); return pathKey(r) === pathKey(d) || isInside(d, r); } catch { return false; } }
  flush() { return this.store.flush(); }

  /** Creates the folder if needed and refuses a quarantine folder that is a symlink/junction or not a directory. Returns its resolved path. */
  private async vault(): Promise<string> {
    await fs.promises.mkdir(this.deps.dir, { recursive: true });
    const st = await fs.promises.lstat(this.deps.dir);
    if (st.isSymbolicLink() || !st.isDirectory()) throw new Error('The quarantine folder is not a regular directory');
    return path.resolve(this.deps.dir);
  }
  /** Re-validates a quarantine path read from stored metadata (which is data, not trusted). */
  private async vaultFile(q: QuarantinedFile): Promise<string> {
    const dir = await this.vault(); const full = path.resolve(q.quarantinePath);
    if (pathKey(path.dirname(full)) !== pathKey(dir) || !isInside(dir, full) || !full.endsWith(QUARANTINE_SUFFIX)) throw new Error('Stored quarantine path is outside the quarantine folder');
    return full;
  }

  /** True when `p` (after resolving symlinks/junctions in its parents) lies inside the real quarantine folder. */
  private async insideVaultReal(p: string): Promise<boolean> {
    try { const vr = await fs.promises.realpath(this.deps.dir); const pr = await fs.promises.realpath(p); return pathKey(pr) === pathKey(vr) || isInside(vr, pr); } catch { return false; }
  }

  quarantine(input: QuarantineInput): Promise<ActionResult<QuarantinedFile>> { return this.serial(() => this.doQuarantine(input)); }
  private async doQuarantine(i: QuarantineInput): Promise<ActionResult<QuarantinedFile>> {
    let src: string;
    try { src = validatePath(i.path); } catch (e) { return fail('INVALID_PATH', (e as Error).message); }
    let dir: string; try { dir = await this.vault(); } catch (e) { return fail('VAULT_UNAVAILABLE', (e as Error).message); }
    if (isInside(dir, path.resolve(src))) return fail('ALREADY_IN_QUARANTINE', 'This file is already inside the quarantine folder.');
    let st: fs.Stats;
    try { st = await fs.promises.lstat(src); } catch (e) { return fail('SOURCE_MISSING', errText(e)); }
    if (st.isSymbolicLink()) return fail('SYMLINK', 'Refusing to quarantine a symbolic link.');
    if (!st.isFile()) return fail('NOT_A_FILE', 'Only regular files can be quarantined.');
    if (await this.insideVaultReal(src)) return fail('ALREADY_IN_QUARANTINE', 'This file is already inside the quarantine folder.');
    let sha: string; try { sha = await sha256File(src); } catch (e) { return fail('READ_FAILED', errText(e)); }
    const id = randomUUID(); const original = path.basename(src);
    const internal = `${sha.slice(0, 16)}_${id.slice(0, 8)}_${sanitizeFileName(original)}${QUARANTINE_SUFFIX}`;
    let dst: string; try { dst = resolveInside(dir, internal); } catch (e) { return fail('UNSAFE_DESTINATION', (e as Error).message); }
    try { await this.mv(src, dst); } catch (e) { this.deps.log(`[SafePeek] Quarantine move failed: ${(e as Error).message}`); return fail('MOVE_FAILED', `The file could not be moved to quarantine. ${errText(e)}`); }
    // Verify before claiming success or touching metadata: the file must exist in the vault as a regular file, and its SHA-256 is re-read from the vault copy.
    // If the file changed between the first hash and the move, the vault copy is the truth; it is quarantined (the safe direction) and flagged.
    let finalSha = sha; let finalSize = st.size; let changedBeforeMove = false;
    try {
      const d = await fs.promises.lstat(dst); if (!d.isFile() || d.isSymbolicLink()) throw new Error('not a regular file');
      finalSha = await sha256File(dst); finalSize = d.size; changedBeforeMove = finalSha !== sha;
    } catch { return fail('VERIFY_FAILED', 'The quarantined copy could not be verified; the file was not recorded as quarantined.'); }
    const analyzedMismatch = !!i.sha256 && i.sha256 !== finalSha;
    if (changedBeforeMove || analyzedMismatch) this.deps.log(`[SafePeek] Quarantined file differs from the analyzed version (${changedBeforeMove ? 'changed during the move' : 'changed since analysis'}); it stays in quarantine and should be rescanned after restore`);
    const item: QuarantinedFile = { id, fileId: i.fileId, originalPath: src, quarantinePath: dst, originalName: original, sha256: finalSha, size: finalSize, detectedType: i.detectedType, riskStatus: i.status, riskScore: i.score, quarantinedAt: this.now(), reason: i.reason + (changedBeforeMove || analyzedMismatch ? ' Note: the file had changed since it was analyzed.' : ''), automatic: i.automatic, state: 'QUARANTINED' };
    this.store.data.items.unshift(item); this.store.data.items = this.store.data.items.slice(0, 1000); this.store.save();
    return { ok: true, value: item, message: 'File moved to quarantine.' };
  }

  restore(id: string, o: { confirmed: boolean; useFallbackFolder?: boolean }): Promise<ActionResult<QuarantinedFile>> { return this.serial(() => this.doRestore(id, o)); }
  private async doRestore(id: string, o: { confirmed: boolean; useFallbackFolder?: boolean }): Promise<ActionResult<QuarantinedFile>> {
    const q = this.get(id); if (!q) return fail('NOT_FOUND', 'Quarantine entry not found.');
    if (q.state !== 'QUARANTINED') return fail('NOT_QUARANTINED', 'This file is no longer in quarantine.');
    if (needsConfirm(q.riskStatus) && o.confirmed !== true) return fail('CONFIRMATION_REQUIRED', 'This file was previously identified as a risk. Explicit confirmation is required to restore it.');
    let from: string; try { from = await this.vaultFile(q); } catch (e) { return fail('UNSAFE_SOURCE', (e as Error).message); }
    let st: fs.Stats; try { st = await fs.promises.lstat(from); } catch { return fail('QUARANTINE_FILE_MISSING', 'The quarantined file is missing from the quarantine folder.'); }
    if (st.isSymbolicLink() || !st.isFile()) return fail('UNSAFE_SOURCE', 'The quarantined item is not a regular file.');
    try { if ((await sha256File(from)) !== q.sha256) return fail('INTEGRITY_MISMATCH', 'The quarantined file no longer matches its recorded SHA-256 and was not restored.'); } catch (e) { return fail('READ_FAILED', errText(e)); }
    let target: string;
    try { target = validatePath(q.originalPath); } catch (e) { return fail('INVALID_PATH', (e as Error).message); }
    let parent = path.dirname(target);
    let parentOk = false; try { const p = await fs.promises.lstat(parent); parentOk = p.isDirectory() && !p.isSymbolicLink(); } catch { /* missing */ }
    if (!parentOk) {
      const fb = this.deps.fallbackRestoreDir;
      if (!o.useFallbackFolder || !fb) return fail('ORIGINAL_FOLDER_MISSING', 'The original folder no longer exists (or is not a normal folder). You can restore to the Downloads folder instead.');
      try { const p = await fs.promises.lstat(fb); if (!p.isDirectory() || p.isSymbolicLink()) throw new Error('bad'); } catch { return fail('FALLBACK_UNAVAILABLE', 'The fallback folder is not available.'); }
      parent = fb;
    }
    const base = sanitizeFileName(q.originalName); const ext = path.extname(base); const stem = ext ? base.slice(0, -ext.length) : base;
    let dest = path.join(parent, base); let n = 0;
    if (await this.insideVaultReal(parent)) return fail('UNSAFE_DESTINATION', 'The restore destination is inside the quarantine folder.');
    for (;;) { try { await fs.promises.lstat(dest); n++; dest = path.join(parent, `${stem} (restored${n > 1 ? ` ${n}` : ''})${ext}`); if (n > 50) return fail('NAME_COLLISION', 'Could not find a free file name.'); } catch { break; } }
    try { await this.mv(from, dest); } catch (e) { return fail('MOVE_FAILED', `The file could not be restored. ${errText(e)}`); }
    try { const d = await fs.promises.lstat(dest); if (!d.isFile() || d.size !== st.size) throw new Error('size'); if ((await sha256File(dest)) !== q.sha256) throw new Error('hash'); }
    catch { q.state = 'RESTORED'; q.restoredAt = this.now(); q.restoredPath = dest; this.store.save(); return fail('VERIFY_FAILED', 'The restored file could not be verified (it does not match the quarantined original). It was left at the destination; do not open it.'); }
    q.state = 'RESTORED'; q.restoredAt = this.now(); q.restoredPath = dest; this.store.save();
    try { this.deps.onRestored?.(q); } catch (e) { this.deps.log(`[SafePeek] onRestored hook failed: ${(e as Error).message}`); }
    return { ok: true, value: q, message: 'File restored. SafePeek did not open or run it.' };
  }

  remove(id: string, o: { confirmed: boolean }): Promise<ActionResult<QuarantinedFile>> { return this.serial(() => this.doRemove(id, o)); }
  private async doRemove(id: string, o: { confirmed: boolean }): Promise<ActionResult<QuarantinedFile>> {
    const q = this.get(id); if (!q) return fail('NOT_FOUND', 'Quarantine entry not found.');
    if (q.state !== 'QUARANTINED') return fail('NOT_QUARANTINED', 'This file is no longer in quarantine.');
    if (o.confirmed !== true) return fail('CONFIRMATION_REQUIRED', 'Permanent deletion requires confirmation.');
    let target: string; try { target = await this.vaultFile(q); } catch (e) { return fail('UNSAFE_SOURCE', (e as Error).message); }
    try { await fs.promises.unlink(target); } catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') return fail('DELETE_FAILED', `The quarantined file could not be deleted. ${errText(e)}`); }
    q.state = 'DELETED'; q.deletedAt = this.now(); this.store.save();
    return { ok: true, value: q, message: 'Quarantined copy permanently deleted.' };
  }
}
