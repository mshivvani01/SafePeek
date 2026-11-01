import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { StateStore } from '../electron/agent/store';
import { FileEventService } from '../electron/agent/fileEventService';
import { waitForStable } from '../electron/agent/stability';
import type { DetectedFile, MonitoredFolder } from '../electron/agent/types';
import { rm, tmp } from './helpers/phase6';

const FAST = { intervalMs: 40, requiredStableChecks: 2, timeoutMs: 3000 };
const dirs: string[] = []; afterEach(() => { dirs.splice(0).forEach(rm); });
function setup(stability = FAST) {
  const root = tmp('sp7w-'); dirs.push(root); const dl = path.join(root, 'Downloads'); fs.mkdirSync(dl);
  const store = new StateStore(path.join(root, 's.json'), dl, () => undefined);
  const recorded: DetectedFile[] = []; const logs: string[] = [];
  const svc = new FileEventService(store, { emitChange: () => undefined, notify: () => undefined, isFolderActive: () => true, log: (m) => logs.push(m), stability, onFileRecorded: (f) => recorded.push(f) });
  const folder: MonitoredFolder = { id: 'downloads', path: dl, label: 'Downloads', enabled: true, isDefault: true, addedAt: new Date().toISOString() };
  return { root, dl, store, svc, folder, recorded, logs };
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('Phase 7A file stability', () => {
  it('waits while a file is growing and only reports stable after it stops changing', async () => {
    const { dl } = setup(); const f = path.join(dl, 'big.zip'); fs.writeFileSync(f, 'a');
    let writes = 0; const t = setInterval(() => { if (writes++ < 6) fs.appendFileSync(f, 'b'.repeat(100)); }, 50);
    const t0 = Date.now(); const r = await waitForStable(f, FAST); clearInterval(t);
    expect(r.stable).toBe(true); if (r.stable) expect(r.size).toBe(1 + 600); expect(Date.now() - t0).toBeGreaterThan(250);
  });
  it('reports a file that never settles as a timeout (it is not analyzed as complete)', async () => {
    const { dl } = setup(); const f = path.join(dl, 'endless.bin'); fs.writeFileSync(f, 'a');
    const t = setInterval(() => fs.appendFileSync(f, 'x'), 15);
    const r = await waitForStable(f, { intervalMs: 30, requiredStableChecks: 3, timeoutMs: 400 }); clearInterval(t);
    expect(r).toMatchObject({ stable: false, reason: 'timeout' });
  });
  it('reports missing when the file is deleted while waiting', async () => {
    const { dl } = setup(); const f = path.join(dl, 'gone.bin'); fs.writeFileSync(f, 'a'); setTimeout(() => fs.rmSync(f), 60);
    expect(await waitForStable(f, FAST)).toMatchObject({ stable: false, reason: 'missing' });
  });
  it('can be cancelled', async () => { const { dl } = setup(); const f = path.join(dl, 'c.bin'); fs.writeFileSync(f, 'a'); const tok = { cancelled: false }; setTimeout(() => (tok.cancelled = true), 30); expect(await waitForStable(f, { ...FAST, requiredStableChecks: 50 }, tok)).toMatchObject({ reason: 'cancelled' }); });
});

describe('Phase 7A watcher event handling', () => {
  it('many duplicate events for one file produce exactly one record and one analysis', async () => {
    const { dl, svc, folder, store, recorded } = setup(); const f = path.join(dl, 'a.pdf'); fs.writeFileSync(f, '%PDF-1.4 x');
    await Promise.all([svc.handle(folder, f, 'add'), svc.handle(folder, f, 'add'), svc.handle(folder, f, 'change'), svc.handle(folder, f, 'add')]);
    await svc.handle(folder, f, 'change'); await svc.handle(folder, f, 'add'); // metadata-style repeats after recording
    expect(store.state.files).toHaveLength(1); expect(recorded).toHaveLength(1);
  });
  it('several files arriving at once are each recorded once', async () => {
    const { dl, svc, folder, store, recorded } = setup(); const names = Array.from({ length: 12 }, (_, i) => `f${i}.txt`);
    names.forEach((n, i) => fs.writeFileSync(path.join(dl, n), `content ${i}`));
    await Promise.all(names.flatMap((n) => [svc.handle(folder, path.join(dl, n), 'add'), svc.handle(folder, path.join(dl, n), 'add')]));
    expect(store.state.files.map((x) => x.name).sort()).toEqual([...names].sort()); expect(recorded).toHaveLength(12);
  });
  it('temporary / incomplete-download / lock files are ignored', async () => {
    const { dl, svc, folder, store } = setup();
    for (const n of ['x.crdownload', 'y.part', 'z.tmp', '~$doc.docx', 'Thumbs.db', 'desktop.ini']) { fs.writeFileSync(path.join(dl, n), 'x'); await svc.handle(folder, path.join(dl, n), 'add'); }
    expect(store.state.files).toHaveLength(0);
  });
  it('a file modified later is re-recorded once, with a new id and a changed signature (old results become stale)', async () => {
    const { dl, svc, folder, store, recorded } = setup(); const f = path.join(dl, 'r.txt'); fs.writeFileSync(f, 'one');
    await svc.handle(folder, f, 'add'); const first = store.state.files[0];
    await sleep(20); fs.writeFileSync(f, 'two two two'); await svc.handle(folder, f, 'change');
    expect(store.state.files).toHaveLength(1); expect(store.state.files[0].id).not.toBe(first.id); expect(store.state.files[0].signature).not.toBe(first.signature); expect(recorded).toHaveLength(2);
  });
  it('a file deleted before it is stable is not recorded', async () => {
    const { dl, svc, folder, store } = setup(); const f = path.join(dl, 'd.txt'); fs.writeFileSync(f, 'x'); setTimeout(() => fs.rmSync(f), 40);
    await svc.handle(folder, f, 'add'); expect(store.state.files).toHaveLength(0);
  });
  it('a file that never settles produces a visible watcher-error event, not silence', async () => {
    const { dl, svc, folder, store } = setup({ intervalMs: 20, requiredStableChecks: 3, timeoutMs: 250 }); const f = path.join(dl, 'busy.bin'); fs.writeFileSync(f, 'x');
    const t = setInterval(() => fs.appendFileSync(f, 'y'), 8); await svc.handle(folder, f, 'add'); clearInterval(t);
    expect(store.state.files).toHaveLength(0); expect(store.state.events.some((e) => e.type === 'watcher-error' && e.fileName === 'busy.bin')).toBe(true);
  });
  it('a quarantined record survives when a new file with the same name is downloaded', async () => {
    const { dl, svc, folder, store } = setup(); const f = path.join(dl, 'invoice.exe'); fs.writeFileSync(f, 'MZ one');
    await svc.handle(folder, f, 'add'); const q = store.state.files[0]; q.quarantineState = 'QUARANTINED'; fs.rmSync(f); // as if SafePeek moved it away
    fs.writeFileSync(f, 'MZ brand new download'); await svc.handle(folder, f, 'add');
    expect(store.state.files).toHaveLength(2); expect(store.state.files.some((x) => x.id === q.id && x.quarantineState === 'QUARANTINED')).toBe(true);
    expect(store.state.files.some((x) => x.id !== q.id && !x.quarantineState)).toBe(true);
  });
  it('files outside the monitored folder and excluded (quarantine) paths are ignored', async () => {
    const { root, dl, store, folder, recorded, logs } = setup(); const out = path.join(root, 'elsewhere.txt'); fs.writeFileSync(out, 'x');
    const svc2 = new FileEventService(store, { emitChange: () => undefined, notify: () => undefined, isFolderActive: () => true, log: (m) => logs.push(m), stability: FAST, onFileRecorded: (f) => recorded.push(f), isExcluded: (p) => p.endsWith('.quarantine') });
    fs.writeFileSync(path.join(dl, 'a.quarantine'), 'x'); await svc2.handle(folder, out, 'add'); await svc2.handle(folder, path.join(dl, 'a.quarantine'), 'add'); expect(store.state.files).toHaveLength(0);
  });
});
