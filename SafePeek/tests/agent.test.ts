import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { MonitoringAgent } from '../electron/agent/agent';
import { StateStore } from '../electron/agent/store';
import { isTemporaryFile } from '../electron/agent/config';
import { validatePath } from '../electron/agent/paths';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until(fn: () => boolean, ms = 6000) { const t = Date.now(); while (!fn()) { if (Date.now() - t > ms) throw new Error('timeout'); await sleep(50); } }

let dir: string, dl: string, agent: MonitoringAgent, store: StateStore, notified: string[];
const mk = () => {
  store = new StateStore(path.join(dir, 'state.json'), dl, () => undefined);
  notified = [];
  agent = new MonitoringAgent(store, { log: () => undefined, emitChange: () => undefined, notify: (f) => { notified.push(f.name); }, stability: { intervalMs: 60, requiredStableChecks: 2, timeoutMs: 5000 } });
};
beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sp-')); dl = path.join(dir, 'Downloads'); fs.mkdirSync(dl); mk(); });
afterEach(async () => { await agent.stopAll(); fs.rmSync(dir, { recursive: true, force: true }); });

describe('helpers', () => {
  it('detects temp files', () => { for (const f of ['a.crdownload', 'b.TMP', 'c.part', 'd.partial', '~$x.docx']) expect(isTemporaryFile(f)).toBe(true); expect(isTemporaryFile('a.pdf')).toBe(false); });
  it('validates paths', () => { expect(() => validatePath('rel/x')).toThrow(); expect(() => validatePath('/a/../b')).toThrow(); expect(() => validatePath('/a\0b')).toThrow(); });
});

describe('monitoring agent (real chokidar)', () => {
  it('detects, ignores temp files, waits for stability, dedupes, pauses/resumes', async () => {
    await agent.start();
    await sleep(300);
    fs.writeFileSync(path.join(dl, 'test-document.txt'), 'hello');
    await until(() => store.state.files.length === 1);
    expect(notified).toEqual(['test-document.txt']);
    expect(store.state.files[0].analysisStatus).toBe('pending');

    // temp file ignored, then renamed -> processed once
    fs.writeFileSync(path.join(dl, 'big.crdownload'), 'x');
    await sleep(500);
    expect(store.state.files.length).toBe(1);
    fs.renameSync(path.join(dl, 'big.crdownload'), path.join(dl, 'big.pdf'));
    await until(() => store.state.files.length === 2);

    // growing file only recorded once complete, with final size
    const g = path.join(dl, 'grow.bin');
    fs.writeFileSync(g, 'a');
    for (let i = 0; i < 6; i++) { await sleep(80); fs.appendFileSync(g, 'bbbbbbbbbb'); }
    expect(store.state.files.some((f) => f.name === 'grow.bin')).toBe(false);
    await until(() => store.state.files.some((f) => f.name === 'grow.bin'));
    expect(store.state.files.find((f) => f.name === 'grow.bin')!.size).toBe(61);

    // concurrent duplicate events -> one record
    const folder = store.state.folders[0];
    fs.writeFileSync(path.join(dl, 'dup.txt'), 'd');
    await Promise.all([agent.events.handle(folder, path.join(dl, 'dup.txt'), 'add'), agent.events.handle(folder, path.join(dl, 'dup.txt'), 'add')]);
    await sleep(500);
    expect(store.state.files.filter((f) => f.name === 'dup.txt').length).toBe(1);

    // disable -> not detected; enable -> detected
    await agent.setMonitoringEnabled(false);
    fs.writeFileSync(path.join(dl, 'while-off.txt'), 'x');
    await sleep(600);
    expect(store.state.files.some((f) => f.name === 'while-off.txt')).toBe(false);
    await agent.setMonitoringEnabled(true);
    await sleep(300);
    fs.writeFileSync(path.join(dl, 'after-on.txt'), 'x');
    await until(() => store.state.files.some((f) => f.name === 'after-on.txt'));
  }, 30000);

  it('persists state and restores it after restart; recovers from corrupted state', async () => {
    await agent.start(); await sleep(300);
    fs.writeFileSync(path.join(dl, 'p.txt'), 'x');
    await until(() => store.state.files.length === 1);
    await agent.setMonitoringEnabled(false);
    await store.flush(); await agent.stopAll();
    mk();
    expect(store.state.files.length).toBe(1);
    expect(store.state.monitoringEnabled).toBe(false);
    await store.flush();
    fs.writeFileSync(path.join(dir, 'state.json'), '{not json');
    mk();
    expect(store.state.files.length).toBe(0);
    expect(store.state.folders[0].path).toBe(dl);
  }, 20000);

  it('manages custom folders and rejects invalid ones', async () => {
    await agent.start();
    const extra = path.join(dir, 'Extra'); fs.mkdirSync(extra);
    const f = await agent.addFolder(extra);
    await expect(agent.addFolder(extra)).rejects.toThrow();
    await expect(agent.addFolder('relative')).rejects.toThrow();
    await expect(agent.removeFolder('downloads')).rejects.toThrow();
    await sleep(300);
    fs.writeFileSync(path.join(extra, 'e.txt'), 'x');
    await until(() => store.state.files.some((x) => x.name === 'e.txt'));
    expect(store.state.files[0].sourceFolder).toBe('Extra');
    await agent.removeFolder(f.id);
    expect(store.state.folders.length).toBe(1);
  }, 20000);

  it('reports an inaccessible folder without crashing', async () => {
    fs.rmSync(dl, { recursive: true });
    await agent.start();
    expect(agent.getStatus().active).toBe(false);
    expect(Object.keys(agent.getStatus().folderErrors)).toContain('downloads');
  });
});
