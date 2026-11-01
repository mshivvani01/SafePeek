import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import { assessByPrefix, buildStack, rm, tmp } from './helpers/phase6';
import { makePE } from './helpers/fixtures';

const roots: string[] = []; afterEach(() => { roots.splice(0).forEach(rm); });
const stack = (o: Parameters<typeof buildStack>[1] = {}) => { const root = tmp('sp7p-'); roots.push(root); return buildStack(root, { assess: assessByPrefix, ...o }); };

describe('Phase 7A safe open', () => {
  it('opens an unchanged SAFE document without confirmation', async () => {
    const s = stack(); const f = await s.add('safe-notes.txt', 'meeting notes'); expect(f.threatStatus).toBe('SAFE');
    expect(await s.protection.openFile(f.id, false)).toMatchObject({ ok: true }); expect(s.sink.opened).toEqual([f.path]);
  });
  it('refuses when the size changed after analysis ("Analysis is outdated")', async () => {
    const s = stack(); const f = await s.add('safe-a.txt', 'one'); fs.appendFileSync(f.path, ' more');
    const r = await s.protection.openFile(f.id, false); expect(r).toMatchObject({ ok: false, code: 'FILE_CHANGED' }); expect((r as { error: string }).error).toMatch(/Analysis is outdated/); expect(s.sink.opened).toEqual([]);
  });
  it('refuses when content changed but size and modified time were preserved (hash check)', async () => {
    const s = stack(); const f = await s.add('safe-b.txt', 'AAAA'); const st = fs.statSync(f.path);
    fs.writeFileSync(f.path, 'BBBB'); fs.utimesSync(f.path, st.atime, st.mtime);
    expect(await s.protection.openFile(f.id, false)).toMatchObject({ ok: false, code: 'FILE_CHANGED' }); expect(s.sink.opened).toEqual([]);
  });
  it('a missing file gives a clear message', async () => { const s = stack(); const f = await s.add('safe-c.txt', 'x'); fs.rmSync(f.path); expect(await s.protection.openFile(f.id, false)).toMatchObject({ ok: false, code: 'FILE_MISSING' }); });
  it('unknown ids and directories are rejected', async () => {
    const s = stack(); expect(await s.protection.openFile('does-not-exist-1234', false)).toMatchObject({ ok: false, code: 'NOT_FOUND' });
    const f = await s.add('safe-d.txt', 'x'); fs.rmSync(f.path); fs.mkdirSync(f.path); expect(await s.protection.openFile(f.id, false)).toMatchObject({ ok: false, code: 'NOT_A_FILE' });
  });
  it('an executable is never opened silently, even when its verdict is SAFE', async () => {
    const s = stack(); const f = await s.add('safe-tool.exe', makePE(), ''); expect(f.threatStatus).toBe('SAFE');
    expect(await s.protection.openFile(f.id, false)).toMatchObject({ ok: false, code: 'CONFIRMATION_REQUIRED' }); expect(s.sink.opened).toEqual([]);
    expect((await s.protection.openFile(f.id, true)).ok).toBe(true); expect(s.sink.opened).toHaveLength(1);
  });
  it('HIGH / CRITICAL / SUSPICIOUS / UNKNOWN each need confirmation and nothing opens without it', async () => {
    const s = stack();
    for (const n of ['high-a.txt', 'crit-a.txt', 'susp-a.txt', 'unk-a.txt']) { const f = await s.add(n, 'x'); expect(await s.protection.openFile(f.id, false), n).toMatchObject({ ok: false, code: 'CONFIRMATION_REQUIRED' }); expect(await s.protection.openFile(f.id, 'true' as never), n).toMatchObject({ ok: false, code: 'CONFIRMATION_REQUIRED' }); }
    expect(s.sink.opened).toEqual([]);
  });
  it('while the pipeline is re-analyzing, an old SAFE verdict is not trusted', async () => {
    const s = stack(); const f = await s.add('safe-e.txt', 'x'); f.analysisStatus = 'analyzing';
    expect(await s.protection.openFile(f.id, false)).toMatchObject({ ok: false, code: 'CONFIRMATION_REQUIRED' });
  });
  it('rescan clears the previous verdict immediately', async () => {
    const s = stack(); const f = await s.add('crit-f.txt', 'x'); expect(f.threatStatus).toBe('CRITICAL'); s.analysis.reanalyze(f.id);
    expect(f.threatStatus).toBeUndefined(); expect(f.riskLevel).toBe('unknown'); await s.settle(); expect(f.threatStatus).toBe('CRITICAL');
  });
});

describe('Phase 7A automatic protection', () => {
  it('automatic quarantine OFF: nothing is moved, but the alert exists', async () => {
    const s = stack(); const f = await s.add('crit-g.exe', makePE(), ''); expect(fs.existsSync(f.path)).toBe(true); expect(s.quarantine.activeCount()).toBe(0); expect(s.alerts.list({ state: 'all' }).length).toBe(1);
  });
  it('automatic quarantine ON: only CRITICAL is moved', async () => {
    const s = stack({ settings: { autoQuarantineCritical: true } });
    const c = await s.add('crit-h.exe', makePE(), ''); const h = await s.add('high-h.exe', makePE(), ''); const u = await s.add('susp-h.exe', makePE(), ''); const l = await s.add('low-h.txt', 'x'); const k = await s.add('safe-h.txt', 'x');
    expect(fs.existsSync(c.path)).toBe(false); expect(c.quarantineState).toBe('QUARANTINED');
    for (const x of [h, u, l, k]) { expect(fs.existsSync(x.path), x.name).toBe(true); expect(x.quarantineState).toBeUndefined(); }
    expect(s.quarantine.activeCount()).toBe(1);
  });
  it('a file the user restored is not auto-quarantined again', async () => {
    const s = stack({ settings: { autoQuarantineCritical: true } }); const f = await s.add('crit-i.exe', makePE(), ''); const q = s.quarantine.list()[0];
    expect((await s.protection.restoreFile(q.id, { confirmed: true })).ok).toBe(true); await s.settle(); expect(fs.existsSync(f.path)).toBe(true); expect(s.quarantine.activeCount()).toBe(0);
  });
  it('a failed automatic quarantine leaves the file, says so, and does not claim success', async () => {
    const s = stack({ settings: { autoQuarantineCritical: true }, move: async () => { throw Object.assign(new Error('EBUSY'), { code: 'EBUSY' }); } }); const f = await s.add('crit-j.exe', makePE(), '');
    expect(fs.existsSync(f.path)).toBe(true); expect(f.quarantineState).toBeUndefined(); const a = s.alerts.list({ state: 'all' })[0]; expect(a.actionTaken).toBeUndefined(); expect(a.message).toMatch(/did not succeed/i);
  });
});

describe('Phase 7A quarantine vs pipeline races', () => {
  it('a quarantined file keeps its verdict even if a rescan is requested (UI, IPC or stray caller)', async () => {
    const s = stack(); const f = await s.add('crit-k.exe', makePE(), ''); expect((await s.protection.quarantineFile(f.id)).ok).toBe(true);
    s.analysis.reanalyze(f.id); expect(s.protection.rescan(f.id)).toMatchObject({ ok: false, code: 'QUARANTINED' }); await s.settle();
    expect(f.threatStatus).toBe('CRITICAL'); expect(f.analysisStatus).toBe('complete'); expect(f.riskLevel).toBe('critical');
  });
  it('a threat analysis started for an already-quarantined file is skipped', async () => {
    const s = stack(); const f = await s.add('crit-l.exe', makePE(), ''); await s.protection.quarantineFile(f.id); const before = JSON.stringify(await s.threat.get(f.id));
    s.threat.rerun(f.id); await s.settle(); expect(JSON.stringify(await s.threat.get(f.id))).toBe(before); expect(f.threatStatus).toBe('CRITICAL');
  });
  it('a result that completes after the file became quarantined is discarded, not stored over its verdict', async () => {
    const s = stack(); const f = await s.add('crit-l2.exe', makePE(), ''); const before = JSON.stringify(await s.threat.get(f.id));
    s.threat.rerun(f.id); f.quarantineState = 'QUARANTINED'; // quarantine completes while the engine is running
    await s.settle(); expect(JSON.stringify(await s.threat.get(f.id))).toBe(before);
  });
  it('manual quarantine, restore and delete work through ProtectionService and keep records consistent', async () => {
    const s = stack(); const f = await s.add('high-m.exe', makePE(), ''); const q = await s.protection.quarantineFile(f.id); expect(q.ok).toBe(true); expect(await s.protection.quarantineFile(f.id)).toMatchObject({ code: 'ALREADY_QUARANTINED' });
    expect(await s.protection.openFile(f.id, true)).toMatchObject({ ok: false, code: 'QUARANTINED' });
    const id = s.quarantine.list()[0].id; expect(await s.protection.deleteQuarantined(id, { confirmed: false })).toMatchObject({ code: 'CONFIRMATION_REQUIRED' });
    expect((await s.protection.deleteQuarantined(id, { confirmed: true })).ok).toBe(true); expect(f.quarantineState).toBe('DELETED'); expect(s.quarantine.activeCount()).toBe(0);
  });
  it('restore re-analyzes the file, never opens it, and a restored risky file still needs confirmation', async () => {
    const s = stack(); const f = await s.add('crit-n.exe', makePE(), ''); await s.protection.quarantineFile(f.id); const id = s.quarantine.list()[0].id;
    const r = await s.protection.restoreFile(id, { confirmed: false }); expect(r).toMatchObject({ ok: false, code: 'CONFIRMATION_REQUIRED' });
    expect((await s.protection.restoreFile(id, { confirmed: true })).ok).toBe(true); expect(s.sink.rescans).toContain(f.id); expect(s.sink.opened).toEqual([]); await s.settle();
    expect(f.threatStatus).toBe('CRITICAL'); expect(fs.existsSync(f.path)).toBe(true); expect(f.quarantineState).toBe('RESTORED');
    expect(await s.protection.openFile(f.id, false)).toMatchObject({ ok: false, code: 'CONFIRMATION_REQUIRED' });
  });
});

describe('Phase 7A alerts and notifications', () => {
  it('re-running the same analysis does not create another alert or notification', async () => {
    const s = stack(); const f = await s.add('high-o.exe', makePE(), ''); for (let i = 0; i < 3; i++) { s.threat.rerun(f.id); await s.settle(); }
    expect(s.alerts.list({ state: 'all' })).toHaveLength(1); expect(s.sink.notified).toHaveLength(1);
  });
  it('the alert carries the right file, severity and score and starts unread', async () => {
    const s = stack(); const f = await s.add('crit-p.exe', makePE(), ''); const a = s.alerts.list({ state: 'all' })[0];
    expect(a).toMatchObject({ fileId: f.id, severity: 'CRITICAL', status: 'CRITICAL', score: f.threatScore, fileName: 'crit-p.exe' }); expect(a.readAt).toBeUndefined(); expect(s.alerts.unreadCount()).toBe(1);
    s.alerts.markRead(a.id); expect(s.alerts.unreadCount()).toBe(0); s.alerts.dismiss(a.id); expect(s.alerts.list({ state: 'active' })).toHaveLength(0); expect(s.alerts.list({ state: 'dismissed' })).toHaveLength(1);
  });
  it('a failing notification backend never loses the alert or breaks the pipeline', async () => {
    const s = stack({ notifyThrows: true }); const f = await s.add('crit-q.exe', makePE(), ''); expect(s.alerts.list({ state: 'all' })).toHaveLength(1); expect(f.threatStatus).toBe('CRITICAL');
  });
  it('SAFE and UNKNOWN never alert', async () => { const s = stack(); await s.add('safe-r.txt', 'x'); await s.add('unk-r.txt', 'x'); expect(s.alerts.list({ state: 'all' })).toHaveLength(0); });
  it('hostile file names are sanitized in alerts', async () => { const s = stack(); await s.add('crit-\u202Egnp.exe', makePE(), ''); expect(s.alerts.list({ state: 'all' })[0].fileName).not.toMatch(/\u202E/); });
});

describe('Phase 7A analysis timeout and mid-analysis changes', () => {
  it('a static analysis that never finishes ends as failed/incomplete, never SAFE', async () => {
    const root = tmp('sp7t-'); roots.push(root); const s = buildStack(root, {}); (s.analysis as unknown as { deps: { timeoutMs: number; analyze: () => Promise<never> } }).deps.timeoutMs = 60; (s.analysis as unknown as { deps: { analyze: () => Promise<never> } }).deps.analyze = () => new Promise(() => undefined);
    const f = await s.add('hang.bin', 'x'); expect(f.analysisStatus).toBe('failed'); expect(f.threatStatus).toBe('UNKNOWN'); expect(f.riskLevel).toBe('unknown'); expect(f.analysis?.partialReasons.join(' ')).toMatch(/timed out/i);
  });
  it('a crash inside the analyzer ends as failed/UNKNOWN', async () => {
    const root = tmp('sp7t-'); roots.push(root); const s = buildStack(root, {}); (s.analysis as unknown as { deps: { analyze: () => Promise<never> } }).deps.analyze = async () => { throw new Error('parser exploded'); };
    const f = await s.add('crash.bin', 'x'); expect(f.analysisStatus).toBe('failed'); expect(f.threatStatus).toBe('UNKNOWN');
  });
  it('a file modified while it is being analyzed is analyzed again (and the signature follows the new bytes)', async () => {
    const root = tmp('sp7t-'); roots.push(root); const s = buildStack(root, { assess: assessByPrefix }); const real = (s.analysis as unknown as { deps: { analyze?: (p: string) => Promise<never> } }).deps; let calls = 0;
    const { analyzeFile } = await import('../electron/analysis/analyzer'); real.analyze = (async (p: string, o?: { name?: string }) => { calls++; const r = await analyzeFile(p, o); if (calls === 1) { await new Promise((x) => setTimeout(x, 15)); fs.appendFileSync(p, ' grew'); } return r; }) as never;
    const f = await s.add('safe-grow.txt', 'start'); expect(calls).toBe(2); expect(f.signature).toBe(`${fs.statSync(f.path).size}:${fs.statSync(f.path).mtimeMs}`); expect(f.analysis?.metadata.size).toBe(fs.statSync(f.path).size);
  });
});
