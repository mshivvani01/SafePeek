import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { AlertService, alertEligible, assessmentFingerprint, decideOpen, DEFAULT_SECURITY_SETTINGS, normalizeSecurity, notificationAllowed } from '../electron/protection';
import type { SecuritySettings } from '../electron/protection';
import type { ThreatStatus } from '../electron/threat/types';
import { assessByPrefix, buildStack, fakeAssessment, rm, tmp } from './helpers/phase6';
import type { StackOpts } from './helpers/phase6';
import { makePE } from './helpers/fixtures';

const dirs: string[] = []; const T = () => { const d = tmp('sp6p-'); dirs.push(d); return d; };
afterEach(() => { dirs.splice(0).forEach(rm); });
const S = (o: StackOpts = {}) => buildStack(T(), { assess: assessByPrefix, ...o });
const events = (st: ReturnType<typeof buildStack>, type: string) => st.store.state.events.filter((e) => e.type === type);
const ALL: ThreatStatus[] = ['SAFE', 'LOW_RISK', 'SUSPICIOUS', 'HIGH_RISK', 'CRITICAL', 'UNKNOWN'];

describe('settings defaults and normalization', () => {
  it('defaults are conservative: auto-quarantine OFF, confirmation ON, informational notifications OFF', () => {
    expect(DEFAULT_SECURITY_SETTINGS).toMatchObject({ autoQuarantineCritical: false, requireConfirmHighRisk: true, notifyCritical: true, notifyHigh: true, notifySuspicious: true, notifyInformational: false });
  });
  it('wrong types fall back to the existing safe values and unknown keys are dropped', () => {
    const n = normalizeSecurity({ autoQuarantineCritical: 'yes', requireConfirmHighRisk: 0, notifyHigh: null, evil: true, explanationLevel: 'x' }); expect(n).toEqual(DEFAULT_SECURITY_SETTINGS); expect('evil' in n).toBe(false);
    expect(normalizeSecurity({ autoQuarantineCritical: true, explanationLevel: 'technical' })).toMatchObject({ autoQuarantineCritical: true, explanationLevel: 'technical' }); expect(normalizeSecurity(null)).toEqual(DEFAULT_SECURITY_SETTINGS);
  });
  it('settings persist', () => {
    const st = S(); st.settings.setSecurity({ autoQuarantineCritical: true }); const again = new (st.settings.constructor as new (f: string) => typeof st.settings)(path.join(st.root, 'security', 'settings.json')); expect(again.security().autoQuarantineCritical).toBe(true);
  });
});

describe('alert thresholds reuse the Phase 5 status (no second scoring system)', () => {
  it('eligibility and notification per status with default settings', () => {
    const d = DEFAULT_SECURITY_SETTINGS; const r = Object.fromEntries(ALL.map((s) => [s, [alertEligible(s, d), notificationAllowed(s, d)]]));
    expect(r).toEqual({ SAFE: [false, false], LOW_RISK: [false, false], SUSPICIOUS: [true, true], HIGH_RISK: [true, true], CRITICAL: [true, true], UNKNOWN: [false, false] });
  });
  it('informational toggle enables LOW_RISK; per-severity toggles silence notifications but not the alert record', () => {
    const s: SecuritySettings = { ...DEFAULT_SECURITY_SETTINGS, notifyInformational: true, notifyHigh: false };
    expect(alertEligible('LOW_RISK', s) && notificationAllowed('LOW_RISK', s)).toBe(true); expect(alertEligible('HIGH_RISK', s)).toBe(true); expect(notificationAllowed('HIGH_RISK', s)).toBe(false);
  });
  it('pipeline: SAFE/LOW/UNKNOWN create nothing; SUSPICIOUS/HIGH/CRITICAL create alerts + notifications with the right severity', async () => {
    const st = S(); for (const n of ['safe-a.txt', 'low-a.txt', 'unk-a.txt']) await st.add(n, 'hello');
    expect(st.alerts.list({ state: 'all' })).toHaveLength(0); expect(st.sink.notified).toHaveLength(0);
    await st.add('susp-a.txt', 'x'); await st.add('high-a.txt', 'x'); await st.add('crit-a.txt', 'x');
    expect(st.alerts.list().map((a) => [a.fileName, a.severity]).sort()).toEqual([['crit-a.txt', 'CRITICAL'], ['high-a.txt', 'HIGH'], ['susp-a.txt', 'WARNING']]); expect(st.sink.notified).toHaveLength(3);
    expect(events(st, 'alert-created')).toHaveLength(3); expect(events(st, 'alert-shown')).toHaveLength(3);
  });
  it('LOW_RISK alerts appear only when informational alerts are enabled', async () => { const st = S({ settings: { notifyInformational: true } }); await st.add('low-a.txt', 'x'); expect(st.alerts.list()).toMatchObject([{ severity: 'INFO' }]); expect(st.sink.notified).toHaveLength(1); });
  it('a disabled severity still records the alert but shows no desktop notification', async () => { const st = S({ settings: { notifyHigh: false } }); await st.add('high-a.txt', 'x'); expect(st.alerts.list()).toHaveLength(1); expect(st.sink.notified).toHaveLength(0); expect(st.alerts.list()[0].notified).toBe(false); });
  it('a failing notification backend does not break the pipeline', async () => { const st = S({ notifyThrows: true }); await st.add('crit-a.txt', 'x'); expect(st.alerts.list()).toHaveLength(1); expect(st.alerts.list()[0].notified).toBe(false); expect(events(st, 'alert-shown')).toHaveLength(0); });
  it('alert text never contains hidden direction-control characters from file names', async () => { const st = S(); await st.add('high-\u202Egnp.exe', 'x'); const a = st.alerts.list()[0]; expect(a.fileName).not.toMatch(/\u202E/); expect(a.message).not.toMatch(/\u202E/); expect(a.message).toMatch(/risk score 65\/100/); });
});

describe('alert deduplication, history, read/dismiss, persistence', () => {
  it('the same assessment is never alerted twice (rescan, restart, UI refresh); a changed outcome is', async () => {
    const st = S(); const f = await st.add('high-a.txt', 'x'); expect(st.sink.notified).toHaveLength(1);
    st.protection.rescan(f.id); await st.settle(); await st.settle(); expect(st.alerts.list({ state: 'all' })).toHaveLength(1); expect(st.sink.notified).toHaveLength(1);
    st.alerts.dismiss(st.alerts.list()[0].id); st.protection.rescan(f.id); await st.settle(); expect(st.alerts.list({ state: 'all' })).toHaveLength(1); // dismissed alerts are not recreated
    const a = fakeAssessment('HIGH_RISK', { inds: [['A', 'HIGH', 't', 'MALWARE']] }); const b = fakeAssessment('HIGH_RISK', { inds: [['B', 'HIGH', 't', 'MALWARE']] }); expect(assessmentFingerprint(a)).not.toBe(assessmentFingerprint(b));
    const x = st.alerts.create({ id: f.id, name: f.name, sha256: f.sha256 }, b); expect(x!.duplicate).toBe(false);
  });
  it('same file name + hash + assessment is a duplicate even for different file ids', () => {
    const st = S(); const a = fakeAssessment('CRITICAL', { inds: [['A', 'HIGH', 't', 'MALWARE']] }); const one = st.alerts.create({ id: 'a', name: 'x.exe', sha256: 'h1' }, a)!; const two = st.alerts.create({ id: 'b', name: 'x.exe', sha256: 'h1' }, a)!;
    expect([one.duplicate, two.duplicate]).toEqual([false, true]); expect(st.alerts.create({ id: 'c', name: 'y.exe', sha256: 'h1' }, a)!.duplicate).toBe(false); expect(st.alerts.create({ id: 'a', name: 'x.exe', sha256: 'h1' }, fakeAssessment('SAFE'))).toBeNull();
  });
  it('mark read / mark all / dismiss / filters / unread count', async () => {
    const st = S(); await st.add('susp-a.txt', 'x'); await st.add('high-a.txt', 'x'); await st.add('crit-a.txt', 'x'); expect(st.alerts.unreadCount()).toBe(3);
    const [c, h] = [st.alerts.list({ severity: 'CRITICAL' })[0], st.alerts.list({ severity: 'HIGH' })[0]]; expect(st.alerts.markRead(c.id)).toBe(true); expect(st.alerts.get(c.id)!.readAt).toBeTruthy(); expect(st.alerts.unreadCount()).toBe(2);
    expect(st.alerts.list({ state: 'unread' })).toHaveLength(2); expect(st.alerts.dismiss(h.id)).toBe(true); expect(st.alerts.list()).toHaveLength(2); expect(st.alerts.list({ state: 'dismissed' })).toHaveLength(1); expect(st.alerts.list({ state: 'all' })).toHaveLength(3);
    expect(st.alerts.markAllRead()).toBe(1); expect(st.alerts.unreadCount()).toBe(0); expect(st.alerts.markRead('nope')).toBe(false); expect(st.alerts.dismiss('nope')).toBe(false);
  });
  it('alerts persist and reload', async () => {
    const st = S(); await st.add('crit-a.txt', 'x'); const id = st.alerts.list()[0].id; st.alerts.markRead(id); const again = new AlertService(path.join(st.root, 'security', 'alerts.json'));
    expect(again.list()).toHaveLength(1); expect(again.get(id)!.readAt).toBeTruthy(); expect(again.get(id)).toMatchObject({ fileName: 'crit-a.txt', severity: 'CRITICAL', score: 90, status: 'CRITICAL' });
  });
  it('a corrupted alert file is set aside, not fatal', () => { const root = T(); fs.mkdirSync(path.join(root, 'a')); fs.writeFileSync(path.join(root, 'a', 'alerts.json'), '{not json'); const a = new AlertService(path.join(root, 'a', 'alerts.json')); expect(a.list()).toEqual([]); expect(fs.readdirSync(path.join(root, 'a')).some((n) => n.includes('corrupt'))).toBe(true); });
  it('every completed assessment is written to threat history with the decision attached later', async () => {
    const st = S(); const f = await st.add('crit-a.txt', 'x'); st.protection.rescan(f.id); await st.settle(); expect(st.history.list().map((h) => [h.fileName, h.status, h.score])).toEqual([['crit-a.txt', 'CRITICAL', 90], ['crit-a.txt', 'CRITICAL', 90]]);
    await st.protection.quarantineFile(f.id); expect(st.history.list()[0].action).toBe('Quarantined'); expect(st.history.list()[0].actionAt).toBeTruthy();
  });
});

describe('protection mode: automatic quarantine', () => {
  it('OFF (default): a CRITICAL file stays where it is; user is alerted', async () => {
    const st = S(); const f = await st.add('crit-a.exe', makePE(), null); expect(fs.existsSync(f.path)).toBe(true); expect(f.quarantineState).toBeUndefined(); expect(st.quarantine.list()).toHaveLength(0);
    expect(st.alerts.list()[0].actionTaken).toBeUndefined(); expect(st.alerts.list()[0].message).toMatch(/Open SafePeek to review/);
  });
  it('ON + CRITICAL: file is physically moved, alert says so, notification sent, activity recorded; nothing deleted or executed', async () => {
    const st = S({ settings: { autoQuarantineCritical: true } }); const f = await st.add('crit-a.exe', makePE(), null);
    expect(fs.existsSync(f.path)).toBe(false); expect(f.quarantineState).toBe('QUARANTINED'); const q = st.quarantine.list()[0]; expect(q).toMatchObject({ automatic: true, riskStatus: 'CRITICAL', originalName: 'crit-a.exe', state: 'QUARANTINED' }); expect(fs.existsSync(q.quarantinePath)).toBe(true);
    const a = st.alerts.list()[0]; expect(a.actionTaken).toBe('Auto-quarantined'); expect(a.message).toMatch(/moved it to quarantine/); expect(st.sink.notified[0].actionTaken).toBe('Auto-quarantined'); expect(st.sink.opened).toHaveLength(0);
    expect(events(st, 'file-quarantined')[0].message).toMatch(/automatically/); expect(events(st, 'alert-created')).toHaveLength(1); expect(st.history.list()[0].action).toBe('Auto-quarantined');
  });
  it.each(['high-a.txt', 'susp-a.txt', 'low-a.txt', 'safe-a.txt', 'unk-a.txt'])('ON + %s (not CRITICAL): never moved', async (name) => {
    const st = S({ settings: { autoQuarantineCritical: true, notifyInformational: true } }); const f = await st.add(name, 'content'); expect(fs.existsSync(f.path)).toBe(true); expect(st.quarantine.list()).toHaveLength(0);
  });
  it('a file the user restored is not auto-quarantined again (no restore/quarantine loop)', async () => {
    const st = S({ settings: { autoQuarantineCritical: true } }); const f = await st.add('crit-a.exe', makePE(), null); const q = st.quarantine.list()[0];
    expect((await st.protection.restoreFile(q.id, { confirmed: true })).ok).toBe(true); await st.settle(); await st.settle();
    expect(fs.existsSync(path.join(st.dl, 'crit-a.exe'))).toBe(true); expect(st.quarantine.list().filter((x) => x.state === 'QUARANTINED')).toHaveLength(0); expect(f.id).toBeTruthy();
  });
  it('if the automatic move fails, the file stays, the alert says so honestly, and no success is claimed', async () => {
    const st = S({ settings: { autoQuarantineCritical: true }, move: async () => { throw new Error('locked by another process'); } }); const f = await st.add('crit-a.exe', makePE(), null);
    expect(fs.existsSync(f.path)).toBe(true); expect(f.quarantineState).toBeUndefined(); expect(st.alerts.list()[0].message).toMatch(/Automatic quarantine did not succeed/); expect(st.alerts.list()[0].actionTaken).toBeUndefined(); expect(events(st, 'quarantine-failed')).toHaveLength(1); expect(events(st, 'file-quarantined')).toHaveLength(0);
  });
  it('assessments that complete for an already-quarantined file are ignored (no new alert, no history)', async () => {
    const st = S(); const f = await st.add('crit-a.exe', makePE(), null); await st.protection.quarantineFile(f.id); const n = st.history.list().length; await st.protection.handleAssessment(f.id); expect(st.history.list()).toHaveLength(n);
  });
});

describe('user actions: quarantine / restore / delete / rescan / review', () => {
  it('manual quarantine moves the file, flags the record, updates alert + history + activity', async () => {
    const st = S(); const f = await st.add('high-a.exe', makePE(), null); const r = await st.protection.quarantineFile(f.id);
    expect(r.ok).toBe(true); expect(fs.existsSync(f.path)).toBe(false); expect(f.quarantineState).toBe('QUARANTINED'); expect(f.quarantineId).toBeTruthy(); expect(st.alerts.list()[0]).toMatchObject({ actionTaken: 'Quarantined' }); expect(st.alerts.list()[0].readAt).toBeTruthy();
    expect(events(st, 'file-quarantined')[0].message).toMatch(/by user/); expect((await st.protection.quarantineFile(f.id))).toMatchObject({ ok: false, code: 'ALREADY_QUARANTINED' }); expect(st.protection.status().quarantinedCount).toBe(1);
  });
  it('quarantine of a missing file fails honestly and leaves state unchanged', async () => {
    const st = S(); const f = await st.add('high-a.txt', 'x'); fs.rmSync(f.path); const r = await st.protection.quarantineFile(f.id); expect(r).toMatchObject({ ok: false, code: 'SOURCE_MISSING' }); expect(f.quarantineState).toBeUndefined(); expect(events(st, 'file-quarantined')).toHaveLength(0);
  });
  it('restore requires confirmation for risky files, restores without executing, and re-runs the analysis pipeline', async () => {
    const st = S(); const f = await st.add('high-a.exe', makePE(), null); await st.protection.quarantineFile(f.id); const q = st.quarantine.list()[0];
    expect(await st.protection.restoreFile(q.id, { confirmed: false })).toMatchObject({ ok: false, code: 'CONFIRMATION_REQUIRED' }); expect(fs.existsSync(f.path)).toBe(false);
    const before = st.history.list().length; expect((await st.protection.restoreFile(q.id, { confirmed: true })).ok).toBe(true); await st.settle(); await st.settle();
    expect(fs.existsSync(f.path)).toBe(true); expect(f.quarantineState).toBe('RESTORED'); expect(st.sink.opened).toHaveLength(0); expect(st.sink.rescans).toContain(f.id); expect(st.history.list().length).toBeGreaterThan(before); expect(events(st, 'file-restored')).toHaveLength(1);
    expect(f.threatStatus).toBe('HIGH_RISK'); // re-assessed after restore
  });
  it('permanent delete removes only the quarantined copy after confirmation and records it', async () => {
    const st = S(); const keep = path.join(st.dl, 'keep.txt'); fs.writeFileSync(keep, 'mine'); const f = await st.add('high-a.exe', makePE(), null); await st.protection.quarantineFile(f.id); const q = st.quarantine.list()[0];
    expect(await st.protection.deleteQuarantined(q.id, { confirmed: false })).toMatchObject({ ok: false, code: 'CONFIRMATION_REQUIRED' }); expect(fs.existsSync(q.quarantinePath)).toBe(true);
    expect((await st.protection.deleteQuarantined(q.id, { confirmed: true })).ok).toBe(true); expect(fs.existsSync(q.quarantinePath)).toBe(false); expect(fs.readFileSync(keep, 'utf8')).toBe('mine'); expect(f.quarantineState).toBe('DELETED'); expect(events(st, 'file-deleted')).toHaveLength(1); expect(st.history.list()[0].action).toBe('Deleted');
  });
  it('rescan runs the existing pipeline again (Phase 3 -> 4 -> 5 -> 6) and is recorded', async () => {
    const st = S(); const f = await st.add('susp-a.txt', 'hello'); const count = (t: string) => events(st, t).length; const b = [count('analysis-completed'), count('content-completed') + 0, count('threat-completed')];
    expect(st.protection.rescan(f.id).ok).toBe(true); await st.settle(); await st.settle();
    expect(count('analysis-completed')).toBe(b[0] + 1); expect(count('threat-completed')).toBe(b[2] + 1); expect(events(st, 'file-rescanned')).toHaveLength(1); expect(st.history.list()).toHaveLength(2); expect(f.threatStatus).toBe('SUSPICIOUS'); expect(f.threatAnalysisStatus).toBe('COMPLETED');
  });
  it('rescan of a quarantined file is refused (the quarantined copy is never analyzed or opened)', async () => { const st = S(); const f = await st.add('high-a.exe', makePE(), null); await st.protection.quarantineFile(f.id); expect(st.protection.rescan(f.id)).toMatchObject({ ok: false, code: 'QUARANTINED' }); expect(st.sink.rescans).toHaveLength(0); });
  it('review marks alerts read and records the action once', async () => {
    const st = S(); const f = await st.add('susp-a.txt', 'x'); expect(st.alerts.unreadCount()).toBe(1); st.protection.markReviewed(f.id); expect(st.alerts.unreadCount()).toBe(0); expect(st.history.list()[0].action).toBe('Reviewed'); expect(events(st, 'file-reviewed')).toHaveLength(1);
  });
  it('unknown ids are rejected by every action', async () => {
    const st = S(); for (const r of [await st.protection.quarantineFile('x'), st.protection.rescan('x'), st.protection.markReviewed('x'), await st.protection.openFile('x', true), await st.protection.openLocation('x'), st.protection.copyPath('x')]) expect(r).toMatchObject({ ok: false, code: 'NOT_FOUND' });
  });
});

describe('open safety', () => {
  it('decision table', () => {
    const on = { requireConfirmHighRisk: true }, off = { requireConfirmHighRisk: false };
    expect(decideOpen('SAFE', false, on)).toMatchObject({ allowed: true, requiresConfirmation: false }); expect(decideOpen('LOW_RISK', false, on).requiresConfirmation).toBe(false);
    for (const s of ['SUSPICIOUS', 'HIGH_RISK', 'CRITICAL', 'UNKNOWN'] as const) expect(decideOpen(s, false, on).requiresConfirmation).toBe(true);
    expect(decideOpen(undefined, false, on).requiresConfirmation).toBe(true); expect(decideOpen('HIGH_RISK', false, off).requiresConfirmation).toBe(false); expect(decideOpen('CRITICAL', false, off).requiresConfirmation).toBe(true);
    expect(decideOpen('SAFE', true, on)).toMatchObject({ allowed: false, level: 'QUARANTINED' });
  });
  it.each([['safe-a.txt'], ['low-a.txt']])('%s opens normally', async (n) => { const st = S(); const f = await st.add(n, 'x'); expect((await st.protection.openFile(f.id, false)).ok).toBe(true); expect(st.sink.opened).toEqual([f.path]); expect(events(st, 'file-opened')).toHaveLength(1); });
  it.each([['high-a.exe', 'HIGH RISK'], ['crit-a.exe', 'CRITICAL'], ['susp-a.txt', 'SUSPICIOUS'], ['unk-a.txt', 'UNKNOWN']])('%s: Open requires explicit confirmation; nothing is launched without it', async (n, label) => {
    const st = S(); const f = await st.add(n, n.endsWith('.exe') ? makePE() : 'x', n.endsWith('.exe') ? null : undefined);
    const r = await st.protection.openFile(f.id, false); expect(r).toMatchObject({ ok: false, code: 'CONFIRMATION_REQUIRED' }); expect((r as { error: string }).error).toContain(label); expect(st.sink.opened).toHaveLength(0);
    expect(await st.protection.openFile(f.id, 'true' as never)).toMatchObject({ ok: false, code: 'CONFIRMATION_REQUIRED' }); expect(await st.protection.openFile(f.id, 1 as never)).toMatchObject({ ok: false });
    expect((await st.protection.openFile(f.id, true)).ok).toBe(true); expect(st.sink.opened).toEqual([f.path]); expect(events(st, 'file-opened-anyway')).toHaveLength(1); expect(st.history.list()[0].action).toBe('Opened anyway');
  });
  it('the setting can relax confirmation for HIGH_RISK only; CRITICAL always asks', async () => {
    const st = S({ settings: { requireConfirmHighRisk: false } }); const h = await st.add('high-a.txt', 'x'); const c = await st.add('crit-a.txt', 'x');
    expect((await st.protection.openFile(h.id, false)).ok).toBe(true); expect(await st.protection.openFile(c.id, false)).toMatchObject({ ok: false, code: 'CONFIRMATION_REQUIRED' });
  });
  it('openInfo gives the confirmation dialog its reasons and never exposes a path', async () => {
    const st = S(); const f = await st.add('crit-a.txt', 'x'); const i = (await st.protection.openInfo(f.id))!; expect(i).toMatchObject({ requiresConfirmation: true, level: 'CRITICAL', fileName: 'crit-a.txt' }); expect(i.reasons.join(' ')).toMatch(/Double file extension/); expect(JSON.stringify(i)).not.toContain(st.dl);
    const safe = await st.add('safe-a.txt', 'x'); expect((await st.protection.openInfo(safe.id))!.reasons).toEqual([]);
  });
  it('quarantined files can never be opened or revealed', async () => { const st = S(); const f = await st.add('high-a.exe', makePE(), null); await st.protection.quarantineFile(f.id); expect(await st.protection.openFile(f.id, true)).toMatchObject({ ok: false, code: 'QUARANTINED' }); expect(await st.protection.openLocation(f.id)).toMatchObject({ ok: false, code: 'QUARANTINED' }); expect(st.sink.opened).toHaveLength(0); expect(st.sink.revealed).toHaveLength(0); });
  it('a file that changed after analysis is not opened (the assessment no longer describes it)', async () => { const st = S(); const f = await st.add('safe-a.txt', 'x'); fs.appendFileSync(f.path, ' tampered'); expect(await st.protection.openFile(f.id, true)).toMatchObject({ ok: false, code: 'FILE_CHANGED' }); expect(st.sink.opened).toHaveLength(0); });
  it('missing files and symlinks are not opened', async () => {
    const st = S(); const f = await st.add('safe-a.txt', 'x'); const target = path.join(st.root, 't.txt'); fs.writeFileSync(target, 'x'); fs.rmSync(f.path); fs.symlinkSync(target, f.path); expect(await st.protection.openFile(f.id, true)).toMatchObject({ ok: false, code: 'NOT_A_FILE' });
    fs.rmSync(f.path); expect(await st.protection.openFile(f.id, true)).toMatchObject({ ok: false, code: 'FILE_MISSING' }); expect(st.sink.opened).toHaveLength(0);
  });
  it('open file location reveals the containing folder instead of launching the file; copy path uses the clipboard', async () => {
    const st = S(); const f = await st.add('crit-a.txt', 'x'); expect((await st.protection.openLocation(f.id)).ok).toBe(true); expect(st.sink.revealed).toEqual([f.path]); expect(st.sink.opened).toHaveLength(0); expect(events(st, 'location-opened')).toHaveLength(1);
    expect(st.protection.copyPath(f.id).ok).toBe(true); expect(st.sink.clipboard).toEqual([f.path]); fs.rmSync(f.path); expect(await st.protection.openLocation(f.id)).toMatchObject({ ok: false, code: 'FILE_MISSING' });
  });
});

describe('protection status', () => {
  it('reports ON when monitoring is active, auto-quarantine state and live counts', async () => {
    const st = S({ settings: { autoQuarantineCritical: true } }); expect(st.protection.status()).toMatchObject({ protectionOn: true, autoQuarantineCritical: true, requireConfirmHighRisk: true, quarantinedCount: 0, unreadAlerts: 0 });
    await st.add('crit-a.exe', makePE(), null); expect(st.protection.status()).toMatchObject({ quarantinedCount: 1, unreadAlerts: 1 });
  });
});
