import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { StateStore } from '../electron/agent/store';
import { AlertService, HistoryService, SecuritySettingsStore } from '../electron/protection';
import { JsonStore } from '../electron/protection/jsonStore';
import { SecretStore } from '../electron/ai';
import { atomicWriteFile, atomicWriteFileSync } from '../electron/util/atomicWrite';
import { fakeAssessment, rm, tmp } from './helpers/phase6';

const roots: string[] = []; afterEach(() => { roots.splice(0).forEach(rm); });
const dir = () => { const d = tmp('sp7s-'); roots.push(d); return d; };
const goodFile = (n = 'a.txt') => ({ id: 'f-' + n + '-0001', name: n, path: path.resolve('/tmp', n), signature: '1:1', extension: 'txt' });

describe('Phase 7A agent state store', () => {
  it('missing file -> defaults with the Downloads folder', () => { const d = dir(); const s = new StateStore(path.join(d, 's.json'), '/dl', () => undefined); expect(s.state.folders[0]).toMatchObject({ id: 'downloads', path: '/dl' }); expect(s.state.files).toEqual([]); });
  it('corrupt JSON -> starts fresh, keeps the bad file aside, logs, does not throw', () => {
    const d = dir(); fs.writeFileSync(path.join(d, 's.json'), '{{{{'); const logs: string[] = []; const s = new StateStore(path.join(d, 's.json'), '/dl', (m) => logs.push(m));
    expect(s.state.files).toEqual([]); expect(fs.readdirSync(d).some((n) => n.includes('.corrupt-'))).toBe(true); expect(logs.join(' ')).toMatch(/unreadable/);
  });
  it('wrong shape or version -> starts fresh', () => { const d = dir(); fs.writeFileSync(path.join(d, 's.json'), JSON.stringify({ version: 99, files: 'x' })); expect(new StateStore(path.join(d, 's.json'), '/dl', () => undefined).state.files).toEqual([]); });
  it('malformed records inside a valid file are dropped individually; valid ones survive', () => {
    const d = dir(); const st = { version: 1, monitoringEnabled: true, folders: [{ id: 'downloads', path: '/old', label: 'Downloads', enabled: true, isDefault: true, addedAt: 'x' }, null, { id: 5 }], files: [goodFile(), null, 7, { id: 'x' }, { ...goodFile('b.txt'), path: 5 }], events: [null, { id: 'e1', type: 'file-detected', message: 'm', timestamp: 't' }, 'str'] };
    fs.writeFileSync(path.join(d, 's.json'), JSON.stringify(st)); const logs: string[] = []; const s = new StateStore(path.join(d, 's.json'), '/dl', (m) => logs.push(m));
    expect(s.state.files.map((f) => f.name)).toEqual(['a.txt']); expect(s.state.folders).toHaveLength(1); expect(s.state.folders[0].path).toBe('/dl'); expect(s.state.events).toHaveLength(1); expect(logs.join(' ')).toMatch(/malformed/);
  });
  it('a state file without a default folder gets one back', () => { const d = dir(); fs.writeFileSync(path.join(d, 's.json'), JSON.stringify({ version: 1, monitoringEnabled: true, folders: [], files: [], events: [] })); expect(new StateStore(path.join(d, 's.json'), '/dl', () => undefined).state.folders[0].isDefault).toBe(true); });
  it('many rapid saves end in one complete, parseable file with the last state (no interleaving, no leftovers)', async () => {
    const d = dir(); const f = path.join(d, 's.json'); const s = new StateStore(f, '/dl', () => undefined);
    for (let i = 0; i < 80; i++) { s.state.files = [goodFile(`n${i}.txt`) as never]; s.save(); } await s.flush();
    expect(JSON.parse(fs.readFileSync(f, 'utf8')).files[0].name).toBe('n79.txt'); expect(fs.readdirSync(d).filter((n) => n.endsWith('.tmp'))).toEqual([]);
  });
  it('corrupt copies are capped so a repeatedly broken store cannot fill the disk', () => {
    const d = dir(); for (let i = 0; i < 6; i++) { fs.writeFileSync(path.join(d, 's.json'), 'broken ' + i); new StateStore(path.join(d, 's.json'), '/dl', () => undefined); }
    expect(fs.readdirSync(d).filter((n) => n.includes('.corrupt-')).length).toBeLessThanOrEqual(3);
  });
});

describe('Phase 7A security stores', () => {
  it('alerts and history: malformed entries are ignored, valid ones kept', () => {
    const d = dir(); const a = fakeAssessment('HIGH_RISK'); const al = new AlertService(path.join(d, 'a.json')); al.create({ id: 'file-1-aaaa', name: 'x.exe', sha256: 'h' }, a);
    const j = JSON.parse(fs.readFileSync(path.join(d, 'a.json'), 'utf8')); j.alerts.push(null, 5, {}, { id: 'z', fileId: 'q', dedupeKey: 'k', fileName: 'n', score: 1, severity: 'BOGUS' }); fs.writeFileSync(path.join(d, 'a.json'), JSON.stringify(j));
    const logs: string[] = []; const al2 = new AlertService(path.join(d, 'a.json'), (m) => logs.push(m)); expect(al2.list({ state: 'all' })).toHaveLength(1); expect(al2.unreadCount()).toBe(1); expect(logs.join(' ')).toMatch(/malformed/);
    const h = new HistoryService(path.join(d, 'h.json')); h.record({ id: 'file-1-aaaa', name: 'x.exe', sha256: null }, a); const hj = JSON.parse(fs.readFileSync(path.join(d, 'h.json'), 'utf8')); hj.entries.push(null, 'x', { id: 1 }); fs.writeFileSync(path.join(d, 'h.json'), JSON.stringify(hj));
    expect(new HistoryService(path.join(d, 'h.json')).list()).toHaveLength(1);
  });
  it('alert de-duplication survives a restart', () => { const d = dir(); const a = fakeAssessment('CRITICAL', { inds: [['R1', 'HIGH', 't', 'SOCIAL_ENGINEERING']] }); const f = { id: 'file-1-aaaa', name: 'x.exe', sha256: 'h' }; new AlertService(path.join(d, 'a.json')).create(f, a); expect(new AlertService(path.join(d, 'a.json')).create(f, a)?.duplicate).toBe(true); });
  it('settings: wrong types, unknown keys and "enabled without provider" fall back to safe defaults', () => {
    const d = dir(); fs.writeFileSync(path.join(d, 'set.json'), JSON.stringify({ version: 1, security: { autoQuarantineCritical: 'yes', notifyCritical: 5, evil: 1 }, ai: { enabled: true, provider: 'none', model: '../../x' } }));
    const s = new SecuritySettingsStore(path.join(d, 'set.json')); expect(s.security().autoQuarantineCritical).toBe(false); expect(s.security().notifyCritical).toBe(true); expect(s.ai().enabled).toBe(false); expect(s.ai().model).toBe(''); expect(s.security()).not.toHaveProperty('evil');
    expect(s.setSecurity({ autoQuarantineCritical: 1 }).autoQuarantineCritical).toBe(false); expect(s.setSecurity({ autoQuarantineCritical: true }).autoQuarantineCritical).toBe(true);
  });
  it('settings: a missing or corrupt file gives defaults (auto-quarantine OFF, AI OFF)', () => { const d = dir(); fs.writeFileSync(path.join(d, 'c.json'), 'nope'); for (const f of ['missing.json', 'c.json']) { const s = new SecuritySettingsStore(path.join(d, f)); expect(s.security().autoQuarantineCritical).toBe(false); expect(s.ai().enabled).toBe(false); } });
  it('JsonStore: hundreds of back-to-back writes never leave a torn or temporary file', () => {
    const d = dir(); const f = path.join(d, 'j.json'); const j = new JsonStore<{ version: 1; n: number }>(f, () => ({ version: 1, n: 0 }), (x): x is { version: 1; n: number } => !!x && typeof x === 'object');
    for (let i = 1; i <= 300; i++) { j.data.n = i; j.save(); } expect(JSON.parse(fs.readFileSync(f, 'utf8')).n).toBe(300); expect(fs.readdirSync(d).filter((n) => n.endsWith('.tmp'))).toEqual([]);
  });
  it('JsonStore: a failing write is logged, not thrown, and the old file stays valid', () => {
    const d = dir(); const f = path.join(d, 'j.json'); const logs: string[] = []; const j = new JsonStore<{ version: 1; n: number }>(f, () => ({ version: 1, n: 1 }), (x): x is { version: 1; n: number } => !!x, (m) => logs.push(m)); j.save();
    fs.rmSync(f); fs.mkdirSync(f); j.data.n = 2; expect(() => j.save()).not.toThrow(); expect(logs.join(' ')).toMatch(/Could not save/);
  });
  it('atomic writers replace the file completely, also under concurrency', async () => {
    const d = dir(); const f = path.join(d, 'x.json'); await Promise.all(Array.from({ length: 25 }, (_, i) => atomicWriteFile(f, JSON.stringify({ i, pad: 'x'.repeat(5000) })))); expect(() => JSON.parse(fs.readFileSync(f, 'utf8'))).not.toThrow();
    atomicWriteFileSync(f, '{"a":1}'); expect(JSON.parse(fs.readFileSync(f, 'utf8'))).toEqual({ a: 1 }); expect(fs.readdirSync(d)).toEqual(['x.json']);
  });
  it('a corrupt secrets file never throws; the key is simply "not configured"', () => {
    const d = dir(); fs.writeFileSync(path.join(d, 'sec.json'), 'garbage'); const s = new SecretStore(path.join(d, 'sec.json'), { isAvailable: () => true, encrypt: (p) => Buffer.from(p), decrypt: (b) => b.toString() });
    expect(s.has('ai-api-key')).toBe(false); expect(s.get('ai-api-key')).toBeNull(); s.set('ai-api-key', 'sk-valid-key-1234'); expect(s.get('ai-api-key')).toBe('sk-valid-key-1234');
  });
  it('secrets are refused (never stored in plaintext) when OS encryption is unavailable', () => { const d = dir(); const s = new SecretStore(path.join(d, 'sec.json'), { isAvailable: () => false, encrypt: () => Buffer.alloc(0), decrypt: () => '' }); expect(() => s.set('ai-api-key', 'sk-valid-key-1234')).toThrow(/not available/); expect(fs.existsSync(path.join(d, 'sec.json'))).toBe(false); });
});
