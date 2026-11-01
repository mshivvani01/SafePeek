import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(__dirname, '..');
const walk = (d: string): string[] => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]));
/** Source with comments removed, so the checks look at code only. */
const read = (f: string) => fs.readFileSync(f, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`])\/\/.*$/gm, '$1');

describe('Electron boundary (static checks over the source)', () => {
  const preload = read(path.join(root, 'electron/preload.ts'));
  it('the renderer never imports Node/Electron APIs', () => {
    for (const f of walk(path.join(root, 'src')).filter((x) => /\.tsx?$/.test(x))) { const s = read(f); expect(s, f).not.toMatch(/from ['"](node:|fs|path|child_process|electron|os)['"]|require\(/); expect(s, f).not.toMatch(/dangerouslySetInnerHTML|\.innerHTML|\beval\(|new Function\(/); }
  });
  it('preload exposes only named functions (no raw ipcRenderer / shell / fs) and every Phase 6 call passes ids and booleans only', () => {
    expect(preload).toContain('contextBridge.exposeInMainWorld'); expect(preload).not.toMatch(/exposeInMainWorld\('safepeek',\s*\{[^}]*ipcRenderer\s*[,}]/); expect(preload).not.toMatch(/\bshell\b|child_process|require\('fs'\)/);
    for (const m of preload.matchAll(/(quarantineFile|restoreQuarantined|deleteQuarantined|openFile|openFileLocation|copyFilePath|rescanFile|markFileReviewed|getOpenInfo): \(([^)]*)\)/g)) expect(m[2], m[1]).not.toMatch(/path|dest|target|folder/i);
  });
  it('main IPC validates ids with a strict pattern and requires confirmation flags to be exactly true', () => {
    const ipc = read(path.join(root, 'electron/ipc/index.ts')); expect(ipc).toContain('idOf'); expect(read(path.join(root, 'electron/ipc/validate.ts'))).toContain('ID_RE'); expect(ipc).toMatch(/confirmed === true/); expect(ipc).not.toMatch(/ipcMain\.handle\('(quarantine|files):[^']*', async? \(_e, [^)]*(path|dest)/i);
    expect(ipc).toMatch(/quarantinePath: _p/); // the internal vault path is stripped before it reaches the renderer
  });
  it('BrowserWindow keeps contextIsolation + sandbox and no nodeIntegration', () => { const m = read(path.join(root, 'electron/main.ts')); expect(m).toMatch(/contextIsolation: true/); expect(m).toMatch(/nodeIntegration: false/); expect(m).toMatch(/sandbox: true/); });
  it('network access exists only in the optional explanation service; the threat/content/analysis engines stay offline', () => {
    for (const f of walk(path.join(root, 'electron')).filter((x) => x.endsWith('.ts'))) { const s = read(f); if (!/electron\/(ai\/explanationService|protection\/protectionService)/.test(f.replace(/\\/g, '/'))) expect(s, f).not.toMatch(/\bfetch\(|XMLHttpRequest|from 'node:https?'|net\.request/); }
    const ai = read(path.join(root, 'electron/ai/explanationService.ts')); expect(ai).toMatch(/providerHost/); expect(ai).not.toMatch(/createReadStream|getFiles|\.path\b/); // it only reads its own explanation cache, never user files or file paths
    for (const f of ['threat', 'content', 'analysis'].flatMap((d) => walk(path.join(root, 'electron', d)))) expect(read(f), f).not.toMatch(/child_process|\bshell\./);
  });
  it('the explanation modules never touch the original file', () => { for (const f of walk(path.join(root, 'electron/ai'))) { const s = read(f); if (!f.endsWith('secretStore.ts') && !f.endsWith('explanationService.ts')) expect(s, f).not.toMatch(/node:fs/); } });
  it('the only code that launches files is ProtectionService.openFile via the injected system hook', () => {
    for (const f of walk(path.join(root, 'electron')).filter((x) => x.endsWith('.ts'))) { const s = read(f); if (!f.endsWith('main.ts')) expect(s, f).not.toMatch(/shell\.openPath|child_process|\bspawn\(|\bexecFile?\(|\bexecSync\(/); }
    expect(read(path.join(root, 'electron/main.ts'))).toMatch(/openPath: \(p\) => shell\.openPath\(p\)/);
    const prot = read(path.join(root, 'electron/protection/protectionService.ts')); expect((prot.match(/system\.openPath\(/g) ?? []).length).toBe(1);
  });
  it('the UI never labels AI as the detector', () => { for (const f of walk(path.join(root, 'src')).filter((x) => /\.tsx$/.test(x))) expect(read(f), f).not.toMatch(/AI detected|detected by AI|AI-detected/i); });
  it('the API key is never written to logs or sent to the renderer', () => {
    const ipc = read(path.join(root, 'electron/ipc/index.ts')); expect(ipc).not.toMatch(/secrets\.get\(/); for (const f of walk(path.join(root, 'electron/ai'))) expect(read(f), f).not.toMatch(/log\([^)]*\bkey\b/);
  });
});
