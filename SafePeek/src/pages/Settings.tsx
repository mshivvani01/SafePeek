import { useEffect, useState, type ReactNode } from 'react';
import Card from '../components/common/Card';
import { defaultSettings, storageService } from '../services/storageService';
import { monitoringService } from '../services/monitoringService';
import { useLive } from '../hooks';
import { defaultSecurity, protectionService } from '../services/protectionService';
import { THEMES, loadTheme, saveTheme, type ThemePref } from '../utils/theme';
import type { AiSettingsView, SecuritySettings } from '../types/phase6';
import type { AppSettings } from '../types/scan';

function Toggle({ label, hint, consequence, checked, disabled, onChange }: { label: string; hint: string; consequence?: string; checked: boolean; disabled?: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="toggle"><span><strong>{label}</strong><small>{hint}</small>{consequence && <small className="consequence">{consequence}</small>}</span>
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} /></label>
  );
}
const SECTIONS = ['Monitoring', 'Notifications', 'Protection', 'AI Explanation', 'Privacy', 'Appearance', 'Advanced'] as const;
const slug = (s: string) => `settings-${s.toLowerCase().replace(/\s+/g, '-')}`;
const Section = ({ title, children }: { title: (typeof SECTIONS)[number]; children: ReactNode }) => <div id={slug(title)}><Card title={title}>{children}</Card></div>;

export default function Settings() {
  const [s, setS] = useState<AppSettings>(defaultSettings);
  const [msg, setMsg] = useState<string | null>(null);
  const [theme, setTheme] = useState<ThemePref>(loadTheme);
  const [version, setVersion] = useState('');
  const st = useLive(monitoringService.status, null);
  useEffect(() => { storageService.loadSettings().then(setS).catch(() => setMsg('Could not load saved preferences. Defaults are shown.')); window.safepeek?.getAppInfo?.().then((i) => setVersion((i as { version?: string })?.version ?? '')).catch(() => undefined); }, []);
  const update = (patch: Partial<AppSettings>) => { const n = { ...s, ...patch }; setS(n); storageService.saveSettings(n).then(() => setMsg('Preferences saved.')).catch(() => setMsg('Could not save preferences. Check that SafePeek can write to its data folder.')); };
  const add = async () => { const r = await monitoringService.addFolder(); setMsg(r?.error ?? (r?.ok ? 'Folder added.' : null)); };
  const test = async () => { const r = await monitoringService.createTestFile(); setMsg(r?.ok ? `Created ${r.name}. It should be detected in a few seconds.` : r?.error ?? 'Not available'); };
  const [sec, setSec] = useState<SecuritySettings>(defaultSecurity);
  const [ai, setAi] = useState<AiSettingsView | null>(null);
  const [key, setKey] = useState('');
  const ps = useLive(protectionService.status, null);
  useEffect(() => { protectionService.settings().then(setSec); protectionService.aiSettings().then(setAi); }, []);
  const updSec = (patch: Partial<SecuritySettings>) => { setSec({ ...sec, ...patch }); protectionService.saveSettings(patch).then((r) => { setSec(r); setMsg('Security settings saved.'); }).catch(() => setMsg('Could not save security settings. Please try again.')); };
  const updAi = (patch: Partial<AiSettingsView>) => protectionService.saveAiSettings(patch).then((r) => { if (r) setAi(r); });
  const saveKey = async () => { const r = await protectionService.setApiKey(key); setKey(''); setMsg(r.ok ? 'API key stored encrypted on this device.' : r.error ?? 'Could not store the key.'); setAi(await protectionService.aiSettings()); };
  const clearKey = async () => { await protectionService.clearApiKey(); setMsg('API key removed and AI explanation turned off.'); setAi(await protectionService.aiSettings()); };
  const off = !st;
  const protOn = !!ps?.protectionOn;
  const aiOn = !!ai?.enabled && ai.provider !== 'none';
  return (
    <div className="page narrow">
      <nav className="settings-nav" aria-label="Settings sections">{SECTIONS.map((x) => <a key={x} className="chip" href={`#${slug(x)}`} onClick={(e) => { e.preventDefault(); document.getElementById(slug(x))?.scrollIntoView({ block: 'start' }); }}>{x}</a>)}</nav>
      {msg && <div className="banner banner-info" role="status">{msg}</div>}

      <Section title="Monitoring">
        <Toggle label="Monitor protected folders" hint={st?.enabled ? 'Enabled. New files in protected folders are detected and analyzed automatically.' : 'Paused. New files will not be detected or analyzed.'} consequence={st && !st.enabled ? 'While monitoring is off, risky downloads are not checked.' : undefined} checked={!!st?.enabled} disabled={off} onChange={(v) => monitoringService.setEnabled(v)} />
        <div className="card-head" style={{ marginTop: 12 }}><h2>Protected folders</h2><button className="btn" onClick={add} disabled={off}>Add folder</button></div>
        <ul className="list">
          {st?.folders.map((f) => (
            <li key={f.id}>
              <div><strong>{f.label}</strong><small className="cell-name">{f.path}</small>{st.folderErrors[f.id] && <span className="folder-err">{st.folderErrors[f.id]}</span>}</div>
              <div className="row-actions">
                <label><input type="checkbox" checked={f.enabled} onChange={(e) => monitoringService.setFolderEnabled(f.id, e.target.checked)} /> Monitor</label>
                {!f.isDefault && <button className="btn" onClick={() => monitoringService.removeFolder(f.id)}>Remove</button>}
              </div>
            </li>
          ))}
          {off && <li><span className="muted">Monitoring settings are available in the desktop app.</span></li>}
        </ul>
      </Section>

      <Section title="Notifications">
        <Toggle label="File detection notifications" hint="Show a Windows notification when a new file is detected. Clicking it opens SafePeek; it never opens the file." checked={s.notifications} onChange={(v) => update({ notifications: v })} />
        <Toggle label="Critical alerts" hint="Notify when a file is rated CRITICAL." checked={sec.notifyCritical} onChange={(v) => updSec({ notifyCritical: v })} />
        <Toggle label="High-risk alerts" hint="Notify when a file is rated HIGH RISK." checked={sec.notifyHigh} onChange={(v) => updSec({ notifyHigh: v })} />
        <Toggle label="Suspicious alerts" hint="Notify when a file is rated SUSPICIOUS." checked={sec.notifySuspicious} onChange={(v) => updSec({ notifySuspicious: v })} />
        <Toggle label="Informational alerts" hint="Also create alerts for LOW RISK files. Off by default. Alerts for Suspicious and above are always kept on the Alerts page." checked={sec.notifyInformational} onChange={(v) => updSec({ notifyInformational: v })} />
      </Section>

      <Section title="Protection">
        <div className={`protect ${protOn ? 'on' : 'off'}`}><i className="dot" /><div><strong>Protection: {protOn ? 'ON' : 'OFF'}</strong><small>{protOn ? `SafePeek monitors protected folders${sec.autoQuarantineCritical ? ' and automatically quarantines files rated CRITICAL' : ' and alerts you to risky files. Automatic quarantine is off, so SafePeek will not move any file unless you tell it to'}.` : 'Monitoring is not active, so new files are not being checked. Turn monitoring on above.'}</small></div></div>
        <Toggle label="Automatically quarantine CRITICAL files" hint="Off by default. Only files rated CRITICAL are moved into SafePeek's quarantine folder. Nothing is ever deleted automatically, and you can restore any file." consequence={sec.autoQuarantineCritical ? 'A CRITICAL rating is heuristic. A legitimate file could be quarantined by mistake; restore it from the Quarantine page.' : undefined} checked={sec.autoQuarantineCritical} onChange={(v) => updSec({ autoQuarantineCritical: v })} />
        <Toggle label="Ask for confirmation before opening risky files" hint="Recommended. Suspicious, high-risk, critical and not-yet-analyzed files need an explicit “Open anyway”." consequence={!sec.requireConfirmHighRisk ? 'With this off, a risky file can be opened more easily. Executables and scripts still always ask.' : undefined} checked={sec.requireConfirmHighRisk} onChange={(v) => updSec({ requireConfirmHighRisk: v })} />
      </Section>

      <Section title="AI Explanation">
        <p><strong>AI explanation: {aiOn ? 'ON' : 'OFF'}</strong> · Provider: {ai && ai.provider !== 'none' ? ai.provider : 'None'} · API key: {ai?.keyConfigured ? 'Configured' : 'Not configured'}</p>
        <p className="muted">SafePeek always explains results locally, offline, with no account or key. This optional feature lets you ask an external AI provider to reword an explanation. When you press the button on a file and confirm, extracted metadata about the file (risk status, score, indicator titles) is sent to the provider you choose. Original files are never uploaded. File content can never change a file's rating. If the provider fails, SafePeek shows the local explanation.</p>
        {!ai && <p className="muted">Available in the desktop app.</p>}
        {ai && <>
          <div className="field"><label>Provider<br /><select value={ai.provider} onChange={(e) => updAi({ provider: e.target.value as AiSettingsView['provider'], enabled: e.target.value === 'none' ? false : ai.enabled })}><option value="none">None (local explanation only)</option><option value="anthropic">Anthropic (api.anthropic.com)</option><option value="openai">OpenAI (api.openai.com)</option></select></label></div>
          <div className="field"><label>Model<br /><input value={ai.model} placeholder="Model name" onChange={(e) => setAi({ ...ai, model: e.target.value })} onBlur={() => updAi({ model: ai.model })} /></label></div>
          <div className="field"><label>API key<br /><input type="password" autoComplete="off" value={key} placeholder={ai.keyConfigured ? '•••••••• (stored encrypted)' : 'Paste key'} onChange={(e) => setKey(e.target.value)} /></label>
            <div className="row-btns"><button className="btn" disabled={!key || !ai.secureStorageAvailable} onClick={saveKey}>Save key</button>{ai.keyConfigured && <button className="btn" onClick={clearKey}>Remove key</button>}</div>
            {!ai.secureStorageAvailable && <small className="muted">Secure storage is not available on this system, so keys cannot be saved.</small>}</div>
          <Toggle label="Allow AI explanation" hint="Off by default. Needs a provider, model and key." consequence={ai.enabled ? 'Data about files you explain is sent to the provider above, after you confirm each time.' : undefined} checked={ai.enabled} disabled={ai.provider === 'none'} onChange={(v) => updAi({ enabled: v })} />
          <Toggle label="Include the file name in what is sent" hint="Off by default." checked={ai.shareFileName} onChange={(v) => updAi({ shareFileName: v })} />
          <Toggle label="Include short evidence snippets from the file" hint="Off by default. Snippets may contain text from the document; they are sent as quoted, untrusted data." consequence={ai.shareEvidenceSnippets ? 'Short excerpts of the document text may leave this device.' : undefined} checked={ai.shareEvidenceSnippets} onChange={(v) => updAi({ shareEvidenceSnippets: v })} />
        </>}
      </Section>

      <Section title="Privacy">
        <p>SafePeek is local-first. Files are analyzed on this device and are never uploaded. SafePeek never visits links found in files. The only optional network feature is AI explanation (above), which is off by default and never sends the original file.</p>
        <p className="muted">Your results, alerts and quarantine live in SafePeek's data folder on this PC. Removing SafePeek's data folder removes them.</p>
      </Section>

      <Section title="Appearance">
        <div className="field"><label>Theme<br /><select value={theme} onChange={(e) => { const v = e.target.value as ThemePref; setTheme(v); saveTheme(v); }}>{THEMES.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
          <small className="muted">Changes how SafePeek looks only. Risk is always shown with an icon and a text label as well as color.</small></div>
      </Section>

      <Section title="Advanced">
        <Toggle label="Start SafePeek when I sign in to Windows" hint="Runs SafePeek in the background after sign-in so new downloads are checked from the start." consequence="Only applies to the installed app, not to a development build." checked={s.startWithWindows} onChange={(v) => update({ startWithWindows: v })} />
        <div className="card-head" style={{ marginTop: 12 }}><div><h2>Self-test</h2><small className="muted">Creates one harmless text file in your first monitored folder so you can watch SafePeek detect it.</small></div><button className="btn" onClick={test} disabled={off}>Create test file</button></div>
      </Section>

      <Card title="About SafePeek"><p><strong>SafePeek</strong>{version ? ` · Version ${version}` : ''}</p><p className="muted">Know what's inside before you open it.</p><p className="muted">SafePeek is a defensive analysis assistant. It does not guarantee that every malicious file will be detected and does not replace antivirus, EDR or a sandbox.</p></Card>
    </div>
  );
}
