import { useState } from 'react';
import RiskBadge from '../components/common/RiskBadge';
import Card from '../components/common/Card';
import { protectionService } from '../services/protectionService';
import { useLiveState } from '../hooks';
import LoadState from '../components/common/LoadState';
import { cleanName, relativeTime, severityLabel, severityRisk } from '../utils/format';
import type { AlertSeverity, SecurityAlert } from '../types/phase6';

type State = 'active' | 'unread' | 'dismissed' | 'all';
const SEVS: (AlertSeverity | 'ALL')[] = ['ALL', 'CRITICAL', 'HIGH', 'WARNING', 'INFO'];

export default function Alerts({ onOpenFile }: { onOpenFile: (fileId: string, alertId?: string) => void }) {
  const [state, setState] = useState<State>('active');
  const [sev, setSev] = useState<AlertSeverity | 'ALL'>('ALL');
  const [msg, setMsg] = useState<string | null>(null);
  const al = useLiveState(() => protectionService.alerts(state, sev === 'ALL' ? undefined : sev), [] as SecurityAlert[], [state, sev]); const alerts = al.data;
  const [confirm, setConfirm] = useState<SecurityAlert | null>(null);
  const quarantine = async (a: SecurityAlert) => { setConfirm(null); const r = await protectionService.quarantineFile(a.fileId); setMsg(r.ok ? `${cleanName(a.fileName)} moved to quarantine.` : r.error); };
  return (
    <div className="page">
      {!protectionService.available() && <div className="banner banner-info">Alerts are available in the desktop app.</div>}
      <div className="filters" role="group" aria-label="Filter alerts">
        {SEVS.map((s) => <button key={s} className={sev === s ? 'chip on' : 'chip'} aria-pressed={sev === s} onClick={() => setSev(s)}>{s === 'ALL' ? 'All severities' : severityLabel[s]}</button>)}
        <span style={{ flex: 1 }} />
        {(['active', 'unread', 'dismissed', 'all'] as State[]).map((s) => <button key={s} className={state === s ? 'chip on' : 'chip'} onClick={() => setState(s)}>{s[0].toUpperCase() + s.slice(1)}</button>)}
        <button className="btn" onClick={() => protectionService.markAllRead()}>Mark all read</button>
      </div>
      <LoadState state={al} what="alerts" />
      {msg && <div className="banner banner-info" role="status">{msg}</div>}
      <Card title="Security alerts">
        {!al.loading && !al.error && alerts.length === 0 && <div className="empty"><strong>No alerts</strong><span>SafePeek raises an alert when a file is rated Suspicious, High risk or Critical.</span></div>}
        {alerts.map((a) => (
          <div key={a.id} className={`alert-row ${a.readAt ? 'read' : 'unread'}`}>
            <RiskBadge level={severityRisk[a.severity]} score={a.score} />
            <div>
              <strong>{!a.readAt && <span className="unread-dot" aria-label="Unread" />}{cleanName(a.fileName)}</strong>
              <small>{a.title} · {relativeTime(a.createdAt)} · {a.readAt ? 'Read' : 'Unread'}{a.dismissedAt ? ' · Dismissed' : ''}</small>
              <small className="muted">{a.message}</small>
              {a.actionTaken && <small>Action taken: <b>{a.actionTaken}</b></small>}
            </div>
            <div className="action-groups">
              <div className="action-group" role="group" aria-label="Alert actions">
                <button className="btn primary" onClick={() => onOpenFile(a.fileId, a.id)}>Review</button>
                {!a.readAt && <button className="btn" onClick={() => protectionService.markRead(a.id)}>Mark as read</button>}
                {!a.dismissedAt && <button className="btn" onClick={() => protectionService.dismiss(a.id)}>Dismiss</button>}
              </div>
              {!a.actionTaken && !a.dismissedAt && <div className="action-group danger-zone" role="group" aria-label="Protective action"><button className="btn danger" onClick={() => setConfirm(a)}>Quarantine…</button></div>}
            </div>
          </div>
        ))}
      </Card>
      {confirm && (
        <div className="modal" role="alertdialog" aria-modal="true" aria-labelledby="aq-t" onKeyDown={(e) => { if (e.key === 'Escape') setConfirm(null); }}><div className="modal-box danger">
          <h3 id="aq-t">Move this file to quarantine?</h3>
          <p>{cleanName(confirm.fileName)} will be moved into SafePeek's protected quarantine folder. It will not be opened or deleted, and you can restore it later.</p>
          <div className="row-btns"><button className="btn" autoFocus onClick={() => setConfirm(null)}>Cancel</button><button className="btn danger" onClick={() => quarantine(confirm)}>Quarantine</button></div>
        </div></div>
      )}
    </div>
  );
}
