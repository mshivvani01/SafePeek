import { useMemo } from 'react';
import Card from '../components/common/Card';
import RiskBadge from '../components/common/RiskBadge';
import StatCard from '../components/dashboard/StatCard';
import LoadState from '../components/common/LoadState';
import { fileService } from '../services/fileService';
import { monitoringService } from '../services/monitoringService';
import { storageService } from '../services/storageService';
import { protectionService } from '../services/protectionService';
import { useLive, useLiveState } from '../hooks';
import { cleanName, relativeTime, riskFromStatus, severityRisk } from '../utils/format';
import type { FileRecord } from '../types/file';
import type { SecurityAlert } from '../types/phase6';

/** Every number here is derived from persisted results; nothing is estimated or invented. */
export default function Dashboard({ onOpenFile, onNavigate }: { onOpenFile?: (id: string) => void; onNavigate?: (page: 'alerts' | 'files' | 'quarantine' | 'settings') => void }) {
  const fl = useLiveState(fileService.list, [] as FileRecord[]); const files = fl.data;
  const al = useLiveState(() => protectionService.alerts('active'), [] as SecurityAlert[]); const alerts = al.data;
  const activity = useLive(fileService.listActivity, []);
  const st = useLive(monitoringService.status, null);
  const ps = useLive(protectionService.status, null);
  const demo = storageService.repository.isDemo;
  const m = useMemo(() => {
    const count = (...s: string[]) => files.filter((f) => !!f.threatStatus && s.includes(f.threatStatus) && f.quarantineState !== 'QUARANTINED').length;
    const assessed = files.filter((f) => !!f.threatStatus && f.threatStatus !== 'UNKNOWN');
    const recent = files.filter((f) => !!f.threatStatus && !['SAFE', 'UNKNOWN'].includes(f.threatStatus)).sort((a, b) => (b.threatAnalyzedAt ?? '').localeCompare(a.threatAnalyzedAt ?? '')).slice(0, 5);
    return { scanned: assessed.length, suspicious: count('SUSPICIOUS'), high: count('HIGH_RISK'), critical: count('CRITICAL'), recent };
  }, [files]);
  const folders = st?.folders.filter((f) => f.enabled).length ?? 0;
  const headline = st?.active ? 'Monitoring is active' : st && !st.enabled ? 'Monitoring is paused' : 'Monitoring is not running';
  const sub = st?.active ? `Watching ${folders} folder${folders === 1 ? '' : 's'}. New files are analyzed automatically, on this device.` : st && !st.enabled ? 'New files will not be checked until you turn monitoring back on in Settings.' : 'SafePeek cannot see new files right now.';
  return (
    <div className="page">
      <LoadState state={fl} what="dashboard data" />
      {demo && <div className="banner banner-info">Preview mode: sample data shown because the SafePeek desktop agent is not running.</div>}
      {st?.lastError && <div className="banner banner-warn" role="alert">{st.lastError}</div>}
      <div className="hero"><h2>{headline}</h2><p>{sub}</p></div>
      <div className="stats6" aria-label="Summary">
        <StatCard label="Files scanned" value={m.scanned} tone="neutral" icon="🔎" />
        <StatCard label="Suspicious" value={m.suspicious} tone="warn" icon="🟠" />
        <StatCard label="High risk" value={m.high} tone="danger" icon="🔴" />
        <StatCard label="Critical" value={m.critical} tone="critical" icon="⛔" />
        <StatCard label="Quarantined" value={ps?.quarantinedCount ?? 0} tone="accent" icon="🔒" />
        <StatCard label="Unread alerts" value={ps?.unreadAlerts ?? 0} tone="warn" icon="🔔" />
      </div>
      <div className="grid2">
        <Card title="Recent detections" aside={onNavigate && <button className="linkbtn" onClick={() => onNavigate('files')}>All files</button>}>
          {m.recent.length === 0 && <div className="empty"><strong>No risky files detected</strong><span>Files rated Low risk or above show up here.</span></div>}
          <ul className="list">{m.recent.map((f) => (
            <li key={f.id}><div><button className="linkbtn" onClick={() => onOpenFile?.(f.id)}>{cleanName(f.name)}</button><small>{f.threatTopReason ?? f.threatHeadline} · {f.threatAnalyzedAt ? relativeTime(f.threatAnalyzedAt) : ''}</small></div><RiskBadge level={riskFromStatus(f.threatStatus!)} score={f.threatScore} /></li>
          ))}</ul>
        </Card>
        <Card title="Monitoring status">
          <div className={`protect ${ps?.protectionOn ? 'on' : 'off'}`}><i className="dot" /><div><strong>Protection: {ps?.protectionOn ? 'ON' : 'OFF'}</strong><small>{ps?.protectionOn ? (ps.autoQuarantineCritical ? 'CRITICAL files are quarantined automatically (you can restore them).' : 'Risky files raise an alert. Nothing is moved unless you choose.') : 'New files are not being checked.'}</small></div></div>
          <ul className="list">
            <li><strong>File monitoring</strong><span className={st?.active ? 'badge badge-safe' : 'badge badge-pending'}>{st?.active ? 'Active' : st && !st.enabled ? 'Paused' : 'Unavailable'}</span></li>
            <li><strong>Protected folders</strong><span className="muted">{folders}</span></li>
            <li><strong>Last detection</strong><span className="muted">{st?.lastDetection ? `${cleanName(st.lastDetection.fileName)} · ${relativeTime(st.lastDetection.at)}` : '—'}</span></li>
            <li><strong>Analysis</strong><span className="muted">Local only</span></li>
          </ul>
        </Card>
        <Card title="Recent alerts" aside={onNavigate && <button className="linkbtn" onClick={() => onNavigate('alerts')}>All alerts</button>}>
          {alerts.length === 0 && <div className="empty"><strong>No active alerts</strong><span>SafePeek alerts you when a file is Suspicious or worse.</span></div>}
          <ul className="list">{alerts.slice(0, 5).map((a) => (
            <li key={a.id}><div><button className="linkbtn" onClick={() => onOpenFile?.(a.fileId)}>{!a.readAt && <span className="unread-dot" aria-label="Unread" />}{cleanName(a.fileName)}</button><small>{a.title} · {relativeTime(a.createdAt)}</small></div><RiskBadge level={severityRisk[a.severity]} score={a.score} /></li>
          ))}</ul>
        </Card>
        <Card title="Recent activity">
          {activity.length === 0 && <div className="empty"><strong>Nothing yet</strong><span>Copy a file into a protected folder to see it appear.</span></div>}
          <ul className="list">{activity.slice(0, 6).map((a) => (
            <li key={a.id}><div><strong className="cell-name">{cleanName(a.fileName)}</strong><small>{a.event} · {relativeTime(a.timestamp)}</small></div><RiskBadge level={a.riskLevel} /></li>
          ))}</ul>
        </Card>
      </div>
    </div>
  );
}
