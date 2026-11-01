import { useState } from 'react';
import RiskBadge from '../components/common/RiskBadge';
import { protectionService } from '../services/protectionService';
import { useLiveState } from '../hooks';
import LoadState from '../components/common/LoadState';
import { cleanName, formatBytes, formatDate, riskFromStatus } from '../utils/format';
import type { QuarantinedFile } from '../types/phase6';

type Dlg = { kind: 'restore' | 'delete'; q: QuarantinedFile; fallback?: boolean } | null;

/** Quarantined files are untrusted: nothing here previews, opens or runs them. Restore and delete require explicit confirmation. */
export default function Quarantine({ onOpenFile }: { onOpenFile?: (fileId: string) => void }) {
  const ql = useLiveState(protectionService.quarantine, [] as QuarantinedFile[]); const items = ql.data;
  const [dlg, setDlg] = useState<Dlg>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string; offerFallback?: QuarantinedFile } | null>(null);
  const [busy, setBusy] = useState(false);
  const active = items.filter((q) => q.state === 'QUARANTINED'); const past = items.filter((q) => q.state !== 'QUARANTINED');
  const go = async () => {
    if (!dlg) return; setBusy(true);
    const r = dlg.kind === 'restore' ? await protectionService.restore(dlg.q.id, true, dlg.fallback) : await protectionService.remove(dlg.q.id, true);
    setBusy(false); const q = dlg.q; setDlg(null);
    if (r.ok) setMsg({ ok: true, text: dlg.kind === 'restore' ? 'File restored. SafePeek did not open or run it, and it is being re-analyzed.' : 'Quarantined copy permanently deleted.' });
    else setMsg({ ok: false, text: r.error, offerFallback: r.code === 'ORIGINAL_FOLDER_MISSING' ? q : undefined });
  };
  return (
    <div className="page">
      {!protectionService.available() && <div className="banner banner-info">Quarantine is available in the desktop app.</div>}
      <div className="banner banner-info">Files here were moved into SafePeek's protected quarantine folder. They are never opened, previewed or executed.</div>
      <LoadState state={ql} what="quarantine" />
      {msg && <div className={msg.ok ? 'banner banner-info' : 'banner banner-warn'} role="status">{msg.text}{msg.offerFallback && <> <button className="btn" onClick={() => setDlg({ kind: 'restore', q: msg.offerFallback!, fallback: true })}>Restore to Downloads instead</button></>}</div>}
      {active.length > 0 && (
        <table className="table fixed" aria-label="Quarantine">
          <thead><tr><th style={{ width: '20%' }}>Filename</th><th style={{ width: '22%' }}>Original location</th><th style={{ width: '12%' }}>Risk</th><th style={{ width: '13%' }}>Quarantined at</th><th style={{ width: '14%' }}>Reason</th><th style={{ width: '19%' }}>Actions</th></tr></thead>
          <tbody>{active.map((q) => (
            <tr key={q.id}>
              <td className="cell-name"><strong>{cleanName(q.originalName)}</strong><small>{formatBytes(q.size)} · {q.detectedType}</small></td>
              <td className="cell-name"><small style={{ color: 'inherit' }}>{cleanName(q.originalPath)}</small></td>
              <td><RiskBadge level={riskFromStatus(q.riskStatus)} score={q.riskScore} /></td>
              <td>{formatDate(q.quarantinedAt)}{q.automatic && <small>Automatic</small>}</td>
              <td className="cell-name">{q.reason}</td>
              <td><div className="action-groups">
                <div className="action-group">{onOpenFile && !!q.fileId && <button className="btn" onClick={() => onOpenFile(q.fileId!)}>Review</button>}</div>
                <div className="action-group"><button className="btn" onClick={() => setDlg({ kind: 'restore', q })}>Restore…</button></div>
                <div className="action-group danger-zone"><button className="btn danger" onClick={() => setDlg({ kind: 'delete', q })}>Delete permanently…</button></div>
              </div></td>
            </tr>
          ))}</tbody>
        </table>
      )}
      {!ql.loading && !ql.error && active.length === 0 && <div className="empty"><strong>Nothing in quarantine</strong><span>Files you quarantine (or that SafePeek quarantines for you) appear here and can be restored or permanently deleted.</span></div>}
      {past.length > 0 && <details><summary className="muted">History ({past.length})</summary><ul className="list">{past.map((q) => <li key={q.id}><span>{cleanName(q.originalName)}</span><small className="muted">{q.state === 'RESTORED' ? `Restored ${formatDate(q.restoredAt ?? '')}` : `Deleted ${formatDate(q.deletedAt ?? '')}`}</small></li>)}</ul></details>}
      {dlg && (
        <div className="modal" role="alertdialog" aria-modal="true" aria-labelledby="qdlg" onKeyDown={(e) => { if (e.key === 'Escape') setDlg(null); }}><div className="modal-box danger">
          {dlg.kind === 'delete' ? <><h3 id="qdlg">Permanently delete this file?</h3><p>{cleanName(dlg.q.originalName)}</p><p><strong>This action cannot be undone.</strong> Only the quarantined copy is deleted.</p></>
            : <><h3 id="qdlg">Warning</h3>{['SUSPICIOUS', 'HIGH_RISK', 'CRITICAL'].includes(dlg.q.riskStatus) && <p>This file was previously identified as {dlg.q.riskStatus === 'CRITICAL' ? 'critical risk' : dlg.q.riskStatus === 'HIGH_RISK' ? 'high risk' : 'suspicious'} ({dlg.q.riskScore}/100).</p>}
              <p>Restoring it will place it back in {dlg.fallback ? 'your Downloads folder' : 'its original location'}. SafePeek will not open or run it.</p><p>Are you sure?</p></>}
          <div className="row-btns"><button className="btn primary" autoFocus onClick={() => setDlg(null)}>Cancel</button><button className="btn danger" disabled={busy} onClick={go}>{dlg.kind === 'delete' ? 'Delete permanently' : 'Restore'}</button></div>
        </div></div>
      )}
    </div>
  );
}
