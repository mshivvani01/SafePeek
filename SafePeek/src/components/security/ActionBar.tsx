import { useEffect, useState } from 'react';
import { protectionService } from '../../services/protectionService';
import type { OpenInfo } from '../../types/phase6';
import type { FileRecord } from '../../types/file';
import { cleanName } from '../../utils/format';

/** Safe actions for one file. Opening a risky file is never one click: "Open Anyway" opens a confirmation first. Nothing here ever runs a file by itself. */
export default function ActionBar({ file }: { file: FileRecord }) {
  const [info, setInfo] = useState<OpenInfo | null>(null);
  const [dlg, setDlg] = useState<'open' | 'quarantine' | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const quarantined = file.quarantineState === 'QUARANTINED';
  useEffect(() => { setMsg(null); setDlg(null); protectionService.openInfo(file.id).then(setInfo).catch(() => undefined); }, [file.id, file.threatStatus, quarantined]);
  const done = (r: { ok: boolean; error?: string; message?: string }, ok: string) => setMsg({ ok: r.ok, text: r.ok ? (r.message ?? ok) : (r as { error: string }).error });
  const run = async (fn: () => Promise<{ ok: boolean }>, ok: string) => { setBusy(true); try { done((await fn()) as never, ok); } finally { setBusy(false); setDlg(null); } };
  const risky = !!info?.requiresConfirmation;
  const hi = file.threatStatus === 'HIGH_RISK' || file.threatStatus === 'CRITICAL';
  if (!protectionService.available()) return <small className="muted">File actions are available in the desktop app.</small>;
  return (
    <div className="actions" aria-label="File actions">
      {quarantined ? <span className="badge badge-critical">🔒 In quarantine — manage it on the Quarantine page</span> : (
        <div className="action-groups">
          <div className="action-group" role="group" aria-label="Review actions"><span className="group-label">Review</span>
            <button className="btn" disabled={busy} onClick={() => run(() => protectionService.review(file.id), 'Marked as reviewed.')}>Mark reviewed</button>
            <button className="btn" disabled={busy} onClick={() => run(() => protectionService.rescan(file.id), 'Rescan started (static → content → threat analysis).')}>Rescan</button>
            <button className="btn" disabled={busy} onClick={() => run(() => protectionService.reveal(file.id), 'Opened the containing folder.')}>Show in folder</button>
            <button className="btn" disabled={busy} onClick={() => run(() => protectionService.copyPath(file.id), 'Path copied.')}>Copy path</button>
          </div>
          <div className="action-group" role="group" aria-label="Protect"><span className="group-label">Protect</span>
            <button className={hi ? 'btn danger' : 'btn'} disabled={busy} onClick={() => setDlg('quarantine')}>Quarantine</button>
          </div>
          <div className={`action-group${risky ? ' danger-zone' : ''}`} role="group" aria-label="Open file"><span className="group-label">Open</span>
            {risky ? <button className="btn warn" disabled={busy} onClick={() => setDlg('open')}>Open anyway…</button> : <button className="btn" disabled={busy} onClick={() => run(() => protectionService.open(file.id, false), 'Opened.')}>Open</button>}
          </div>
        </div>
      )}
      {msg && <div className={msg.ok ? 'banner banner-info' : 'banner banner-warn'} role="status">{msg.text}</div>}
      {dlg === 'open' && info && (
        <div className="modal" role="alertdialog" aria-modal="true" aria-labelledby="od-t"><div className="modal-box danger">
          <h3 id="od-t"><span aria-hidden="true">⚠️</span> {file.threatStatus === 'CRITICAL' ? 'This file has been classified as CRITICAL' : file.threatStatus === 'HIGH_RISK' ? 'This file has been classified as HIGH RISK' : file.threatStatus === 'SUSPICIOUS' ? 'This file looks suspicious' : 'This file could not be fully analyzed'}</h3>
          <p>{cleanName(info.fileName)}</p>
          {info.reasons.length > 0 && <><p>SafePeek detected:</p><ul className="reasons">{info.reasons.map((r, i) => <li key={i}>{cleanName(r)}</li>)}</ul></>}
          <p><strong>Opening this file may put your device or accounts at risk.</strong></p>
          <div className="row-btns"><button className="btn primary" autoFocus onClick={() => setDlg(null)}>Cancel</button><button className="btn danger" disabled={busy} onClick={() => run(() => protectionService.open(file.id, true), 'Opened after confirmation.')}>Open Anyway</button></div>
        </div></div>
      )}
      {dlg === 'quarantine' && (
        <div className="modal" role="alertdialog" aria-modal="true" aria-labelledby="qd-t"><div className="modal-box">
          <h3 id="qd-t">Move this file to quarantine?</h3>
          <p>{cleanName(file.name)} will be moved out of its current folder into SafePeek's protected quarantine folder. It will not be opened or deleted, and you can restore it later.</p>
          <div className="row-btns"><button className="btn" onClick={() => setDlg(null)}>Cancel</button><button className="btn danger" autoFocus disabled={busy} onClick={() => run(() => protectionService.quarantineFile(file.id), 'File moved to quarantine.')}>Quarantine</button></div>
        </div></div>
      )}
    </div>
  );
}
