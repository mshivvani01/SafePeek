import { useState } from 'react';
import RiskBadge from '../components/common/RiskBadge';
import { protectionService } from '../services/protectionService';
import { useLiveState } from '../hooks';
import LoadState from '../components/common/LoadState';
import { cleanName, formatDate, riskFromStatus } from '../utils/format';
import type { ThreatHistoryEntry } from '../types/phase6';

export default function ThreatHistory({ onOpenFile }: { onOpenFile: (fileId: string) => void }) {
  const hl = useLiveState(protectionService.history, [] as ThreatHistoryEntry[]); const rows = hl.data;
  const [q, setQ] = useState('');
  const shown = rows.filter((r) => !q || r.fileName.toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="page">
      <LoadState state={hl} what="threat history" />
      <div className="field"><input aria-label="Search history" placeholder="Search by file name" value={q} onChange={(e) => setQ(e.target.value)} /></div>
      <table className="table fixed" aria-label="Threat history">
        <thead><tr><th>Date</th><th>File</th><th>Risk</th><th>Score</th><th>Action</th></tr></thead>
        <tbody>{shown.map((r) => (
          <tr key={r.id}><td>{formatDate(r.assessedAt)}</td><td className="cell-name"><button className="linkbtn" onClick={() => onOpenFile(r.fileId)}>{cleanName(r.fileName)}</button></td><td><RiskBadge level={riskFromStatus(r.status)} /></td><td>{r.status === 'UNKNOWN' ? '—' : r.score}</td><td>{r.action}{r.actionAt && <small>{formatDate(r.actionAt)}</small>}</td></tr>
        ))}</tbody>
      </table>
      {!hl.loading && !hl.error && shown.length === 0 && <div className="empty"><strong>No assessments recorded yet</strong><span>Every rating SafePeek gives a file is kept here.</span></div>}
    </div>
  );
}
