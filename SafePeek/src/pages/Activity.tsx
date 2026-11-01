import RiskBadge from '../components/common/RiskBadge';
import { fileService } from '../services/fileService';
import { storageService } from '../services/storageService';
import { useLiveState } from '../hooks';
import LoadState from '../components/common/LoadState';
import { cleanName, formatDate } from '../utils/format';

export default function Activity() {
  const al = useLiveState(fileService.listActivity, [] as Awaited<ReturnType<typeof fileService.listActivity>>); const rows = al.data;
  return (
    <div className="page">
      {storageService.repository.isDemo && <div className="banner banner-info">Demo entries only (agent not available here).</div>}
      <LoadState state={al} what="activity" />
      <table className="table fixed" aria-label="Activity">
        <thead><tr><th>Time</th><th>File / folder</th><th>Event</th><th>Risk</th><th>Status</th></tr></thead>
        <tbody>{rows.map((r) => (
          <tr key={r.id}><td>{formatDate(r.timestamp)}</td><td className="cell-name">{cleanName(r.fileName)}</td><td>{r.event}</td><td><RiskBadge level={r.riskLevel} /></td><td>{r.status}</td></tr>
        ))}</tbody>
      </table>
      {!al.loading && !al.error && rows.length === 0 && <div className="empty"><strong>No activity yet</strong><span>Detections, analyses and your actions are listed here.</span></div>}
    </div>
  );
}
