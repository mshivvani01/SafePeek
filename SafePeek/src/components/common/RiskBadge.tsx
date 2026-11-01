import type { RiskLevel } from '../../types/threat';
import { RISK_META } from '../../utils/format';

/** Risk is always icon + text (+ optional score / explanation), never color alone. */
export default function RiskBadge({ level, score, tagline }: { level: RiskLevel | null; score?: number | null; tagline?: boolean }) {
  if (!level) return <span className="muted">—</span>;
  const m = RISK_META[level];
  return (
    <span className="riskbadge">
      <span className={`badge badge-${level}`}><span aria-hidden="true">{m.icon}</span> {m.label}{typeof score === 'number' && level !== 'unknown' ? <span className="badge-score"> · {score}</span> : null}</span>
      {tagline && <small>{m.tagline}</small>}
    </span>
  );
}
