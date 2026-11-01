import { useEffect, useState } from 'react';
import type { FileRecord } from '../../types/file';
import type { ThreatAssessment } from '../../types/threat';
import Card from '../common/Card';
import { threatService } from '../../services/fileService';
import { originText, categoryLabel, coverageLabel, recommendationLabel, severityTone, threatStatusLabel, threatStatusToRisk, RISK_META } from '../../utils/format';

export function useThreat(id: string, status?: string): ThreatAssessment | null {
  const [t, setT] = useState<ThreatAssessment | null>(null);
  useEffect(() => {
    let on = true; setT(null);
    if (status === 'COMPLETED' || status === 'INCOMPLETE') threatService.get(id).then((r) => { if (on) setT(r); }).catch(() => undefined);
    return () => { on = false; };
  }, [id, status]);
  return t;
}
const cov = (v: string) => (v === 'COMPLETE' ? 'badge badge-safe' : v === 'PENDING' ? 'badge badge-unknown' : 'badge badge-suspicious');

/** Phase 5: risk status, reasons, indicators with evidence, coverage and recommendations. All values come from the persisted ThreatAssessment (rendered as React text nodes only). */
export default function ThreatPanel({ file, section = 'assessment', visualNote }: { file: FileRecord; section?: 'assessment' | 'recommendation'; visualNote?: string }) {
  const t = useThreat(file.id, file.threatAnalysisStatus);
  const st = file.threatAnalysisStatus ?? 'NOT_STARTED';
  const [showAll, setShowAll] = useState(false);
  if (!file.analysis) return null;
  if (section === 'recommendation') {
    if (!t || t.recommendations.length === 0) return <p className="muted">A recommendation appears once the threat analysis finishes.</p>;
    return (
      <>
        <ul className="list">{t.recommendations.map((r, i) => <li key={i}><div><strong>{recommendationLabel[r.action]} — {r.title}</strong><small>{r.description}</small></div></li>)}</ul>
        <small className="muted">SafePeek never opens, runs or deletes files automatically. It moves a file to quarantine only if you choose to, or if you enable automatic quarantine for CRITICAL files.</small>
      </>
    );
  }
  if (!t) {
    return (
      <Card title="Threat assessment">
        <p className="muted">{st === 'FAILED' ? 'Threat analysis failed for this file. Re-run it below.' : st === 'ANALYZING' ? 'Threat analysis in progress…' : 'Threat analysis starts after static and content analysis finish.'}</p>
        <small className="muted">Static: {file.analysisStatus} · Content: {file.contentStatus ?? 'NOT_STARTED'} · Threat: {st}</small>
      </Card>
    );
  }
  const risk = threatStatusToRisk[t.status];
  const real = t.indicators.filter((i) => i.severity !== 'INFO'); const info = t.indicators.filter((i) => i.severity === 'INFO');
  const shown = showAll ? real : real.slice(0, 8);
  return (
    <>
      <Card title="What SafePeek found">
        <div className="risk-hero">
          <div className="risk-top">
            <span className={`risk-big badge badge-${risk}`}><span aria-hidden="true">{RISK_META[risk].icon}</span> {threatStatusLabel[t.status].toUpperCase()}</span>
            {t.status !== 'UNKNOWN' && <span className="score">Risk score: <b>{t.score}</b>/100</span>}
            <span className="score">Confidence: <b>{t.confidence}</b>% ({t.confidenceLevel.toLowerCase()})</span>
          </div>
          {t.status !== 'UNKNOWN' && <div className="bar" title="Heuristic risk score"><i style={{ width: `${t.score}%` }} /></div>}
          <p className="lead">{t.headline}</p>
          {!t.analysisComplete && <div className="banner banner-warn">Analysis incomplete — the file could not be fully inspected. {t.status === 'UNKNOWN' || real.length === 0 ? 'No malicious indicators were detected in the available analysis, but that is not reassuring on its own.' : ''}</div>}
          <small className="muted disclaimer">The risk score is a heuristic measure of how many and how severe the suspicious indicators are. It is not a probability of malware. Confidence describes how complete the analysis was, not how risky the file is.</small>
        </div>
      </Card>
      {t.reasons.length > 0 && (
        <Card title="Why SafePeek flagged this">
          <p>{real.length ? `${threatStatusLabel[t.status].toUpperCase()}${t.status !== 'UNKNOWN' ? ` — ${t.score}/100` : ''}` : 'Notes about this analysis:'}</p>
          <ul className="reasons why">{t.reasons.map((r) => { const ind = t.indicators.find((i) => i.id === r.indicatorIds[0]); const src = originText(ind?.origins); return (
            <li key={r.id}><span aria-hidden="true">{r.severity === 'CRITICAL' || r.severity === 'HIGH' ? '🔴' : r.severity === 'MEDIUM' ? '🟠' : r.severity === 'LOW' ? '🟡' : 'ℹ️'}</span> <strong>{ind?.title ?? r.text}</strong>{ind && <small>{r.text}</small>}{src && <small className="muted">Source: {src}</small>}</li>); })}
            {visualNote && <li><span aria-hidden="true">ℹ️</span> <strong>Visual content</strong><small>{visualNote}</small></li>}
          </ul>
        </Card>
      )}
      <Card title={`Indicators (${real.length})`}>
        {real.length === 0 && <p className="muted">No suspicious indicators were detected in the available static analysis.</p>}
        {shown.map((i) => (
          <div className="ind" key={i.id}>
            <div className="ind-head"><span className={`badge badge-${severityTone[i.severity]}`}>{i.severity}</span><strong>{i.title}</strong><span className="tag">{categoryLabel(i.category)}</span>{i.correlated && <span className="tag">correlated</span>}<span className="tag">+{i.points}</span></div>
            <small>{i.description}</small>
            {i.evidence && <small className="code-ev">Evidence: {i.evidence}</small>}
            <small className="muted">Source: {originText(i.origins) || i.source.replace(/_/g, ' ').toLowerCase()}</small>
          </div>
        ))}
        {real.length > 8 && <button className="btn" onClick={() => setShowAll(!showAll)}>{showAll ? 'Show fewer' : `Show all ${real.length}`}</button>}
        {info.length > 0 && <details><summary className="muted">Informational notes ({info.length})</summary>{info.map((i) => <div className="ind" key={i.id}><strong>{i.title}</strong><small>{i.description}</small>{i.evidence && <small className="code-ev">{i.evidence}</small>}</div>)}</details>}
      </Card>
      <Card title="Analysis coverage">
        <div className="cov">
          <span className={cov(t.coverage.static)}>Static Analysis: {coverageLabel[t.coverage.static]}</span>
          <span className={cov(t.coverage.content)}>Content Analysis: {coverageLabel[t.coverage.content]}</span>
          <span className={cov(t.coverage.threat === 'COMPLETE' ? 'COMPLETE' : 'PARTIAL')}>Threat Analysis: {coverageLabel[t.coverage.threat]}</span>
        </div>
        {t.coverage.notes.map((n, i) => <small key={i} className="muted">• {n}</small>)}
        <details><summary className="muted">How the score was calculated</summary>
          <small>Raw total {t.breakdown.rawScore}, final {t.breakdown.finalScore}. Correlation bonus {t.breakdown.correlationBonus}, breadth bonus {t.breakdown.breadthBonus}. Engine v{t.engineVersion}.</small>
          {t.breakdown.notes.map((n, i) => <small key={i}>• {n}</small>)}
          <ul className="list">{t.breakdown.contributions.map((c) => <li key={c.indicatorId}><span>{c.title}</span><small>weight {c.weight} → {c.applied}{c.note ? ` (${c.note})` : ''}</small></li>)}</ul>
        </details>
        <details><summary className="muted">Limitations</summary>{t.limitations.map((l, i) => <small key={i}>• {l}</small>)}<small className="disclaimer">{t.disclaimer}</small></details>
      </Card>
    </>
  );
}
