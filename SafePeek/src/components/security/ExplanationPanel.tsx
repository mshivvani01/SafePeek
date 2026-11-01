import { useEffect, useState } from 'react';
import Card from '../common/Card';
import { protectionService } from '../../services/protectionService';
import { cleanName } from '../../utils/format';
import type { AiDisclosure, ExplanationBundle, ThreatExplanation } from '../../types/phase6';
import type { FileRecord } from '../../types/file';

function useExplanation(f: FileRecord) {
  const [b, setB] = useState<ExplanationBundle | null>(null);
  const key = `${f.id}:${f.threatAnalyzedAt}:${f.threatAnalysisStatus}`;
  useEffect(() => {
    let on = true; setB(null);
    if (f.threatAnalysisStatus === 'COMPLETED' || f.threatAnalysisStatus === 'INCOMPLETE') protectionService.explanation(f.id).then((r) => { if (on) setB(r); }).catch(() => undefined);
    return () => { on = false; };
  }, [key]); // eslint-disable-line react-hooks/exhaustive-deps
  return [b, setB] as const;
}

/** Phase 6: "Why is this risky?". Every string is rendered as a React text node. The authoritative verdict stays Phase 5; the wording below says which part is the AI's. */
export default function ExplanationPanel({ file }: { file: FileRecord }) {
  const [b, setB] = useExplanation(file);
  const [level, setLevel] = useState<'simple' | 'technical'>('simple');
  const [disc, setDisc] = useState<AiDisclosure | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { protectionService.settings().then((s) => setLevel(s.explanationLevel)); }, []);
  if (!b) return null;
  const e: ThreatExplanation = b.ai && level === 'simple' ? b.ai : b.local;
  const flagged = b.status !== 'SAFE' && b.status !== 'UNKNOWN';
  const setLvl = (l: 'simple' | 'technical') => { setLevel(l); protectionService.saveSettings({ explanationLevel: l }); };
  const askAi = async () => { setBusy(true); setDisc(await protectionService.disclosure(file.id)); setBusy(false); };
  const confirmAi = async () => { setBusy(true); const r = await protectionService.requestAi(file.id, true); if (r) setB(r); setDisc(null); setBusy(false); };
  return (
    <Card title={flagged ? 'Why is this risky?' : 'What SafePeek found'} aside={
      <div className="seg" role="tablist" aria-label="Explanation level">
        <button role="tab" aria-selected={level === 'simple'} className={level === 'simple' ? 'chip on' : 'chip'} onClick={() => setLvl('simple')}>Simple view</button>
        <button role="tab" aria-selected={level === 'technical'} className={level === 'technical' ? 'chip on' : 'chip'} onClick={() => setLvl('technical')}>Technical view</button>
      </div>}>
      {level === 'simple' ? (
        <div className="explain">
          <p className="lead">{e.summary}</p>
          {e.whatWasFound.length > 0 && <><h3>What SafePeek found</h3><ul className="reasons">{e.whatWasFound.map((x, i) => <li key={i}>{cleanName(x)}</li>)}</ul></>}
          {e.whyItMatters.length > 0 && <><h3>Why it matters</h3><ul className="reasons">{e.whyItMatters.map((x, i) => <li key={i}>{x}</li>)}</ul></>}
          <h3>Recommended action</h3><p><strong>{e.recommendedAction}</strong></p>
          <small className="muted">{b.ai && e === b.ai ? `AI-assisted explanation (${b.ai.provider}, ${b.ai.model}). SafePeek's threat engine produced the risk status and score; the AI only reworded the evidence.` : "Explanation generated locally from SafePeek's threat engine evidence. No AI and no network were used."}</small>
        </div>
      ) : (
        <div className="explain">
          <h3>Technical details</h3>
          <ul className="list">{(b.local.technicalDetails ?? []).map((x, i) => <li key={i}><code className="code-ev">{cleanName(x)}</code></li>)}</ul>
          {b.local.confidenceExplanation && <small className="muted">{b.local.confidenceExplanation}</small>}
        </div>
      )}
      {b.aiOutcome === 'REJECTED' || b.aiOutcome === 'FAILED' ? <div className="banner banner-warn">{b.aiMessage}</div> : null}
      {b.aiOutcome !== 'OFF' && !disc && !(b.ai) && <div className="row-btns"><button className="btn" disabled={busy} onClick={askAi}>Get AI-assisted explanation…</button><small className="muted">Optional. Nothing is sent until you confirm.</small></div>}
      {disc && (
        <div className="banner banner-info">
          <strong>Send evidence to {disc.provider} ({disc.endpointHost})?</strong>
          <small>Sent: {disc.includes.join('; ')}.</small><small>Never sent: {disc.excludes.join('; ')}. Original files are never uploaded.</small>
          <details><summary>Show the exact message that would be sent</summary><pre className="page">{disc.payloadPreview}</pre></details>
          <div className="row-btns"><button className="btn" disabled={busy} onClick={() => setDisc(null)}>Cancel</button><button className="btn primary" disabled={busy} onClick={confirmAi}>Send and explain</button></div>
        </div>
      )}
    </Card>
  );
}
