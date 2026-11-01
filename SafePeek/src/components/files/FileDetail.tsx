import type { FileRecord } from '../../types/file';
import Card from '../common/Card';
import SafePreview from './SafePreview';
import ThreatPanel, { useThreat } from './ThreatPanel';
import ExplanationPanel from '../security/ExplanationPanel';
import ActionBar from '../security/ActionBar';
import { useEffect, useState } from 'react';
import type { ContentResult } from '../../types/content';
import { contentService, threatService } from '../../services/fileService';
import { analysisLabel, contentLabel, formatBytes, cleanName, formatDate, plural, previewTypeLabel, threatStatusToRisk, typeLabel, RISK_META } from '../../utils/format';

const Row = ({ k, v }: { k: string; v: string }) => <div><dt>{k}</dt><dd>{v}</dd></div>;
const icon = (sev: string) => (sev === 'info' ? 'ℹ' : sev === 'high' ? '🔴' : '⚠');

/** Shows what analysis actually found. Nothing was executed. The Phase 5 threat panel summarizes it as a heuristic assessment. */
export default function FileDetail({ file }: { file: FileRecord }) {
  const a = file.analysis;
  const c = useContent(file.id, file.contentStatus);
  const done = !!a && a.status !== 'failed';
  const risk = file.threatStatus ? threatStatusToRisk[file.threatStatus] : 'unknown';
  const has = (code: string) => a?.indicators.some((i) => i.code === code);
  const meta: [string, string][] = a ? [
    ['Declared type', a.identity.declaredType ?? 'No extension'], ['Actual type', a.identity.detectedType], ['MIME type', a.identity.mimeType ?? '—'],
    ['Size', formatBytes(a.metadata.size)], ['SHA-256', a.sha256 ?? 'Not calculated'], ['Full path', a.identity.path],
    ['Created', formatDate(a.metadata.createdAt)], ['Modified', formatDate(a.metadata.modifiedAt)], ['Accessed', a.metadata.accessedAt ? formatDate(a.metadata.accessedAt) : '—'],
    ['Analyzed', formatDate(a.analysisTimestamp)], ['Execution', 'NOT PERFORMED']
  ] : [['Status', file.status], ['Location', file.sourceFolder ?? '—'], ['Full path', file.path], ['Size', formatBytes(file.size)], ['Detected', formatDate(file.detectedAt ?? file.createdAt)], ['File type', typeLabel(file.extension)], ['Created', formatDate(file.createdAt)], ['Modified', formatDate(file.modifiedAt)]];
  return (
    <div className="detail">
      <div className={`file-hero sev-${risk}`}>
        <div className="file-head"><div><h2 className="cell-name">{cleanName(file.name)}</h2><p>{a ? a.identity.detectedType : `${file.extension.toUpperCase() || 'Unknown'} file · type based on extension only`}</p></div></div>
        <div className="hero-risk">
          {file.threatStatus ? <span className={`risk-big badge badge-${risk}`}><span aria-hidden="true">{RISK_META[risk].icon}</span> {RISK_META[risk].label.toUpperCase()}{file.threatStatus !== 'UNKNOWN' ? ` · ${file.threatScore}/100` : ''}</span> : <span className="badge badge-unknown">{analysisLabel[file.analysisStatus] ?? file.analysisStatus}</span>}
          {file.threatStatus && <strong>{RISK_META[risk].tagline}</strong>}
        </div>
        {file.threatStatus && (file.threatTopReason || file.threatHeadline) && <p className="hero-why">{file.threatTopReason ?? file.threatHeadline}</p>}
        {file.quarantineState === 'QUARANTINED' && <div className="banner banner-warn">This file is in SafePeek's quarantine. It cannot be opened from here; manage it on the Quarantine page.</div>}
        {file.threatStatus && <small className="muted">Rating and score come from SafePeek's local heuristic threat engine. They are not a guarantee.</small>}
      </div>
      {file.analysisStatus === 'analyzing' && <div className="banner banner-info">Static analysis in progress…</div>}
      {file.analysisStatus === 'pending' && <div className="banner banner-info">Queued for static analysis.</div>}
      {a?.status === 'partial' && <div className="banner banner-warn">PARTIAL ANALYSIS — {a.partialReasons.join(' ')} Static metadata is still available.</div>}
      {a?.status === 'failed' && <div className="banner banner-warn">ANALYSIS FAILED — {a.partialReasons.join(' ')}</div>}
      <ExplanationPanel file={file} />
      <ThreatPanel file={file} visualNote={visualNote(c)} />
      <VisualPanel file={file} c={c} />
      <ContentSections file={file} c={c} />
      <details className="tech card"><summary>Technical details</summary>
      <div className="detail">
      {a && (
        <Card title="Static findings">
          <ul className="list">
            {a.indicators.map((i, n) => <li key={n}><div><strong>{icon(i.severity)} {i.title}</strong><small>{i.description}</small>{i.evidence && <small>Evidence: {i.evidence}</small>}</div></li>)}
            {done && !has('TYPE_MISMATCH') && <li><strong>✓ File type matches extension</strong></li>}
            {done && !has('EXECUTABLE_FILE') && !has('SCRIPT_FILE') && !has('EMBEDDED_EXECUTABLE') && <li><strong>✓ No executable or script detected</strong></li>}
          </ul>
          <small className="muted">Facts and indicators from static analysis; the threat assessment above weighs them. Files are analyzed locally; nothing is uploaded.</small>
        </Card>
      )}
      {a?.pe && <Card title="Windows executable (PE)"><dl className="meta">
        <Row k="Kind" v={a.pe.kind} /><Row k="Architecture" v={a.pe.architecture} /><Row k="Subsystem" v={a.pe.subsystem ?? '—'} />
        <Row k="Entry point (RVA)" v={a.pe.entryPointRva !== null ? `0x${a.pe.entryPointRva.toString(16)}` : '—'} /><Row k=".NET assembly" v={a.pe.isDotNet ? 'Yes' : 'No'} />
        <Row k="Signature block" v={a.pe.hasSignatureBlock ? 'Present (not verified)' : 'Not present'} /><Row k="Sections" v={a.pe.sections.join(', ') || '—'} />
        <Row k={`Imported DLLs (${a.pe.imports.length})`} v={a.pe.imports.join(', ') || '—'} /></dl></Card>}
      {a?.pdf && <Card title="PDF structure"><dl className="meta">
        <Row k="Version" v={a.pdf.version ?? '—'} /><Row k="Pages" v={a.pdf.pageCount !== null ? String(a.pdf.pageCount) : '—'} /><Row k="Encrypted" v={a.pdf.encrypted ? 'Yes' : 'No'} />
        <Row k="JavaScript" v={a.pdf.hasJavaScript ? 'Detected' : 'Not detected'} /><Row k="Embedded files" v={String(a.pdf.embeddedFileCount)} /><Row k="Annotations" v={String(a.pdf.annotationCount)} />
        {Object.entries(a.pdf.metadata).map(([k, v]) => <Row key={k} k={k} v={v} />)}</dl><small className="muted">Raw structural scan; the PDF was never opened in a reader.</small></Card>}
      {a?.office && <Card title="Office document"><dl className="meta">
        <Row k="Type" v={a.office.label} /><Row k="Macros" v={a.office.hasMacros ? 'Detected' : 'Not detected'} /><Row k="ActiveX" v={a.office.hasActiveX ? 'Detected' : 'Not detected'} />
        <Row k="External relationships" v={String(a.office.externalRelationships.length)} /><Row k="Embedded objects" v={String(a.office.embeddedObjects.length)} />
        {Object.entries(a.office.metadata).map(([k, v]) => <Row key={k} k={k} v={v} />)}</dl></Card>}
      {a?.script && <Card title="Script"><dl className="meta"><Row k="Language" v={a.script.language} /><Row k="Lines" v={String(a.script.lineCount)} /><Row k="Execution" v="Not performed" />
        <Row k="Static content" v="Available for future content analysis" /></dl></Card>}
      {a?.archive && <Card title={`Archive contents (${a.archive.entryCount}${a.archive.truncated ? '+' : ''})`}>
        <ul className="list">{a.archive.entries.slice(0, 200).map((e, n) => <li key={n}><span>{e.isDirectory ? '📁' : e.dangerous ? '🔴' : '📄'} {e.name}{e.encrypted ? ' 🔒' : ''}</span><small className="muted">{e.isDirectory ? '' : formatBytes(e.size)}</small></li>)}</ul>
        <small className="muted">Listed only. Nothing was extracted or run.</small></Card>}
      {a && a.embeddedObjects.length > 0 && <Card title="Embedded objects"><ul className="list">{a.embeddedObjects.map((o, n) => <li key={n}><span>{o.executable ? '🔴' : '📎'} {o.name}</span><small className="muted">{o.kind}</small></li>)}</ul></Card>}
      {a && a.urls.length > 0 && <Card title={`Detected URLs (${a.urls.length})`}><ul className="list">{a.urls.slice(0, 50).map((u) => <li key={u}><code className="url">{u}</code></li>)}</ul><small className="muted">Extracted as text only. SafePeek does not visit URLs; they are checked locally for suspicious patterns (see Indicators).</small></Card>}
      <Card title="File information"><dl className="meta">{meta.map(([k, v]) => <Row key={k} k={k} v={v} />)}</dl></Card>
      {a && <div className="row-btns"><button className="btn" onClick={() => window.safepeek?.reanalyzeFile(file.id)}>Re-run static analysis ({plural(a.indicators.length, 'indicator')} now)</button>{a.status !== 'failed' && <button className="btn" onClick={() => contentService.rerun(file.id)}>Re-run content analysis</button>}<button className="btn" onClick={() => threatService.rerun(file.id)}>Re-run threat analysis</button></div>}
      </div>
      </details>
      <Card title="Recommended action">
        <ThreatPanel file={file} section="recommendation" />
        <ActionBar file={file} />
      </Card>
    </div>
  );
}

function useContent(id: string, status?: string): ContentResult | null {
  const [c, setC] = useState<ContentResult | null>(null);
  useEffect(() => {
    let on = true; setC(null);
    if (status === 'COMPLETED' || status === 'PARTIAL' || status === 'UNSUPPORTED' || status === 'FAILED') contentService.get(id).then((r) => { if (on) setC(r); }).catch(() => undefined);
    return () => { on = false; };
  }, [id, status]);
  return c;
}

const statusBadge = (st?: string) => (st === 'COMPLETED' ? 'badge badge-safe' : st === 'PARTIAL' || st === 'FAILED' ? 'badge badge-suspicious' : 'badge badge-unknown');

/** Phase 4 sections: What's inside, Safe Preview, Extracted content. */
function ContentSections({ file, c }: { file: FileRecord; c: ContentResult | null }) {
  const [full, setFull] = useState(false);
  const st = file.contentStatus ?? 'NOT_STARTED';
  const a = file.analysis;
  if (!a || a.status === 'failed') return null;
  const ent = c?.summary.entities;
  const entRows: [string, string[]][] = ent ? ([['Organizations', ent.organizations], ['People', ent.people], ['Amounts', ent.amounts], ['Dates', ent.dates], ['Emails', ent.emails], ['Phone numbers', ent.phones]] as [string, string[]][]).filter(([, v]) => v.length) : [];
  const text = [c?.extractedText, c?.ocrText && c.ocrText !== c.extractedText ? `${c.extractedText ? '— Text read from images (OCR) —\n' : ''}${c.ocrText}` : ''].filter(Boolean).join('\n\n');
  return (
    <>
      <Card title="What's inside?">
        <div className="row-btns"><span className={statusBadge(st)}>Content analysis: {contentLabel[st] ?? st}</span>{c && <span className="badge badge-unknown">{previewTypeLabel[c.previewType]} preview{c.previewAvailable ? '' : ' unavailable'}</span>}<span className="badge badge-unknown">🔒 Analyzed locally</span></div>
        {(st === 'QUEUED' || st === 'ANALYZING' || st === 'NOT_STARTED') && <p className="muted">Content analysis {st === 'ANALYZING' ? 'in progress…' : 'is queued.'}</p>}
        {c && (
          <>
            <p className="lead">{c.status === 'UNSUPPORTED' || (!c.summary.description && c.unsupportedReason) ? c.unsupportedReason : c.summary.description || 'No content summary available.'}</p>
            <dl className="meta">
              {c.summary.documentType && c.status !== 'UNSUPPORTED' && <Row k="Looks like" v={c.summary.documentType} />}
              {c.summary.title && <Row k="Title" v={c.summary.title} />}
              {c.pageCount != null && <Row k={c.extractorType === 'pptx' ? 'Slides' : 'Pages'} v={String(c.pageCount)} />}
              {c.extractorType === 'xlsx' && c.sheets && <Row k="Sheets" v={c.sheets.map((s) => s.name).join(', ')} />}
              {c.textLength > 0 && <Row k="Text length" v={`${c.textLength.toLocaleString()} characters`} />}
              <Row k="Links found" v={String(c.links.length)} />
              {entRows.map(([k, v]) => <Row key={k} k={k} v={v.join(' · ')} />)}
            </dl>
            {c.status === 'PARTIAL' && <div className="banner banner-warn">⚠ Partial — SafePeek could not extract all content from this file.{c.technicalDetails && <small> Technical details: {c.technicalDetails}</small>}</div>}
            {c.status === 'FAILED' && <div className="banner banner-warn">Content could not be analyzed.{c.technicalDetails && <small> Technical details: {c.technicalDetails}</small>}</div>}
            {c.extractionWarnings.map((w, i) => <small key={i} className="muted">• {w}</small>)}
            <small className="muted">This describes what the file contains; the threat assessment above weighs it.</small>
          </>
        )}
      </Card>
      {c && <Card title="Safe Preview"><SafePreview c={c} a={a} /><small className="muted">Shown as inert data. Nothing in the file was opened, run or followed.</small></Card>}
      {c && (text || c.links.length > 0 || (c.properties && Object.keys(c.properties).length > 0)) && (
        <Card title="Extracted content">
          {text && <><pre className="page">{full ? text : text.slice(0, 3000)}</pre>{text.length > 3000 && <button className="btn" onClick={() => setFull(!full)}>{full ? 'Show less' : `Show all ${text.length.toLocaleString()} characters`}</button>}{c.truncated && c.truncationNote && <small className="muted">{c.truncationNote}</small>}</>}
          {c.links.length > 0 && <><strong>Detected links ({c.links.length})</strong><ul className="list">{c.links.slice(0, 50).map((l) => <li key={l.url}><code className="url">{l.url}</code><small className="muted">{l.source}</small></li>)}</ul><small className="muted">Shown as text only. SafePeek never visits or opens links.</small></>}
          {c.properties && Object.keys(c.properties).length > 0 && <dl className="meta">{Object.entries(c.properties).map(([k, v]) => <Row key={k} k={k} v={v} />)}</dl>}
        </Card>
      )}
    </>
  );
}

/** One factual sentence about the visual channel, or undefined when nothing visual was analyzed. Built only from what the extractor recorded. */
function visualNote(c: ContentResult | null): string | undefined {
  const v = c?.visual; if (!v) return undefined;
  const parts: string[] = [];
  if (v.ocrPages.length) parts.push(`${v.ocrPages.length} PDF page${v.ocrPages.length === 1 ? ' was' : 's were'} analyzed using OCR.`);
  else if (c?.extractorType === 'image' && v.ocrStatus === 'COMPLETED') parts.push('This image was analyzed using OCR.');
  if (v.qrCodes.length) parts.push(`${v.qrCodes.length} QR code${v.qrCodes.length === 1 ? ' was' : 's were'} decoded (not opened).`);
  return parts.length ? parts.join(' ') : undefined;
}
const ocrLabel: Record<string, string> = { COMPLETED: 'Complete', PARTIAL: 'Partial', FAILED: 'Failed', UNSUPPORTED: 'Unsupported', NOT_ATTEMPTED: 'Not needed' };
const qrKindLabel: Record<string, string> = { url: 'Web address', email: 'E-mail (mailto:)', phone: 'Phone number (tel:)', sms: 'Text message (sms:)', wifi: 'Wi-Fi settings (wifi:)', text: 'Plain text', 'other-scheme': 'Other link type' };

/** Part 19 + Part 12: what SafePeek found in images / scanned pages / QR codes. Everything is rendered as text; decoded content is never made clickable. */
function VisualPanel({ file, c }: { file: FileRecord; c: ContentResult | null }) {
  const t = useThreat(file.id, file.threatAnalysisStatus);
  const v = c?.visual;
  if (!c || !v || (v.imagesAnalyzed === 0 && v.qrCodes.length === 0 && v.ocrStatus === 'NOT_ATTEMPTED')) return null;
  const isPdf = c.extractorType === 'pdf';
  const qrInd = (t?.indicators ?? []).filter((i) => i.severity !== 'INFO' && i.origins?.includes('QR'));
  const flagged = (t?.evidence ?? []).filter((e) => e.origin === 'QR' && e.type === 'url').map((e) => e.value ?? '');
  return (
    <Card title="Visual Analysis">
      <div className="row-btns"><span className={v.ocrStatus === 'COMPLETED' || v.ocrStatus === 'NOT_ATTEMPTED' ? 'badge badge-safe' : 'badge badge-suspicious'}>OCR status: {ocrLabel[v.ocrStatus]}</span><span className="badge badge-unknown">🔒 Read locally; nothing uploaded</span></div>
      <dl className="meta">
        <Row k="Images analyzed" v={String(v.imagesAnalyzed)} />
        {(isPdf || v.ocrPages.length > 0) && <Row k="OCR pages" v={v.ocrPages.length ? `${v.ocrPages.length} (page${v.ocrPages.length === 1 ? '' : 's'} ${v.ocrPages.join(', ')})` : '0'} />}
        <Row k="QR codes" v={String(v.qrCodes.length)} />
        <Row k="URLs detected" v={String(v.urlsDetected)} />
        {v.ocrConfidence != null && v.ocrStatus !== 'NOT_ATTEMPTED' && <Row k="OCR confidence" v={`${Math.round(v.ocrConfidence)}%`} />}
        {v.downscaled && <Row k="Large images" v="Reduced in size before OCR" />}
      </dl>
      {(v.sources.directText || v.sources.ocrText || v.sources.qr) && <>
        <strong>Content sources</strong>
        <ul className="list">
          {v.sources.directText && <li><span>✓ {isPdf ? 'PDF text extracted' : 'Text extracted'}</span></li>}
          {v.sources.ocrText && <li><span>✓ OCR text extracted{v.ocrPages.length ? ` from ${v.ocrPages.length} page${v.ocrPages.length === 1 ? '' : 's'}` : ' from the image'}</span></li>}
          {v.sources.qr && <li><span>✓ QR code content decoded</span></li>}
        </ul></>}
      {(v.ocrStatus === 'PARTIAL' || v.ocrStatus === 'FAILED' || v.ocrStatus === 'UNSUPPORTED' || v.limitsHit.length > 0) && <div className="banner banner-warn">Some visual content could not be fully analyzed, so the absence of findings is not reassuring.{v.limitsHit.length > 0 && <small> Limits reached: {[...new Set(v.limitsHit)].join('; ')}.</small>}</div>}
      {v.qrCodes.length > 0 && <>
        <strong>QR Codes Detected</strong>
        <p className="muted">{v.qrCodes.length} QR code{v.qrCodes.length === 1 ? '' : 's'} detected. Decoded content is shown as text and was never opened.</p>
        {v.qrCodes.map((q) => { const isFlagged = !!q.url && flagged.some((f) => q.url!.startsWith(f) || f.startsWith(q.url!.slice(0, 100))); return (
          <div className="ind" key={q.index}>
            <div className="ind-head"><strong>QR code {q.index}</strong><span className="tag">{qrKindLabel[q.kind]}</span><span className="tag">{q.location}</span></div>
            <small>Decoded content:</small><code className="url">{q.payload}</code>{q.truncated && <small className="muted">Content was cut at {q.payload.length} characters.</small>}
            {q.kind === 'url' && <small>URL analysis: <b>{!t ? 'pending' : isFlagged ? 'Suspicious' : 'No suspicious pattern found (not proof of safety)'}</b>{q.schemeAssumed ? ' · web address assumed (no scheme in the code)' : ''}</small>}
            {q.kind === 'url' && isFlagged && qrInd.length > 0 && <small>Risk contribution: {qrInd.slice(0, 3).map((i) => i.title).join('; ')}</small>}
            {q.kind !== 'url' && q.kind !== 'text' && <small className="muted">Not a web address: shown as text only; SafePeek never launches it.</small>}
          </div>); })}
      </>}
      <small className="muted">OCR is not guaranteed to read every image, font, language or low-quality scan correctly. Images were read locally; nothing was uploaded.</small>
    </Card>
  );
}
