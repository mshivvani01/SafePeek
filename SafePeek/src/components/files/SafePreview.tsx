import { useState } from 'react';
import type { ContentResult } from '../../types/content';
import type { AnalysisResult } from '../../types/analysis';
import { formatBytes } from '../../utils/format';

/**
 * Safe Preview. Everything here is DATA rendered as React text nodes (auto-escaped): no innerHTML, no iframes, no embedded viewers,
 * no links. The only non-text element is an <img> whose source is a data: URI of the original image bytes.
 */
const Trunc = ({ c }: { c: ContentResult }) => (c.truncated && c.truncationNote ? <small className="muted">{c.truncationNote}</small> : null);
function Table({ rows }: { rows: string[][] }) {
  if (!rows.length) return null;
  const w = Math.max(...rows.map((r) => r.length));
  return <div className="tablewrap"><table className="table mini"><tbody>{rows.map((r, i) => <tr key={i}>{Array.from({ length: w }, (_, j) => (i === 0 ? <th key={j}>{r[j] ?? ''}</th> : <td key={j}>{r[j] ?? ''}</td>))}</tr>)}</tbody></table></div>;
}

export function ExecutableNotice({ a }: { a?: AnalysisResult }) {
  return (
    <div className="unsupported"><strong>Safe Preview unavailable</strong>
      <p>{a?.identity.category === 'executable' ? 'This is an executable file.' : 'This file type cannot be previewed.'}</p><p>SafePeek will not execute this file.</p>
      <p className="muted">Static information is available below: type{a?.pe ? ', architecture, sections, imports' : ''}, hash and indicators.</p></div>
  );
}

export default function SafePreview({ c, a }: { c: ContentResult; a?: AnalysisResult }) {
  const [page, setPage] = useState(0);
  const [showAll, setShowAll] = useState(false);
  if (!c.previewAvailable) {
    if (a?.identity.category === 'executable' && a.identity.detectedTypeId !== 'jar') return <ExecutableNotice a={a} />;
    return <div className="unsupported"><strong>Safe Preview unavailable</strong><p>{c.unsupportedReason ?? c.extractionWarnings[0] ?? 'No previewable content was extracted.'}</p></div>;
  }
  return (
    <div className="safepreview">
      {c.embeddedContentWarning && <div className="banner banner-warn">⚠ Embedded content detected. SafePeek has not executed this content.</div>}
      {c.previewType === 'pdf' && c.pages && (
        <div>
          <div className="pager"><button className="btn" disabled={page === 0} onClick={() => setPage(page - 1)}>‹</button><span>Page {page + 1} of {c.pageCount ?? c.pages.length}{c.pages[page]?.source && c.pages[page].source !== 'text' ? ' · includes text read with OCR' : ''}</span><button className="btn" disabled={page >= c.pages.length - 1} onClick={() => setPage(page + 1)}>›</button></div>
          <pre className="page">{c.pages[page]?.text || '(no text on this page)'}</pre><Trunc c={c} />
        </div>
      )}
      {c.previewType === 'document' && c.sections && (
        <div className="doc">{c.sections.slice(0, showAll ? 2000 : 80).map((s, i) => s.kind === 'table' ? <Table key={i} rows={c.tables?.[s.tableIndex!]?.rows ?? []} /> : s.kind === 'heading' ? <p key={i} className={`h h${Math.min(s.level, 3)}`}>{s.text}</p> : <p key={i}>{s.text}</p>)}
          {c.sections.length > 80 && !showAll && <button className="btn" onClick={() => setShowAll(true)}>Show all {c.sections.length} blocks</button>}</div>
      )}
      {c.previewType === 'spreadsheet' && c.sheets && (
        <div>{c.sheets.map((s) => <div key={s.name}><strong>{s.name}</strong> <small className="muted">{s.range && `${s.range} · `}{s.rowCount} row{s.rowCount === 1 ? '' : 's'}{s.truncated ? ' (truncated)' : ''}</small><Table rows={s.rows} /></div>)}<Trunc c={c} /></div>
      )}
      {c.previewType === 'presentation' && c.slides && (
        <div>{c.slides.map((s) => <div className="slide" key={s.number}><small className="muted">Slide {s.number}</small><p className="h h1">{s.title || '(untitled)'}</p><pre className="page">{s.text}</pre>{s.notes && <small className="muted">Notes: {s.notes}</small>}</div>)}</div>
      )}
      {c.previewType === 'image' && c.image && (
        <div className="imgprev">
          {c.image.dataUrl ? <img src={c.image.dataUrl} alt="Safe preview of the image" /> : <p className="muted">{c.image.previewOmittedReason ?? 'Preview not available.'}</p>}
          <dl className="meta"><div><dt>Dimensions</dt><dd>{c.image.width && c.image.height ? `${c.image.width} × ${c.image.height}` : '—'}</dd></div><div><dt>Size</dt><dd>{formatBytes(c.image.size)}</dd></div>
            <div><dt>OCR</dt><dd>{c.ocrText ? `Text found${c.ocrConfidence != null ? ` (confidence ${Math.round(c.ocrConfidence)}%)` : ''}` : c.visual && c.visual.ocrStatus !== 'COMPLETED' ? 'Not completed' : 'No text found'} · local only</dd></div></dl>
        </div>
      )}
      {c.previewType === 'text' && (c.tables?.length ? <Table rows={c.tables[0].rows} /> : <pre className="page">{c.extractedText}</pre>)}
      {c.previewType === 'text' && <Trunc c={c} />}
      {c.previewType === 'archive' && c.archiveEntries && (
        <div><ul className="tree">{c.archiveEntries.map((e, i) => (
          <li key={i} style={{ paddingLeft: e.depth * 18 }}><span>{e.isDirectory ? '📁' : e.dangerous ? '🔴' : e.unsafePath ? '⛔' : '📄'} {e.name}{e.isDirectory ? '/' : ''}{e.encrypted ? ' 🔒' : ''}</span>
            <small className="muted">{e.unsafePath ? 'unsafe path · ' : ''}{e.dangerous ? 'executable/script · ' : ''}{e.isDirectory ? '' : formatBytes(e.size)}</small></li>))}</ul>
          <small className="muted">Listed only. Nothing was extracted or run.</small></div>
      )}
    </div>
  );
}
