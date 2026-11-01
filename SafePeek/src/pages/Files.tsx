import { useEffect, useMemo, useState } from 'react';
import FileDetail from '../components/files/FileDetail';
import RiskBadge from '../components/common/RiskBadge';
import { fileService } from '../services/fileService';
import { useLiveState } from '../hooks';
import LoadState from '../components/common/LoadState';
import { cleanName, analysisLabel, contentLabel, formatBytes, formatDate, relativeTime, threatStatusToRisk, RISK_META } from '../utils/format';
import type { FileRecord } from '../types/file';
import type { RiskLevel } from '../types/threat';

type Filter = 'all' | RiskLevel | 'quarantined';
const FILTERS: [Filter, string][] = [['all', 'All'], ['safe', RISK_META.safe.label], ['low', RISK_META.low.label], ['suspicious', RISK_META.suspicious.label], ['high', RISK_META.high.label], ['critical', RISK_META.critical.label], ['unknown', RISK_META.unknown.label], ['quarantined', 'Quarantined']];
const riskOf = (f: FileRecord): RiskLevel => (f.threatStatus ? threatStatusToRisk[f.threatStatus] : f.riskLevel);
const isQ = (f: FileRecord) => f.quarantineState === 'QUARANTINED';
const matches = (f: FileRecord, k: Filter) => k === 'all' || (k === 'quarantined' ? isQ(f) : riskOf(f) === k);
const statusText = (f: FileRecord) => {
  if (f.quarantineState === 'QUARANTINED') return 'Quarantined';
  if (f.threatAnalysisStatus === 'COMPLETED') return 'Assessed';
  if (f.threatAnalysisStatus === 'INCOMPLETE') return 'Assessed (incomplete)';
  if (f.threatAnalysisStatus === 'FAILED') return 'Threat analysis failed';
  if (f.threatAnalysisStatus === 'ANALYZING' || f.threatAnalysisStatus === 'QUEUED') return 'Threat analysis…';
  if (f.contentStatus && ['QUEUED', 'ANALYZING', 'NOT_STARTED'].includes(f.contentStatus) && f.analysisStatus === 'complete') return `Content: ${contentLabel[f.contentStatus]}`;
  return `Static: ${analysisLabel[f.analysisStatus] ?? f.analysisStatus}`;
};

export default function Files({ selectedId }: { selectedId?: string | null }) {
  const fl = useLiveState(fileService.list, [] as FileRecord[]); const files = fl.data;
  const [sel, setSel] = useState<string | null>(selectedId ?? null);
  useEffect(() => { if (selectedId) { setSel(selectedId); setFilter('all'); } }, [selectedId]);
  const [filter, setFilter] = useState<Filter>('all');
  const shown = useMemo(() => files.filter((f) => matches(f, filter)), [files, filter]);
  const counts = useMemo(() => Object.fromEntries(FILTERS.map(([k]) => [k, files.filter((f) => matches(f, k)).length])) as Record<Filter, number>, [files]);
  const current = shown.find((f) => f.id === sel) ?? shown[0];
  return (
    <div className="page">
      <div className="filters" role="group" aria-label="Filter by risk">
        {FILTERS.map(([k, l]) => <button key={k} className={filter === k ? 'chip on' : 'chip'} aria-pressed={filter === k} onClick={() => setFilter(k)}>{l} ({counts[k]})</button>)}
      </div>
      <LoadState state={fl} what="files" />
      {!fl.loading && !fl.error && files.length === 0 && <div className="empty"><strong>No files detected yet</strong><span>New files in protected folders appear here automatically, with a risk rating.</span></div>}
      {files.length > 0 && (
        <div className="table-scroll">
          <table className="table fixed" aria-label="Files">
            <thead><tr><th className="col-name">Filename</th><th className="col-type">Detected type</th><th className="col-risk">Risk</th><th className="col-score">Score</th><th className="col-status">Status</th><th className="col-when">Detected at</th></tr></thead>
            <tbody>
              {shown.map((f) => (
                <tr key={f.id} className={`clickable${f.id === current?.id ? ' sel' : ''}`} tabIndex={0} aria-selected={f.id === current?.id} onClick={() => setSel(f.id)} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSel(f.id); } }}>
                  <td className="cell-name"><strong>{cleanName(f.name)}</strong><small>{formatBytes(f.size)}{f.sourceFolder ? ` · ${f.sourceFolder}` : ''}</small></td>
                  <td className="cell-name">{f.analysis?.identity.detectedType ?? (f.extension ? `.${f.extension}` : '—')}</td>
                  <td><RiskBadge level={riskOf(f)} /></td>
                  <td className="num">{f.threatStatus && f.threatStatus !== 'UNKNOWN' ? `${f.threatScore}/100` : '—'}</td>
                  <td>{statusText(f)}</td>
                  <td title={formatDate(f.detectedAt ?? f.createdAt)}>{relativeTime(f.detectedAt ?? f.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {shown.length === 0 && <div className="empty"><strong>No files match this filter</strong></div>}
        </div>
      )}
      {current ? <FileDetail file={current} /> : files.length > 0 && <p className="muted">Select a file to see its details.</p>}
    </div>
  );
}
