import fs from 'node:fs';
import path from 'node:path';
import { analyzeFile } from '../../electron/analysis/analyzer';
import type { ContentResult } from '../../electron/content/types';
import { assessThreat } from '../../electron/threat';
import type { ThreatAssessment } from '../../electron/threat';

/** Minimal Phase 4 result for rule tests. Real extraction is covered by tests/content.test.ts and the full pipeline test. */
export function contentStub(text: string | null, o: Partial<ContentResult> = {}): ContentResult {
  const now = new Date().toISOString();
  return {
    version: 1, status: text === null ? 'UNSUPPORTED' : 'COMPLETED', extractorType: text === null ? 'none' : 'text', fileName: 'x', extractedText: text ?? undefined, textLength: text?.length ?? 0, links: [],
    summary: { documentType: 'Unknown', title: null, description: '', pageCount: null, textLength: text?.length ?? 0, entities: { organizations: [], people: [], amounts: [], dates: [], emails: [], phones: [] }, keySections: [] },
    previewType: 'text', previewAvailable: text !== null, embeddedContentWarning: false, extractionWarnings: [], truncated: false, startedAt: now, analyzedAt: now, executionPerformed: false, uploaded: false, ...o
  };
}

/** Writes `data` as `name` in dir, runs the REAL Phase 3 analyzer on it, then the Phase 5 engine with the given (synthetic) Phase 4 result. */
export async function assessFile(dir: string, name: string, data: Buffer | string, content?: ContentResult | null): Promise<ThreatAssessment> {
  const p = path.join(dir, name); fs.writeFileSync(p, data);
  const analysis = await analyzeFile(p);
  return assessThreat({ fileName: name, analysis, content: content === undefined ? contentStub(typeof data === 'string' ? data : null) : content });
}
export const ids = (a: ThreatAssessment): string[] => a.indicators.map((i) => i.id);
export const real = (a: ThreatAssessment) => a.indicators.filter((i) => i.severity !== 'INFO');
