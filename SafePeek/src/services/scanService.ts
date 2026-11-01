import type { Analyzer, ScanResult } from '../types/scan';
import type { FileRecord } from '../types/file';

/**
 * Orchestrates analyzers (Phase 3 static, Phase 4 content, Phase 5 threat).
 * Phase 1: no analyzers registered, so scan() reports an honest "engine not connected" result.
 */
class ScanService {
  private analyzers: Analyzer[] = [];
  register(a: Analyzer) { this.analyzers.push(a); }
  get engineConnected() { return this.analyzers.length > 0; }

  async scan(file: FileRecord): Promise<ScanResult> {
    const startedAt = new Date().toISOString();
    const result: ScanResult = { fileId: file.id, startedAt, completedAt: null, riskLevel: 'unknown', score: 0, indicators: [], metadata: {}, contentSummary: null };
    for (const a of this.analyzers.filter((x) => x.canAnalyze(file))) {
      const partial = await a.analyze(file);
      result.indicators.push(...(partial.indicators ?? []));
      Object.assign(result.metadata, partial.metadata);
      result.contentSummary = partial.contentSummary ?? result.contentSummary;
    }
    result.completedAt = new Date().toISOString();
    return result;
  }
}
export const scanService = new ScanService();
