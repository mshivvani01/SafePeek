import { describe, expect, it } from 'vitest';
import { formatBytes, summarizeCounts } from '../src/utils/format';
import { scanService } from '../src/services/scanService';
import { mockFiles } from '../src/data/mockData';

describe('format utils', () => {
  it('formats bytes', () => { expect(formatBytes(0)).toBe('0 B'); expect(formatBytes(2048)).toBe('2.0 KB'); expect(formatBytes(-1)).toBe('—'); });
  it('summarizes counts', () => { expect(summarizeCounts(mockFiles, 1).high).toBe(1); });
});
describe('scanService', () => {
  it('reports unknown risk with no analyzers (never claims safe)', async () => {
    const r = await scanService.scan(mockFiles[0]);
    expect(scanService.engineConnected).toBe(false);
    expect(r.riskLevel).toBe('unknown');
  });
});
