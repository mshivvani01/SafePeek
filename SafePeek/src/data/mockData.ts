// Sample data shown ONLY in browser preview mode (when the SafePeek desktop agent is not available). Never used in the packaged app.
import type { ActivityEvent, FileRecord, QuarantineItem } from '../types/file';

const base = { sha256: null, contentSummary: null, detectedUrls: [], indicators: [], previewAvailable: false, status: 'new' as const, analysisStatus: 'pending' as const };

export const mockFiles: FileRecord[] = [
  { ...base, id: 'f1', name: 'college_notice.pdf', path: 'C:\\Users\\demo\\Downloads\\college_notice.pdf', extension: 'pdf', mimeType: 'application/pdf', size: 184_320, createdAt: '2026-10-03T09:12:00Z', modifiedAt: '2026-10-03T09:12:00Z', riskLevel: 'safe' },
  { ...base, id: 'f2', name: 'salary_increment.pdf', path: 'C:\\Users\\demo\\Downloads\\salary_increment.pdf', extension: 'pdf', mimeType: 'application/pdf', size: 522_240, createdAt: '2026-10-03T16:42:00Z', modifiedAt: '2026-10-03T16:42:00Z', riskLevel: 'suspicious' },
  { ...base, id: 'f3', name: 'unknown.zip', path: 'C:\\Users\\demo\\Downloads\\unknown.zip', extension: 'zip', mimeType: 'application/zip', size: 2_411_520, createdAt: '2026-10-03T17:05:00Z', modifiedAt: '2026-10-03T17:05:00Z', riskLevel: 'high' },
  { ...base, id: 'f4', name: 'offer_letter.jpg', path: 'C:\\Users\\demo\\Downloads\\offer_letter.jpg', extension: 'jpg', mimeType: 'image/jpeg', size: 731_136, createdAt: '2026-10-02T11:30:00Z', modifiedAt: '2026-10-02T11:30:00Z', riskLevel: 'safe' }
];

export const mockActivity: ActivityEvent[] = [
  { id: 'a1', timestamp: '2026-10-03T17:05:00Z', fileName: 'unknown.zip', event: 'Analysis pending', riskLevel: 'high', status: 'Demo' },
  { id: 'a2', timestamp: '2026-10-03T16:42:00Z', fileName: 'salary_increment.pdf', event: 'Analysis pending', riskLevel: 'suspicious', status: 'Demo' },
  { id: 'a3', timestamp: '2026-10-03T09:12:00Z', fileName: 'college_notice.pdf', event: 'Analysis pending', riskLevel: 'safe', status: 'Demo' },
  { id: 'a4', timestamp: '2026-10-02T11:30:00Z', fileName: 'offer_letter.jpg', event: 'Analysis pending', riskLevel: 'safe', status: 'Demo' }
];

export const mockQuarantine: QuarantineItem[] = [
  { id: 'q1', originalName: 'unknown.zip', originalPath: 'C:\\Users\\demo\\Downloads\\unknown.zip', quarantinedAt: '2026-10-03T17:06:00Z', riskLevel: 'high', reason: 'Demo entry: archive from unknown sender', status: 'quarantined' }
];
