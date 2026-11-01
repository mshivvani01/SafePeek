import type { ArchiveViewEntry, ContentExtractor, ExtractOutput } from './types';
import { LIMITS } from './limits';
import { cleanInline } from './sanitizer';
import { extOf } from '../analysis/extensions';

const INSPECTABLE = new Set(['pdf', 'docx', 'xlsx', 'pptx', 'txt', 'csv', 'json', 'log', 'md', 'png', 'jpg', 'jpeg', 'webp', 'gif']);

/**
 * Presents the Phase 3 archive listing as a tree. The archive is NEVER extracted: entry names are data only, and unsafe paths
 * (absolute, drive letters, "..") are flagged and shown but never resolved against the file system.
 */
export const archiveExtractor: ContentExtractor = {
  id: 'archive',
  canHandle: (c) => c.typeId === 'zip' || c.typeId === 'jar' || (!!c.analysis?.archive && !c.analysis.office),
  async extract(ctx): Promise<ExtractOutput> {
    const a = ctx.analysis?.archive;
    if (!a) return { status: 'PARTIAL', warnings: ['Archive listing was not available from static analysis.'], previewType: 'archive', previewAvailable: false };
    const warnings: string[] = [];
    let entries = a.entries; let truncated = a.truncated;
    if (entries.length > LIMITS.MAX_ARCHIVE_ENTRIES) { entries = entries.slice(0, LIMITS.MAX_ARCHIVE_ENTRIES); truncated = true; warnings.push(`Archive has more than ${LIMITS.MAX_ARCHIVE_ENTRIES} entries; only the first ${LIMITS.MAX_ARCHIVE_ENTRIES} are shown.`); }
    const view: ArchiveViewEntry[] = entries.map((e) => {
      const clean = cleanInline(e.name.replace(/\\/g, '/'), 300); const segs = clean.split('/').filter(Boolean);
      return { path: clean, name: segs[segs.length - 1] ?? clean, depth: Math.min(segs.length - 1, LIMITS.MAX_ARCHIVE_DEPTH), isDirectory: e.isDirectory, size: e.size, encrypted: e.encrypted, dangerous: e.dangerous, unsafePath: e.unsafePath,
        inspectable: !e.isDirectory && !e.dangerous && !e.unsafePath && !e.encrypted && INSPECTABLE.has(extOf(segs[segs.length - 1] ?? '')) };
    });
    // Deterministic tree order: sort by path so folders group with their children.
    view.sort((x, y) => x.path.localeCompare(y.path));
    if (view.some((v) => (v.path.split('/').length - 1) > LIMITS.MAX_ARCHIVE_DEPTH)) warnings.push(`Some entries are nested deeper than ${LIMITS.MAX_ARCHIVE_DEPTH} levels; indentation is capped.`);
    if (a.encryptedEntries) warnings.push(`${a.encryptedEntries} entr${a.encryptedEntries === 1 ? 'y is' : 'ies are'} password-protected; their contents cannot be shown.`);
    return { archiveEntries: view, archiveFormat: a.format, truncated, warnings, status: warnings.length ? 'PARTIAL' : 'COMPLETED', extractedText: '', links: [] };
  }
};
