import fs from 'node:fs';
import { describeFsError, isLockedOrDenied } from '../util/fsErrors';
import path from 'node:path';
import type { AnalysisResult, EmbeddedObject, StaticIndicator } from './types';
import { DANGEROUS_EXTENSIONS, EXECUTABLE_EXTENSIONS, MACRO_EXTENSIONS, SCRIPT_LANGUAGES, doubleExtension, extOf } from './extensions';
import { Detected, TYPES, declaredTypeLabel, detectType, isMismatch } from './magic';
import { readHead, sha256File } from './hash';
import { inspectPE } from './pe';
import { inspectPDF } from './pdf';
import { inspectOffice } from './office';
import { ZipHandle, openZip, toArchiveInfo } from './zip';
import { extractUrls, readTextCapped, scriptInfo } from './script';

export const LIMITS = { tinyBytes: 100, largeBytes: 500 * 1024 * 1024, maxHashBytes: 4 * 1024 * 1024 * 1024, headBytes: 8192 };
const IND = (code: StaticIndicator['code'], type: string, severity: StaticIndicator['severity'], title: string, description: string, evidence?: string): StaticIndicator => ({ code, type, severity, title, description, evidence });
const errMsg = (e: unknown) => ((e as NodeJS.ErrnoException).code ? `${(e as NodeJS.ErrnoException).code}: ` : '') + (e as Error).message;

/**
 * Static analysis of ONE file. Treats the file as untrusted: it is only ever read as bytes (never executed, opened by its default
 * application, or extracted to disk). Each stage is isolated: a parser failure yields a 'partial' result, never an exception.
 */
export async function analyzeFile(filePath: string, opts: { name?: string } = {}): Promise<AnalysisResult> {
  const startedAt = new Date().toISOString();
  const name = opts.name ?? path.basename(filePath);
  const ext = extOf(name);
  const reasons: string[] = [];
  const indicators: StaticIndicator[] = [];
  const urls = new Set<string>();
  const embedded: EmbeddedObject[] = [];
  const result = {
    version: 1 as const, status: 'complete' as AnalysisResult['status'], partialReasons: reasons, startedAt, completedAt: '', analysisTimestamp: '',
    identity: { name, path: path.normalize(filePath), extension: ext, declaredType: declaredTypeLabel(ext), detectedType: TYPES.unknown.label, detectedTypeId: 'unknown', mimeType: null as string | null, category: 'unknown' as const, typeMismatch: false, executionPerformed: false as const },
    metadata: { size: 0, createdAt: '', modifiedAt: '', accessedAt: null as string | null, sizeClass: 'normal' as AnalysisResult['metadata']['sizeClass'] },
    sha256: null as string | null, urls: [] as string[], embeddedObjects: embedded, indicators
  } as AnalysisResult;
  const finish = (): AnalysisResult => {
    result.urls = [...urls].slice(0, 200);
    if (result.urls.length) indicators.push(IND('EXTERNAL_URL', 'external-url', 'info', 'External URL detected', `${result.urls.length} URL(s) found in the file. They were not visited.`, result.urls.slice(0, 3).join(', ')));
    if (reasons.length && result.status === 'complete') result.status = 'partial';
    result.completedAt = result.analysisTimestamp = new Date().toISOString();
    return result;
  };

  // 1. metadata (also validates the file is readable)
  let size = 0;
  try {
    const st = await fs.promises.stat(filePath);
    if (!st.isFile()) throw new Error('Not a regular file');
    size = st.size;
    result.metadata = {
      size, createdAt: new Date(st.birthtimeMs || st.ctimeMs).toISOString(), modifiedAt: st.mtime.toISOString(), accessedAt: isNaN(st.atimeMs) ? null : st.atime.toISOString(),
      sizeClass: size === 0 ? 'empty' : size < LIMITS.tinyBytes ? 'tiny' : size > LIMITS.largeBytes ? 'large' : 'normal'
    };
  } catch (e) {
    result.status = 'failed';
    reasons.push((e as NodeJS.ErrnoException).code === 'ENOENT' ? 'File no longer exists (moved or deleted).' : isLockedOrDenied(e) ? describeFsError(e) : `File could not be read (${errMsg(e)}).`);
    return finish();
  }

  // 2. hash (streaming)
  if (size > LIMITS.maxHashBytes) reasons.push('File too large to hash (limit 4 GB).');
  else try { result.sha256 = await sha256File(filePath); } catch (e) { reasons.push(`SHA-256 could not be calculated (${errMsg(e)}).`); }

  // 3. type detection
  let det: Detected = TYPES.unknown;
  let head: Buffer = Buffer.alloc(0);
  try { head = await readHead(filePath, LIMITS.headBytes); det = detectType(head, name, size); } catch (e) { reasons.push(`File type could not be determined (${errMsg(e)}).`); }

  // 4. container-specific inspection
  let zip: ZipHandle | null = null;
  try {
    if (det.id === 'zip') {
      try {
        zip = await openZip(filePath);
        const office = await inspectOffice(zip);
        if (office) {
          det = office.format === 'unknown-ooxml' ? TYPES.ooxml : TYPES[office.format];
          result.office = office;
          embedded.push(...office.embeddedObjects);
          for (const r of office.externalRelationships) for (const u of extractUrls(r.target)) urls.add(u);
        } else if (zip.entries.some((e) => e.name === 'META-INF/MANIFEST.MF') && ext === 'jar') det = TYPES.jar;
        if (!office) result.archive = toArchiveInfo(zip, det.id === 'jar' ? 'JAR' : 'ZIP');
        if (office && zip.truncated) reasons.push('Package has more than 5000 entries; only the first 5000 were inspected.');
      } catch (e) { reasons.push(`ZIP structure could not be fully parsed (${errMsg(e)}).`); }
      finally { try { zip?.zip.close(); } catch { /* ignore */ } }
    } else if (det.id === 'pdf') {
      const pdf = await inspectPDF(filePath, size); result.pdf = pdf;
      pdf.urls.forEach((u) => urls.add(u));
      if (pdf.encrypted) reasons.push('PDF is encrypted; its content and actions could not be inspected.');
      if (pdf.truncated) reasons.push('PDF larger than the 16 MB scan limit; only the beginning was inspected.');
    } else if (det.id === 'pe' || det.id === 'dos-exe') {
      if (det.id === 'pe') { const pe = await inspectPE(filePath, size); result.pe = pe; if (!pe.parseComplete) reasons.push('PE structure could not be fully parsed.'); }
    } else if (det.category === 'text' || det.category === 'script') {
      const { text, truncated } = await readTextCapped(filePath, size);
      extractUrls(text).forEach((u) => urls.add(u));
      if (det.category === 'script' || det.id === 'html') result.script = scriptInfo(name, text, truncated, det.id);
      if (truncated) reasons.push('Large text file; only the first 2 MB was read.');
    } else if (det.id === 'gzip' || det.id === '7z' || det.id === 'rar') {
      reasons.push(`${det.label}: contents are not listed (only ZIP archives are inspected).`);
    } else if (det.id === 'ole2') {
      reasons.push('Legacy Office (OLE2) files are identified but not inspected for macros.');
    }
  } catch (e) { reasons.push(`${det.label} could not be fully parsed (${errMsg(e)}).`); }

  result.identity.detectedType = det.label; result.identity.detectedTypeId = det.id; result.identity.mimeType = det.mime; result.identity.category = det.category;
  if (result.script && det.category === 'text' && det.id === 'html') result.identity.category = 'text';

  // 5. indicators (facts only)
  if (size === 0) indicators.push(IND('EMPTY_FILE', 'other', 'info', 'Empty file', 'The file contains no data.'));
  if (isMismatch(ext, det)) {
    result.identity.typeMismatch = true;
    indicators.push(IND('TYPE_MISMATCH', 'mime-mismatch', 'warning', 'File type mismatch', `The extension says ${result.identity.declaredType ?? ext}, but the content is ${det.label}.`, `Declared ".${ext}"; detected ${det.label}`));
  }
  const dbl = doubleExtension(name);
  if (dbl) indicators.push(IND('DOUBLE_EXTENSION', 'double-extension', 'warning', 'Double extension detected', 'The filename ends with a document-like extension followed by an executable/script extension.', `Filename contains "${dbl}"`));
  const isExec = det.category === 'executable' && det.id !== 'jar' || EXECUTABLE_EXTENSIONS.includes(ext);
  if (isExec) indicators.push(IND('EXECUTABLE_FILE', 'executable-content', 'warning', 'Executable file', `${det.id === 'pe' || det.id === 'dos-exe' || det.id === 'elf' ? det.label : `Extension ".${ext}" is executable`}. It was not executed.`, `Detected ${det.label}; extension ".${ext || 'none'}"`));
  const scriptLike = (det.id === 'script') || (SCRIPT_LANGUAGES[ext] && !['html', 'htm'].includes(ext) && DANGEROUS_EXTENSIONS.has(ext));
  if (scriptLike) indicators.push(IND('SCRIPT_FILE', 'script', 'warning', 'Script file', `${result.script?.language ?? SCRIPT_LANGUAGES[ext] ?? 'Script'} file. It was not executed.`, `Extension ".${ext}"`));
  if (result.office?.hasMacros || MACRO_EXTENSIONS.includes(ext) && result.office) indicators.push(IND('MACRO_DETECTED', 'macro', 'warning', 'Macros detected', 'The Office package contains a VBA project or a macro-enabled content type. Macros were not run.', result.office.macroEnabledType ? 'Macro-enabled content type' : 'vbaProject.bin present'));
  if (result.office?.externalRelationships.length) indicators.push(IND('EXTERNAL_RELATIONSHIP', 'external-url', 'info', 'External relationships', `${result.office.externalRelationships.length} external relationship(s) in the Office package.`, result.office.externalRelationships.slice(0, 3).map((r) => r.target).join(', ')));
  if (result.pdf?.suspiciousActions.length) indicators.push(IND('SUSPICIOUS_PDF_ACTION', 'pdf-action', 'warning', 'PDF contains active actions', 'Actions that can run or open things were found in the PDF structure. None were run.', result.pdf.suspiciousActions.join('; ')));
  if (result.pdf?.encrypted) indicators.push(IND('ENCRYPTED_CONTENT', 'other', 'info', 'Encrypted PDF', 'The PDF is encrypted so content could not be inspected.'));
  if (result.pdf && result.pdf.embeddedFileCount > 0) embedded.push({ name: `${result.pdf.embeddedFileCount} embedded file(s)`, kind: 'PDF attachment', executable: false, source: 'pdf' });
  if (result.archive) {
    const a = result.archive;
    const bad = a.entries.filter((e) => e.dangerous);
    if (bad.length) indicators.push(IND('ARCHIVE_EXECUTABLE', 'archive', 'warning', 'Archive contains executable/script files', `${bad.length} entr${bad.length === 1 ? 'y' : 'ies'} inside the archive are executable or script types. Nothing was extracted or run.`, bad.slice(0, 5).map((e) => e.name).join(', ')));
    const trav = a.entries.filter((e) => e.unsafePath);
    if (trav.length) indicators.push(IND('ARCHIVE_PATH_TRAVERSAL', 'archive', 'high', 'Archive entries with unsafe paths', 'Entry names use absolute paths or ".." segments (Zip Slip pattern). SafePeek never extracts archives to disk.', trav.slice(0, 3).map((e) => e.name).join(', ')));
    if (a.encryptedEntries) { indicators.push(IND('ENCRYPTED_CONTENT', 'archive', 'info', 'Password-protected archive entries', `${a.encryptedEntries} entr${a.encryptedEntries === 1 ? 'y is' : 'ies are'} encrypted.`)); reasons.push('Archive has password-protected entries; their contents could not be inspected.'); }
    for (const e of a.entries) { const d = doubleExtension(e.name.split('/').pop() ?? ''); if (d) indicators.push(IND('DOUBLE_EXTENSION', 'double-extension', 'warning', 'Double extension inside archive', 'An archived file has a decoy extension followed by an executable/script one.', `${e.name} (${d})`)); }
    if (a.truncated) reasons.push('Archive has more than 5000 entries; only the first 5000 are listed.');
  }
  for (const o of embedded) if (o.executable) indicators.push(IND('EMBEDDED_EXECUTABLE', 'embedded-object', 'high', 'Embedded executable', 'An executable/script file is embedded in this document. It was not run.', o.name));
  return finish();
}
