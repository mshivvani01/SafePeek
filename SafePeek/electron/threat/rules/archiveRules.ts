import type { Rule, RuleFinding } from '../types';
import { EXEC_EXT, SCRIPT_EXT, F, baseName, clip, extOfName, list } from './util';

const DOC_EXT = new Set(['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'jpg', 'jpeg', 'png', 'csv']);
const ARCHIVE_EXT = new Set(['zip', 'rar', '7z', 'gz', 'tar', 'cab', 'tgz', 'bz2']);
const IMAGE_EXT = new Set(['iso', 'img', 'vhd', 'vhdx']);
const LURE_NAME = /(verif|invoice|payment|update|security|statement|receipt|scholarship|salary|refund|confirm|login|account)/i;

interface Entry { name: string; dir: boolean; encrypted: boolean; unsafe: boolean; depth: number }
function entriesOf(c: Parameters<Rule>[0]): Entry[] {
  const a = c.analysis?.archive;
  if (a) return a.entries.map((e) => ({ name: e.name, dir: e.isDirectory, encrypted: e.encrypted, unsafe: e.unsafePath, depth: e.name.split('/').filter(Boolean).length - 1 }));
  return (c.content?.archiveEntries ?? []).map((e) => ({ name: e.path, dir: e.isDirectory, encrypted: e.encrypted, unsafe: e.unsafePath, depth: e.depth }));
}

/** Archive rules. Uses the Phase 3 entry listing (and Phase 4 tree). Nothing is extracted, opened or executed. */
export const archiveRules: Rule = (c) => {
  const a = c.analysis?.archive; if (!a && !c.content?.archiveEntries?.length) return [];
  const es = entriesOf(c); const files = es.filter((e) => !e.dir); if (!files.length && !a) return [];
  const out: RuleFinding[] = [];
  const ext = (e: Entry) => extOfName(e.name);
  const exes = files.filter((e) => EXEC_EXT.has(ext(e))); const scripts = files.filter((e) => SCRIPT_EXT.has(ext(e)) && !EXEC_EXT.has(ext(e)));
  const docs = files.filter((e) => DOC_EXT.has(ext(e)));
  const dbl = (c.analysis?.indicators ?? []).filter((i) => i.code === 'DOUBLE_EXTENSION' && /inside archive/i.test(i.title));
  const dblNames = dbl.map((i) => (i.evidence ?? '').replace(/\s*\(.*\)\s*$/, ''));

  if (exes.length) out.push(F({ ruleId: 'ARCHIVE_EXECUTABLES', category: 'ARCHIVE_RISK', weight: 34, source: 'ARCHIVE_ANALYSIS', title: `Archive contains ${exes.length} executable file${exes.length === 1 ? '' : 's'}`,
    description: `Executable entries: ${list(exes.map((e) => e.name))}. Software is often distributed in archives, so this alone is common; it matters more when the archive is presented as documents. Nothing was extracted or run.`,
    reason: `The archive contains executable file(s): ${list(exes.map((e) => baseName(e.name)), 2)}.`, evidence: list(exes.map((e) => e.name)), dedupeKey: 'archive-exec-entry', capGroup: 'archive',
    evidenceItems: exes.slice(0, 5).map((e) => ({ type: 'archive-entry', description: 'Executable inside archive', value: clip(e.name, 100) })) }));
  if (scripts.length) out.push(F({ ruleId: 'ARCHIVE_SCRIPTS', category: 'ARCHIVE_RISK', weight: 28, source: 'ARCHIVE_ANALYSIS', title: `Archive contains ${scripts.length} script file${scripts.length === 1 ? '' : 's'}`, description: `Script entries: ${list(scripts.map((e) => e.name))}. Scripts and shortcuts can run commands when opened. Nothing was extracted or run.`, reason: `The archive contains script file(s): ${list(scripts.map((e) => baseName(e.name)), 2)}.`, evidence: list(scripts.map((e) => e.name)), dedupeKey: 'archive-exec-entry', capGroup: 'archive' }));
  if (dbl.length) out.push(F({ ruleId: 'ARCHIVE_DOUBLE_EXT', category: 'SOCIAL_ENGINEERING', weight: 42, severity: 'HIGH', source: 'ARCHIVE_ANALYSIS', title: 'Archive contains a file with a double extension', description: `A file inside the archive has a document-like extension followed by an executable/script one (${list(dblNames)}). That disguises a program as a document.`, reason: `The archive contains a double-extension file (${list(dblNames, 2)}).`, evidence: list(dbl.map((i) => i.evidence ?? '')), dedupeKey: 'archive-exec-entry', capGroup: 'archive' }));
  const unsafe = files.filter((e) => e.unsafe).concat(es.filter((e) => e.dir && e.unsafe));
  if (unsafe.length || (c.analysis?.indicators ?? []).some((i) => i.code === 'ARCHIVE_PATH_TRAVERSAL')) out.push(F({ ruleId: 'ARCHIVE_PATH_TRAVERSAL', category: 'ARCHIVE_RISK', weight: 50, severity: 'HIGH', source: 'ARCHIVE_ANALYSIS', title: 'Archive entries use unsafe paths (Zip Slip pattern)', description: 'Entry names contain ".." segments or absolute paths. An unpacking tool that does not check them could write files outside the chosen folder (for example into Startup). SafePeek never extracts archives to disk.', reason: 'Archive entry paths try to escape the extraction folder.', evidence: list(unsafe.map((e) => e.name)) || 'unsafe entry path', capGroup: 'archive' }));
  const nested = files.filter((e) => ARCHIVE_EXT.has(ext(e)));
  if (nested.length >= 3) out.push(F({ ruleId: 'ARCHIVE_NESTED', category: 'ARCHIVE_RISK', weight: 14, source: 'ARCHIVE_ANALYSIS', title: `Archive contains ${nested.length} nested archives`, description: 'Archives inside archives are sometimes used to push content past scanners. Nested archives were not opened.', reason: 'The archive contains several nested archives.', evidence: list(nested.map((e) => e.name)), capGroup: 'archive' }));
  const deep = Math.max(0, ...es.map((e) => e.depth));
  if (deep > 6) out.push(F({ ruleId: 'ARCHIVE_DEEP', category: 'ARCHIVE_RISK', weight: 12, source: 'ARCHIVE_ANALYSIS', title: 'Unusually deep folder nesting', description: `Folders are nested ${deep} levels deep, which is uncommon for ordinary archives and can be used to create overly long paths.`, reason: 'The archive has unusually deep folder nesting.', evidence: `${deep} levels`, capGroup: 'archive' }));
  const imgs = files.filter((e) => IMAGE_EXT.has(ext(e)));
  if (imgs.length) out.push(F({ ruleId: 'ARCHIVE_DISK_IMAGE', category: 'ARCHIVE_RISK', weight: 16, source: 'ARCHIVE_ANALYSIS', title: 'Archive contains a disk image', description: 'Disk images (.iso, .img, .vhd) are used to carry executables past some download protections.', reason: 'The archive contains a disk image.', evidence: list(imgs.map((e) => e.name)), capGroup: 'archive' }));
  if (a && a.encryptedEntries > 0) out.push(F({ ruleId: 'ARCHIVE_ENCRYPTED', category: 'ARCHIVE_RISK', weight: exes.length || scripts.length ? 18 : 10, source: 'ARCHIVE_ANALYSIS', title: 'Archive has password-protected entries', description: `${a.encryptedEntries} entr${a.encryptedEntries === 1 ? 'y is' : 'ies are'} encrypted, so their contents could not be inspected. Password-protected archives are also a way to avoid scanners.`, reason: 'Some archive entries are password-protected and could not be inspected.', evidence: `${a.encryptedEntries} encrypted`, capGroup: 'archive' }));
  if (a && (a.totalUncompressed > 2 * 1024 ** 3 || (c.analysis!.metadata.size > 0 && a.totalUncompressed / c.analysis!.metadata.size > 200 && a.totalUncompressed > 100 * 1024 ** 2))) out.push(F({ ruleId: 'ARCHIVE_EXPANSION', category: 'ARCHIVE_RISK', weight: 16, source: 'ARCHIVE_ANALYSIS', title: 'Archive expands to a very large size', description: `Declared uncompressed size is ${(a.totalUncompressed / 1024 ** 2).toFixed(0)} MB, far larger than the archive itself. This can be a decompression-bomb pattern, or just highly compressible data.`, reason: 'The archive expands to a disproportionately large size.', evidence: `${(a.totalUncompressed / 1024 ** 2).toFixed(0)} MB uncompressed`, capGroup: 'archive' }));

  // Combinations
  const risky = [...exes, ...scripts];
  if (risky.length && docs.length) out.push(F({ ruleId: 'ARCHIVE_DOC_PLUS_EXEC', category: 'SOCIAL_ENGINEERING', weight: 15, correlation: true, source: 'CORRELATION', title: 'Documents bundled with an executable', description: 'The archive pairs ordinary-looking documents with a program or script. Bundling a decoy document next to an executable is a common way to make the executable look like part of a legitimate package.', reason: 'Documents and an executable/script are bundled together.', evidence: `${docs.length} document(s) + ${risky.length} executable/script file(s)` }));
  const stem = (n: string) => baseName(n).toLowerCase().replace(/\.(?:[a-z0-9]{2,5})$/i, '').replace(/\.(?:pdf|docx?|xlsx?|jpe?g|png|txt)$/i, '');
  const same = risky.find((r) => docs.some((d) => stem(d.name) && stem(d.name) === stem(r.name)));
  if (same) out.push(F({ ruleId: 'ARCHIVE_SAME_NAME', category: 'SOCIAL_ENGINEERING', weight: 15, correlation: true, source: 'CORRELATION', title: 'Executable shares its name with a document', description: `"${clip(baseName(same.name), 60)}" has the same base name as a document in the archive, so the program and the document are easy to confuse.`, reason: 'An executable has the same name as a document in the archive.', evidence: clip(same.name, 100) }));
  const lure = risky.filter((r) => LURE_NAME.test(baseName(r.name)));
  if (lure.length) out.push(F({ ruleId: 'ARCHIVE_LURE_NAME', category: 'SOCIAL_ENGINEERING', weight: 10, source: 'ARCHIVE_ANALYSIS', title: 'Executable named like a business document or security step', description: `Executable/script entries are named with everyday wording (${list(lure.map((e) => baseName(e.name)))}). Lure names make a program look like a form, receipt or verification step.`, reason: 'An executable inside the archive has a document-themed name.', evidence: list(lure.map((e) => e.name)), capGroup: 'archive' }));
  return out;
};
