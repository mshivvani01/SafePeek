import type { Rule, RuleFinding } from '../types';
import { F, clip, list } from './util';

const STANDARD_SECTIONS = new Set(['.text', '.data', '.rdata', '.rsrc', '.reloc', '.idata', '.edata', '.pdata', '.bss', '.tls', '.crt', '.didat', '.gfids', '.00cfg', '.ndata', '.sxdata', '.xdata', '.debug', '.code', 'code', 'data', 'bss', '.itext', '.eh_fram', '.rodata', '.init', '.fini', '.text$mn', '.retplne', '.detourc', '.detourd', '_rdata', '.orpc', 'text', '.cormeta', '.vmp']);
const PACKER_SECTIONS = /^(?:\.?upx\d?|\.aspack|\.adata|\.mpress\d|\.themida|\.vmp\d|\.petite|\.nsp\d|\.enigma\d|\.packed|\.boom|\.perplex|\.yp|pec\d|\.winlice)$/i;
const NET_DLLS = /^(?:wininet|winhttp|urlmon|ws2_32|wsock32|wsa|dnsapi)\.dll$/i;
const UNCOMMON_EXEC_EXT = new Set(['scr', 'pif', 'com', 'cpl', 'hta', 'jse', 'vbe', 'wsf', 'lnk', 'msi']);

/** Executable / PE-structure rules. "Is an executable" is a base weight: most executables are legitimate programs. */
export const executableRules: Rule = (c) => {
  const a = c.analysis; if (!a) return [];
  const out: RuleFinding[] = [];
  const pe = a.pe;
  if (c.isExecutable && c.typeId !== 'jar') {
    const dll = pe?.kind === 'DLL';
    out.push(F({ ruleId: 'EXEC_FILE', category: 'SUSPICIOUS_EXECUTABLE', weight: dll ? 12 : 22, base: true, title: dll ? 'Dynamic-link library (DLL)' : 'Executable file',
      description: `This is a ${c.typeLabel}${pe ? ` (${pe.architecture})` : ''}. Executable files can run code when opened. Most are legitimate programs, so this alone is not a sign of malware, but SafePeek did not run it and cannot judge its behavior.`,
      reason: `The file is a ${c.typeLabel}; executables can run code when opened.`, evidence: `Detected ${c.typeLabel}; extension ".${c.ext || 'none'}"` }));
  } else if (c.typeId === 'jar') {
    out.push(F({ ruleId: 'EXEC_JAR', category: 'SUSPICIOUS_EXECUTABLE', weight: 14, base: true, title: 'Java archive (JAR)', description: 'A JAR file can run Java code when opened with a Java runtime. It was not run or unpacked.', reason: 'The file is a Java archive that can run code.', evidence: c.typeLabel }));
  }
  if (c.isScript && !(c.analysis?.identity.detectedTypeId === 'html' && !c.scriptKind)) {
    const lang = a.script?.language ?? c.scriptKind ?? 'Script';
    const w = /PowerShell|VBScript|Windows Script|HTML Application|encoded/i.test(lang) ? 30 : /Batch/i.test(lang) ? 26 : /JavaScript/i.test(lang) ? 28 : 20;
    out.push(F({ ruleId: 'SCRIPT_FILE', category: 'SUSPICIOUS_SCRIPT', weight: w, base: true, title: `${lang} script`,
      description: `This is a ${lang} file. Windows can run scripts such as these directly, with the same permissions as the user. Many scripts are harmless automation, so this alone does not mean the file is malicious. It was not executed.`,
      reason: `The file is a ${lang} script that Windows can run directly.`, evidence: `Language: ${lang}${a.script ? `; ${a.script.lineCount} lines` : ''}` }));
  }
  if (UNCOMMON_EXEC_EXT.has(c.ext) && (c.isExecutable || c.isScript)) {
    out.push(F({ ruleId: 'EXEC_UNCOMMON_EXT', category: 'SUSPICIOUS_EXECUTABLE', weight: 12, title: `Uncommon executable type ".${c.ext}"`, description: `".${c.ext}" files can run code but are rarely distributed to ordinary users, which makes them popular for disguise.`, reason: `".${c.ext}" is an uncommon executable file type.`, evidence: `.${c.ext}` }));
  }
  if (pe) {
    const secs = pe.sections;
    const packed = secs.filter((s) => PACKER_SECTIONS.test(s));
    if (packed.length) out.push(F({ ruleId: 'PE_PACKER_SECTIONS', category: 'OBFUSCATION', weight: 22, title: 'Section names used by executable packers', description: `Section names (${list(packed)}) match tools that compress or protect executables. Packers are used by legitimate software and by malware to hide code from analysis.`, reason: `Executable sections look packed (${list(packed)}).`, evidence: `Sections: ${list(secs, 8)}`, dedupeKey: 'pe-packing', capGroup: 'pe' }));
    else {
      const odd = secs.filter((s) => !STANDARD_SECTIONS.has(s.toLowerCase()));
      if (odd.length >= 2) out.push(F({ ruleId: 'PE_ODD_SECTIONS', category: 'SUSPICIOUS_EXECUTABLE', weight: 6, title: 'Unusual section names', description: `${odd.length} section names are not typical compiler output (${list(odd)}). Some build tools use custom names, so this is a weak signal.`, reason: 'The executable has unusual section names.', evidence: `Sections: ${list(secs, 8)}`, dedupeKey: 'pe-packing', capGroup: 'pe' }));
    }
    if (secs.length === 0 && pe.kind !== 'Other') out.push(F({ ruleId: 'PE_NO_SECTIONS', category: 'OBFUSCATION', weight: 14, title: 'Executable has no sections', description: 'A normal program has at least one section. A header-only structure is unusual and can indicate a damaged, hand-crafted or protected file.', reason: 'The executable header has no sections.', capGroup: 'pe' }));
    if (!pe.parseComplete) out.push(F({ ruleId: 'PE_MALFORMED', category: 'SUSPICIOUS_EXECUTABLE', weight: 8, title: 'Executable structure could not be fully parsed', description: 'Parts of the PE structure were unreadable or inconsistent. Corrupt files and deliberately malformed files look the same to a static parser.', reason: 'The executable structure is malformed or incomplete.', capGroup: 'pe' }));
    const net = pe.imports.filter((d) => NET_DLLS.test(d));
    if (net.length) {
      const small = pe.imports.length <= 4 && !pe.importsTruncated;
      out.push(F({ ruleId: 'PE_NETWORK_IMPORTS', category: 'EXECUTION_RISK', weight: small ? 14 : 4, source: 'STATIC_ANALYSIS', title: 'Imports network libraries', description: `The program imports ${list(net)}, so it can use the network (e.g. to download data).${small ? ' Combined with a very small import table this is more notable.' : ' Many ordinary programs do this.'} SafePeek only lists imported DLL names, not individual functions.`, reason: 'The executable can use network libraries.', evidence: `Imports: ${list(pe.imports, 8)}`, capGroup: 'pe' }));
    }
    if (pe.kind === 'EXE' && pe.imports.length <= 1 && !pe.importsTruncated && pe.parseComplete) out.push(F({ ruleId: 'PE_FEW_IMPORTS', category: 'OBFUSCATION', weight: 8, title: 'Very small import table', description: 'Almost no imported libraries can mean the program resolves system functions at run time, which is typical of packed or hand-written code. Tiny test programs look the same.', reason: 'The executable imports almost nothing.', evidence: `Imports: ${list(pe.imports) || 'none'}`, capGroup: 'pe' }));
    out.push(F({ ruleId: 'PE_SIGNATURE_INFO', category: 'SUSPICIOUS_EXECUTABLE', weight: 0, severity: 'INFO', title: pe.hasSignatureBlock ? 'Digital-signature block present (not verified)' : 'No digital-signature block',
      description: pe.hasSignatureBlock ? 'The file contains a signature data block. SafePeek does NOT verify signatures, so this does not show who published the file or that it is trusted and did not lower the score.' : 'No signature block was found. Many legitimate programs are unsigned; this did not change the score.', evidence: `signatureVerified: ${String(pe.signatureVerified)}` }));
    if (pe.isDotNet) out.push(F({ ruleId: 'PE_DOTNET', category: 'SUSPICIOUS_EXECUTABLE', weight: 0, severity: 'INFO', title: '.NET assembly', description: 'The program is managed (.NET) code. This is common for legitimate software and is also easy to decompile and obfuscate. Informational only.' }));
  }
  return out;
};

type ScriptPattern = { id: string; re: RegExp; weight: number; title: string; cat: RuleFinding['category']; desc: string; key?: string };
const SP = (id: string, re: RegExp, weight: number, title: string, cat: RuleFinding['category'], desc: string, key?: string): ScriptPattern => ({ id, re, weight, title, cat, desc, key });
const SCRIPT_PATTERNS: ScriptPattern[] = [
  SP('ps_enc', /-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,}/i, 30, 'Encoded PowerShell command', 'OBFUSCATION', 'A base64-encoded command is passed to PowerShell, which hides what will run.', 'script-obf'),
  SP('b64', /frombase64string|certutil[^\n]{0,40}-decode|\batob\s*\(/i, 15, 'Decodes hidden (base64) data', 'OBFUSCATION', 'The script decodes base64 content at run time, a common way to conceal code.', 'script-obf'),
  SP('iex', /\binvoke-expression\b|(?:^|[\s;|(])iex\s*[\s(]/im, 14, 'Runs text as code (Invoke-Expression)', 'EXECUTION_RISK', 'Strings are executed as commands, so the real code may not be visible in the file.'),
  SP('download', /downloadstring|downloadfile|net\.webclient|invoke-webrequest|\biwr\s|invoke-restmethod|start-bitstransfer|bitsadmin[^\n]{0,20}\/transfer|certutil[^\n]{0,40}-urlcache|msxml2\.(?:server)?xmlhttp|winhttp\.winhttprequest|\bcurl\s+-|\bwget\s/i, 18, 'Downloads data from the internet', 'EXECUTION_RISK', 'The script fetches content from a remote location. Installers do this legitimately; downloaders do it to fetch malware.'),
  SP('policy', /-executionpolicy\s+bypass|-ep\s+bypass|set-executionpolicy/i, 12, 'Bypasses PowerShell execution policy', 'EXECUTION_RISK', 'Execution policy is a safety setting; scripts that switch it off are avoiding a protection.'),
  SP('hidden', /-windowstyle\s+hidden|-w\s+hidden|\s-nop\b|\bvbhide\b|\bwindowstyle\s*=\s*0/i, 12, 'Runs hidden', 'EXECUTION_RISK', 'The script hides its window so the user does not see it running.'),
  SP('defense', /add-mppreference[^\n]{0,30}exclusion|set-mppreference[^\n]{0,40}disable|netsh\s+advfirewall[^\n]{0,40}off|sc\s+stop\s+windefend|disableantispyware/i, 45, 'Tampers with security software', 'MALWARE', 'The script tries to disable or bypass Windows security features.'),
  SP('inject', /\[reflection\.assembly\]::load|virtualalloc|writeprocessmemory|createremotethread|add-type[^\n]{0,80}dllimport/i, 25, 'Memory / code-injection style APIs', 'MALWARE', 'The script references APIs used to load or inject code in memory.'),
  SP('persist', /schtasks\s+\/create|new-scheduledtask|currentversion\\run|reg\s+add[^\n]{0,60}\\run\b|startup\\/i, 18, 'Sets up persistence', 'EXECUTION_RISK', 'The script arranges to run again automatically (scheduled task, Run key or Startup folder).'),
  SP('lolbin', /\bmshta(?:\.exe)?\s|regsvr32[^\n]{0,30}\/i:http|rundll32[^\n]{0,40}javascript|wmic[^\n]{0,30}process\s+call\s+create/i, 22, 'Uses built-in Windows tools to run code', 'EXECUTION_RISK', 'Built-in Windows programs are being used to launch remote or script content, a technique used to avoid detection.'),
  SP('ransom', /vssadmin[^\n]{0,20}delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit[^\n]{0,60}recoveryenabled\s+no|cipher\s+\/w/i, 45, 'Deletes backups / recovery data', 'MALWARE', 'Deleting shadow copies or recovery settings is typical of ransomware preparation.'),
  SP('wsh', /new\s+activexobject\s*\(\s*["']wscript\.shell|createobject\s*\(\s*["']wscript\.shell["']\s*\)|wscript\.shell/i, 16, 'Starts programs through Windows Script Host', 'EXECUTION_RISK', 'The script can launch other programs via WScript.Shell.'),
  SP('dropper', /adodb\.stream[\s\S]{0,400}savetofile|savetofile[\s\S]{0,400}adodb\.stream/i, 38, 'Writes downloaded data to disk (dropper pattern)', 'MALWARE', 'ADODB.Stream with SaveToFile is a classic way for scripts to save a downloaded payload.'),
  SP('evalobf', /eval\s*\(\s*(?:unescape|atob|string\.fromcharcode)|document\.write\s*\(\s*unescape|string\.fromcharcode\s*\((?:\s*\d+\s*,){9,}/i, 20, 'Evaluates obfuscated code', 'OBFUSCATION', 'Code is rebuilt from encoded characters and executed.', 'script-obf')
];

/** Script content rules. Patterns are matched against extracted TEXT only; the script is never executed, parsed as code or evaluated. */
export const scriptContentRules: Rule = (c) => {
  if (!c.isScript || !c.rawText) return [];
  const t = c.rawText.slice(0, 200_000);
  const out: RuleFinding[] = []; const hit = new Set<string>();
  for (const p of SCRIPT_PATTERNS) {
    const m = p.re.exec(t); if (!m) continue; hit.add(p.id);
    const line = t.slice(Math.max(0, m.index - 20), m.index + Math.min(80, m[0].length + 30));
    out.push(F({ ruleId: `SCRIPT_${p.id.toUpperCase()}`, category: p.cat, weight: p.weight, source: 'CONTENT_ANALYSIS', title: p.title, description: `${p.desc} (Pattern match only; the script was not run.)`, reason: `${p.title}.`, evidence: clip(line, 110), dedupeKey: p.key, capGroup: 'script-content',
      evidenceItems: [{ type: 'script-pattern', description: p.title, value: clip(line, 110) }] }));
  }
  if (hit.has('download') && (hit.has('iex') || /start-process|\bstart\s+["']?\w+\.exe|\.run\s*\(|shell\.exec|invoke-item/i.test(t))) {
    out.push(F({ ruleId: 'SCRIPT_DOWNLOAD_EXEC', category: 'MALWARE', weight: 32, severity: 'HIGH', correlation: true, source: 'CORRELATION', title: 'Downloads and then runs content', description: 'The script both fetches remote data and executes content. This download-and-execute combination is the standard shape of a malware downloader, though some installers behave the same way.', reason: 'The script downloads content and then executes it.', evidence: 'download pattern + execute pattern' }));
  }
  const longest = t.split(/\r\n|\r|\n/).reduce((m, l) => Math.max(m, l.length), 0);
  if (longest > 3000) out.push(F({ ruleId: 'SCRIPT_LONG_LINE', category: 'OBFUSCATION', weight: 10, source: 'CONTENT_ANALYSIS', title: 'Extremely long single line', description: `A line of ${longest.toLocaleString()} characters is typical of minified, packed or machine-generated code. It is a weak signal on its own.`, reason: 'The script contains a very long single line (possible packing).', evidence: `${longest.toLocaleString()} characters`, dedupeKey: 'script-obf', capGroup: 'script-content' }));
  if ((t.match(/\bchr\(\s*\d+\s*\)/gi) ?? []).length >= 20 || (t.match(/\\x[0-9a-f]{2}/gi) ?? []).length >= 40) out.push(F({ ruleId: 'SCRIPT_CHAR_OBF', category: 'OBFUSCATION', weight: 18, source: 'CONTENT_ANALYSIS', title: 'Text built from character codes', description: 'Many Chr()/\\x escapes are used to assemble strings, which hides readable commands from simple inspection.', reason: 'The script assembles text from character codes.', dedupeKey: 'script-obf', capGroup: 'script-content' }));
  return out;
};
