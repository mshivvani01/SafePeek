# SafePeek Security Document

> SafePeek cannot guarantee detection of every malicious file and does not replace a full antivirus, EDR, sandbox, or enterprise security product.

This document describes what SafePeek is designed to defend against, how it is built to stay safe while doing so, and where its limits are. Statements describe the implemented design; **what has actually been run and tested is recorded in `CONTINUATION.md` and `docs/FINAL_TEST_REPORT.md`** (notably, the Windows runtime has not been verified).

## 1. Threat model
**Designed to help with** (a user about to open a newly downloaded or received file):
- Executables or scripts disguised as documents or images (`invoice.pdf.exe`, a PE file named `.pdf`).
- Phishing, scam, credential-theft and payment-fraud documents (urgent wording, fake offers, look-alike brand links, links that do not match the text).
- Documents with active content: PDF JavaScript/launch actions, Office macros, ActiveX, embedded objects, external relationships.
- Archives that hide executables or scripts, use unsafe entry paths (Zip-Slip), or are password-protected.

**Also in scope - SafePeek itself as a target**: hostile files aiming at SafePeek's parsers, the UI, the quarantine, or the optional AI layer (prompt injection, path tricks, oversized or malformed input).

**Out of scope**: zero-day exploits, obfuscated or encrypted payloads, malware that is only malicious at run time, malware already running on the PC, network attacks, and a compromised operating system. SafePeek has no signatures, no cloud reputation lookup and no behavioural sandbox.

## 2. Static analysis
Files are only read as bytes. SafePeek never executes, loads, opens in another application, or follows links in an incoming file. Analysis covers SHA-256, magic-byte type vs. extension, double extensions, PE headers (bounds-checked parser), PDF structure (token scan), OOXML package inspection, ZIP central-directory listing, script identification and URL extraction. Each stage is isolated; a failure produces a `partial`/`failed` result, never an exception that hides the file, and never a "Safe" verdict. Static analysis has a 120 s limit and detects a file that changes while being analyzed (size + modified time compared before and after; bounded retries, then flagged partial).

## 3. Content analysis (safe extraction and preview)
- Text, tables and links are extracted from PDF, DOCX, XLSX, PPTX, text/CSV/JSON/log, images (local OCR) and archive listings. Executables are never handed to an extractor.
- Archives are **never extracted to disk**; entry names are data only. Spreadsheet formulas are never evaluated (cached values only). XML parsing strips DOCTYPE declarations.
- The preview is inert: every string is rendered as a React text node (no `innerHTML`, no iframes, no clickable links); the sanitizer strips control and bidirectional characters and caps length. PDF "preview" is extracted text, not a rendered page, because a renderer cannot be proven to neutralise PDF actions.
- Size, page, entry and time limits are centralized (`electron/content/limits.ts`). Per-file timeouts reject the result but cannot cancel work already in flight (see Limitations).
- `electron/content` and `electron/threat` contain no network, process or `eval` APIs; this is enforced by tests.

### 3a. Visual content (Phase 8)
Images and scanned PDF pages are **untrusted pixels**, treated as data only.
- **Bounded**: images over 50 megapixels / 20 000 px are not decoded (decompression-bomb guard); everything handed to OCR is downsampled to at most about 2 200 px / 4.5 MP; OCR runs in bands, with a per-call timeout (the OCR worker is *terminated* on timeout or crash, never left running), and a total time budget. PDFs: at most 10 OCR pages, 25 inspected pages, 3 images per page, a total decoded-pixel budget, and pdf.js `maxImageSize` so an oversized embedded image is skipped instead of decoded. Any limit reached marks the result **PARTIAL** (never SAFE).
- **No execution / no network**: PDF page images are read from the operator list as data (no scripts, actions, annotations or URLs are run or followed, `enableScripting` stays off). OCR is local (the English model ships in the app); nothing is uploaded; there are no network calls in `electron/content/` (enforced by a test that now also scans `visual/`).
- **QR payloads are text**: decoded, control/bidi characters stripped, length-capped, classified (`url`, `mailto`, `tel`, `sms`, `wifi`, other scheme, text) and displayed. They are never opened, resolved or launched. Only `http(s)` and a short list of dangerous schemes (`javascript:`, `data:`, `file:` ...) are fed to the URL analyzer, which is a pure string function (no DNS, no requests).
- **Image engine isolation**: `sharp` is loaded lazily; if its native binary is missing, visual analysis degrades to UNSUPPORTED instead of breaking the app. The UI renders decoded text as text (never as links).
- **Cache**: OCR results are cached by SHA-256 of the exact bytes read, only when fully COMPLETED, with the limits in the key; a changed file can never hit a stale entry. A file that changes between static analysis and extraction is flagged as possibly stale (PARTIAL).
- **Limitation**: OCR/QR evidence is best-effort. A document can defeat OCR (distorted text, other languages, tiny fonts) and a QR code can be unreadable; SafePeek never treats "nothing found" as proof of safety.

## 4. Threat engine
`electron/threat` is a pure, synchronous, deterministic rule engine: the same inputs always give the same outputs. Each rule emits an indicator with a category, severity, weight, evidence and source. There is no machine learning and no network access. Rules include file/extension disguise, executable and script content, PDF/Office/HTML, archives, URLs (parsed as strings, never visited), and phishing/scam language with correlation between text and links. The engine is the **only** component that decides the risk status. Explanation, alert and AI code only read the stored assessment.

## 5. Risk scoring
The score (0-100) is **heuristic**. It is a sum of weighted indicators with de-duplication, diminishing returns and severity guards (High risk needs at least one HIGH indicator; Critical needs two HIGH or one CRITICAL). Bands: Low risk >= 20, Suspicious >= 40, High risk >= 60, Critical >= 80. Weights are hand-tuned and **not calibrated on a malware corpus**. The score is not a probability and is not a mathematical guarantee of safety: expect false positives (legitimate urgent letters, installers, scripts that download) and false negatives (novel, obfuscated, encrypted, image-only or non-English content). Confidence is reported separately. Incomplete analysis (failed, partial, truncated or unsupported content) is reported as Unknown, never Safe.

## 6. Electron security
- `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`. The renderer has no access to Node, `require` or `process`.
- **Preload** exposes a fixed set of functions through `contextBridge`. They take ids and booleans only; no path, destination or command ever crosses from the renderer.
- **IPC validation** (`electron/ipc/validate.ts`): one gate accepts calls only from SafePeek's own page (bundled `file://.../dist/index.html`, or the Vite dev server in development); ids must match `^[A-Za-z0-9-]{8,64}$`; confirmations must be the boolean `true`; settings are normalized to known keys with safe defaults and written atomically. Handlers that accepted renderer paths (`files:stat`, `pickFolder`) were removed.
- **Renderer isolation**: strict Content-Security-Policy (`default-src 'self'`, `script-src 'self'`, `img-src 'self' data:`); `window.open` denied; navigation to any untrusted URL blocked; `<webview>` blocked; all permission requests denied; renderer crash triggers a reload; a single-instance lock is held.
- Windows notification identity is set with `setAppUserModelId('com.safepeek.app')`.

## 7. Path security
`validatePath` (`electron/agent/paths.ts`) rejects: empty, over-long or NUL-containing paths; non-absolute paths; `..` traversal segments; Win32 device-namespace paths (`\\?\`, `\\.\`); and NTFS alternate data streams (`file.txt:stream`). UNC network paths (`\\server\share`) are refused as **newly added** monitored folders but allowed for files already tracked (redirected Downloads). Symlinks and junctions: monitored folders that are symlinks are refused; quarantine, restore and open call `lstat`/`realpath` and refuse symlinked files, symlinked vault or destination folders, and anything whose resolved path leaves its expected folder. Symlink handling is exercised on Linux; **junction and ACL behaviour on Windows has not been run** and relies on the same code paths.

## 8. Quarantine security
- Files are moved (never copied-then-left) to `userData/quarantine/files/<hash>_<id>_<name>.quarantine`, a non-launchable suffix. Metadata is written only after the move and size are verified; a failure never claims success.
- Move order: validate path -> `lstat` (refuse symlinks / non-files) -> refuse if the vault is a symlink -> SHA-256 -> rename (or copy + verify + delete across drives, with rollback; never overwriting) -> verify.
- **Hash verification**: the vault copy is re-hashed; a mismatch with the analyzed version is flagged. Restore re-validates the stored vault path (tampered metadata is rejected), verifies the SHA-256, refuses to restore into the vault, refuses symlinked destinations, and never overwrites an existing file (adds "(restored)").
- **Permanent deletion** requires explicit confirmation, deletes only the vault copy, and keeps a DELETED record. Restore of Suspicious/High/Critical files requires explicit confirmation.
- The quarantine folder is excluded from monitoring; quarantined files are never opened, previewed, rescanned or revealed. The renderer-visible record contains no vault path.
- A file modified after analysis can still be quarantined (isolation is the safe direction) and the record notes it; Open and Restore refuse changed files.
- **Safe open**: the hash and path are re-checked immediately before launch; executables and scripts always require confirmation; Suspicious, Critical and Unknown always require confirmation; High risk requires it unless the user relaxes that setting (Critical cannot be relaxed); a changed, missing or symlinked file is not opened. `ProtectionService.openFile` is the only code path that can launch a file.

## 9. AI security
- The deterministic **local explanation is always generated first** and is the default. The AI layer is optional, off by default, and can only reword; it never changes status or score.
- **No automatic upload.** An external provider (Anthropic or OpenAI) is contacted only if AI is enabled, a provider/model/key are set, the user presses the button on a specific file, and the user confirms a disclosure that shows the exact payload. The original file, its bytes, extracted/OCR text, URLs and paths are never sent; file name and short evidence snippets only with separate opt-ins.
- **Prompt-injection protection** (`electron/ai/promptBuilder.ts`): the prompt separates SYSTEM instructions, SECURITY EVIDENCE (structured facts from the engine) and UNTRUSTED FILE CONTENT (opt-in, JSON-encoded, delimited, delimiters neutralised).
- **Output validation** (`electron/ai/explanationEngine.ts`): JSON shape and length limits are enforced and text is sanitized. Output is rejected if it names malware families, claims antivirus/VirusTotal results, attributes an actor, guarantees safety, includes links or markup, tells the user to open/run something, echoes injection text, quotes a different score, or uses a higher risk label than the engine. On any rejection or failure the local explanation is shown.
- **API key protection**: stored only through Electron `safeStorage`; if OS encryption is unavailable the key is **not** saved; it is never sent to the renderer, logged, or cached in results; HTTP redirects are refused (`redirect: 'error'`) so a redirect cannot carry the key. Network code exists only in `electron/ai/explanationService.ts` (enforced by `tests/phase6.security.test.ts`). `safeStorage` behaviour on Windows has not been verified.

## 10. Data at rest
`userData/` (per-user, plain JSON) holds file records, results, history, alerts and the quarantine vault. Only the API key is encrypted. Quarantined files are moved, **not** encrypted or defanged. JSON stores validate each record on load, write atomically (temp file + rename with retry on `EPERM`/`EBUSY`) and keep at most three corrupt copies.

## 11. Limitations
- **SafePeek cannot guarantee detection of every malicious file and does not replace a full antivirus, EDR, sandbox, or enterprise security product.**
- Heuristic engine without signatures, reputation or behaviour analysis; weights are uncalibrated.
- Parsers and the threat engine run in the Electron main process. Timeouts reject a result but cannot preempt in-flight CPU work; a hostile file can cause short stalls. A utility process is the proper fix and is not implemented.
- RAR/7z/GZIP contents, legacy OLE2 Office macros, and scanned PDFs are not inspected.
- Quarantine does not protect against software that already opened the file.
- The installer is not code-signed; SmartScreen may warn. Signing is a release decision not yet made.
- Windows-specific behaviour (toasts, `safeStorage`, junctions, ACLs, exclusive locks, installer) has **not** been verified on Windows.
- `npm audit` advisories in transitive development dependencies (the electron-builder toolchain) have not been addressed.

## 12. Reporting a vulnerability
Report suspected vulnerabilities privately to the maintainers of this project rather than in a public issue, with the SafePeek version (shown in the sidebar) and steps to reproduce. Do not attach live malware.
