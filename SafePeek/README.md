# SafePeek

> **Know what's inside before you open it.**

SafePeek is a Windows desktop security assistant. It watches your Downloads folder (and any folders you add), automatically analyzes each new file **without ever running it**, shows you what is inside, explains in plain language whether anything looks risky, and lets you quarantine, restore or delete files safely.

**Status:** v1.1.0 - Phase 8 (visual & cross-modal threat intelligence) on top of the v1.0.0 release candidate. See [`CONTINUATION.md`](CONTINUATION.md) for exactly what has and has not been verified. In particular, the Windows runtime and the Windows installer have **not** been verified yet.

> SafePeek cannot guarantee detection of every malicious file and does not replace a full antivirus, EDR, sandbox, or enterprise security product. A result of "Safe" means *no suspicious indicators were found*, not that a file is guaranteed harmless.

## What SafePeek does
1. **Detects** new files in protected folders once they have finished downloading.
2. **Analyzes** them statically: SHA-256, real file type vs. extension, double extensions, executables and scripts, PE headers, PDF structure, Office macros/external links, archive listings, URLs.
3. **Reads** the content locally and safely: PDF, Word, Excel, PowerPoint, text/CSV/JSON/log, image OCR, and archive trees - shown as an inert preview.
4. **Assesses** risk with a deterministic, explainable rule engine (score 0-100, confidence, evidence, recommendations).
5. **Explains** the result in plain language (offline; optional AI wording if you turn it on).
6. **Alerts** you with in-app alerts and Windows notifications.
7. **Protects**: quarantine, restore, permanent delete, confirmation before opening risky files, threat history.

## Visual & cross-modal analysis (v1.1)
SafePeek can read what a suspicious file *shows*, not just what it says. Using **bounded, local-only OCR** it reads text inside images (PNG, JPG, WebP, GIF) and inside **scanned / image-only / mixed PDFs**, decodes **QR codes** (as text only, never opened), extracts **URLs** from that text, and **correlates** the visual evidence with the file's technical characteristics. Everything goes through the *existing* deterministic threat engine: the visual channels are an extra **evidence source**, not a second engine. Each indicator says where it came from (document text, OCR, QR code, static analysis) and the same evidence seen through two paths is counted once. Nothing is uploaded and no URL is ever opened. Details: [`docs/PHASE8.md`](docs/PHASE8.md). **OCR is best-effort**: it is not guaranteed to read every image, font, language or low-quality scan.

## Key features
- Automatic monitoring of Downloads and custom folders (stability detection, temp-file filtering, duplicate prevention).
- Static analysis, content extraction, safe preview, local OCR (bundled English model; no downloads).
- Phishing / scam / credential-theft language rules, disguised-executable detection, URL look-alike analysis (URLs are never visited).
- Risk levels: Safe, Low risk, Suspicious, High risk, Critical, Unknown. Incomplete analysis is reported as Unknown, never as Safe.
- Quarantine with hash verification, confirmed restore, confirmed permanent delete.
- "Open Anyway" confirmation for risky or unanalyzed files; executables always ask.
- Local-first AI explanation layer; the optional external provider is off by default.
- Dashboard, Files, File Detail, Alerts, Activity, Threat history, Quarantine, Settings.

## Architecture
```
FILE -> WATCHER -> STATIC ANALYSIS -> CONTENT ANALYSIS -> THREAT ENGINE -> RISK ASSESSMENT
     -> EXPLANATION -> ALERT -> USER ACTION -> OPEN / QUARANTINE / RESTORE / DELETE
```
All of this runs in the Electron **main process**; the React UI only receives ids, results and booleans through a narrow preload bridge. Details: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/THREAT_ENGINE.md`](docs/THREAT_ENGINE.md), [`docs/PHASE6.md`](docs/PHASE6.md).

| Folder | Contents |
|---|---|
| `electron/agent` | watcher, stability check, file records, persistence |
| `electron/analysis` | static analysis (hash, magic bytes, PE, PDF, Office, ZIP, scripts, URLs) |
| `electron/content` | extraction, OCR, sanitizer, safe preview |
| `electron/threat` | rules, scoring, URL analysis, threat service |
| `electron/ai` | local explanations, optional AI prompt/validation, secret store |
| `electron/protection` | quarantine, alerts, history, open safety, settings |
| `electron/ipc`, `electron/main.ts`, `electron/preload.ts` | IPC validation, window hardening, bridge |
| `src` | React UI |
| `tests` | Vitest suites and fixtures |

## Technology stack
Electron 31, React 18, TypeScript (strict), Vite 5, Vitest, chokidar, pdf.js (legacy build), yauzl, fast-xml-parser, tesseract.js, electron-builder (NSIS). Plain CSS, no UI framework.

## Security model (summary)
Never execute incoming files; treat all content as untrusted; context isolation on, Node integration off, renderer sandboxed; every IPC input validated; the renderer never supplies a path; hash-verified quarantine; deterministic detection with the AI only explaining. Full detail: [`docs/SECURITY.md`](docs/SECURITY.md).

## Privacy model
Local-first. Files are analyzed on your PC and nothing is uploaded. No reputation or cloud-scanning service is called. Optional AI explanation is **off by default**; if you enable it, it sends only evidence metadata (never the file, its text, its URLs or its path), and only after you press a button and confirm the exact payload. API keys are stored with OS-backed encryption (Windows `safeStorage`) or not stored at all.

## Installation (end users)
Run `SafePeek-Setup-1.1.0.exe` and follow the wizard (per-user install, you can change the folder). See [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md). The installer is **not code-signed**, so Windows SmartScreen may warn on first run.

## Development
Requires Node.js 20+ and npm.
```
npm install
npm run dev          # compiles electron/, starts Vite on :5173, launches Electron
```
In development the UI is served from the local Vite dev server on port 5173; the packaged app loads bundled files only.

## Testing
```
npm run typecheck    # tsc --noEmit (renderer + tests)
npm test             # vitest run
npm run fixtures     # regenerate the synthetic sample files in tests/fixtures
```
There is no lint script. Test status and what was and was not run: [`docs/FINAL_TEST_REPORT.md`](docs/FINAL_TEST_REPORT.md).

## Building and Windows packaging
```
npm run build        # typecheck + compile electron/ + vite build
npm run verify:ocr   # runs OCR/QR/PDF checks under Electron's own runtime (run after build:electron)
npm run package      # build + electron-builder --win --x64  -> release/SafePeek-Setup-1.1.0.exe
npm run package:dir  # unpacked app in release/win-unpacked (quick smoke test)
```
Configuration lives in the `build` section of `package.json`: appId `com.safepeek.app`, NSIS (not one-click, per-user, choose install folder, desktop and Start menu shortcuts), x64, `build/icon.ico`. Build the installer on Windows. **The packaging configuration is ready; the installer has not been built or run in the environment where this release candidate was prepared.**

## Limitations
- Heuristic detection: expect false positives and false negatives (novel, obfuscated, encrypted, image-only or non-English content). No signatures, reputation lookup or sandbox.
- Only ZIP/JAR archives are listed; RAR/7z/GZIP are identified but not opened. Legacy Office (.doc/.xls/.ppt) files are identified but not inspected for macros.
- Scanned PDFs are not OCR'd; PDF preview is extracted text, not a rendered page.
- Closing the SafePeek window quits the app (no tray); monitoring runs only while SafePeek is running. "Start with Windows" can launch it at sign-in.
- Parsers and the threat engine run in the main process without a hard preemptive timeout.
- Per-file result caches are not garbage-collected; files deleted outside SafePeek stay listed.
- Quarantine moves files into a protected folder; it does not encrypt or defang them and cannot affect software that already opened the file.
- Windows-specific behaviour is covered by code paths and mocked errors, not by a Windows run.

## Documentation
- [`docs/PHASE8.md`](docs/PHASE8.md) - visual & cross-modal analysis (v1.1): design, limits, test evidence, known limitations.
[`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) - [`docs/SECURITY.md`](docs/SECURITY.md) - [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) - [`docs/THREAT_ENGINE.md`](docs/THREAT_ENGINE.md) - [`docs/PHASE6.md`](docs/PHASE6.md) - [`docs/PHASE7A.md`](docs/PHASE7A.md) - [`docs/PHASE7B.md`](docs/PHASE7B.md) - [`docs/FINAL_TEST_REPORT.md`](docs/FINAL_TEST_REPORT.md) - [`CHANGELOG.md`](CHANGELOG.md) - [`CONTINUATION.md`](CONTINUATION.md)
