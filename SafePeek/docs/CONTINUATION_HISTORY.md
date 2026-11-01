> **ARCHIVED.** This is the historical per-phase handoff log (Phases 1-7A), kept for its detailed implementation notes and limitations. Its "Current phase" statements are superseded by the root `CONTINUATION.md`, which is the current status.

# Continuation Guide

## Current phase
**Phase 7A - Final integration + runtime hardening + testing** (version 0.7.0). Cumulative: Phase 1-6 + 7A. Details: `docs/PHASE7A.md`. Do not rebuild; extend.

## PHASE 7A COMPLETE
Completed: pipeline integration review (no duplicate pipelines), race fixes (quarantine vs pipeline, stale verdicts, change during analysis, locked files), analysis timeout, safe-open hardening (hash re-check, executables always confirm), quarantine/restore/delete audit (hash verification, symlink/vault containment), path validation (device paths, ADS, UNC folders), IPC audit (sender gate, strict ids, settings normalization, removed `files:stat`), persistence resilience (per-record validation, atomic writes), main-process hardening, Windows toast identity, UI loading/error states, 140 new tests.

Verified (Linux sandbox): `npm install`, `npm run typecheck`, `npm test` (424 pass), `npm run build`. Real Electron 31 under Xvfb: window loads, bridge exposes 43 functions, `require`/`process` undefined in the renderer, removed `statFile` absent, malformed id rejected, bad settings rejected, a disguised `invoice.pdf.exe` dropped into the watched folder -> HIGH_RISK 71/100 + alert, open refused without confirmation, quarantine succeeded and the renderer-visible record has no vault path.
Not verified: **Windows runtime** (toasts, click-to-navigate, safeStorage, junctions, ACL/locking), restore/delete/settings persistence clicked through the real UI, visual appearance, `npm run package` (electron-builder/NSIS never run), real AI provider calls, lint (no lint script exists).

Known issues: "Known limitations" in `docs/PHASE7A.md`.

Phase 7B should:
1. Run on Windows: watcher, toast notifications, safeStorage, restore/delete through the UI; fix what surfaces.
2. Final UI polish (screenshots of every page, empty/error states, destructive-action styling) and user docs.
3. Release config: icon, electron-builder NSIS settings, `npm run package`, signing decision, autostart/tray (settings exist but are inert), changelog.
4. Optional: utility process for parsers/threat engine with real timeouts; cache garbage collection.

---
# Phase 6 notes (previous continuation, unchanged below)

## Current phase
**Phase 6 - AI Explanation + Alerts + Quarantine & Protection** (version 0.6.0). Cumulative: Phase 1 + 2 + 3 + 4 + 5 + 6. Do not start from scratch; extend this project. Phase 6 design: `docs/PHASE6.md`. Phase 5 design: `docs/THREAT_ENGINE.md`.

## Phase 6 summary
- New: `electron/ai/*`, `electron/protection/*`, IPC/preload (ids + booleans only), renderer `src/types/phase6.ts`, `src/services/protectionService.ts`, `src/components/security/{ExplanationPanel,ActionBar}.tsx`, pages `Alerts`, `ThreatHistory`, real `Quarantine`, extended `Settings` (Protection, Notifications, AI Explanation) and `Dashboard` (Safe/Low/Suspicious/High/Critical/Quarantined/Unread alerts from persisted data). File Detail: hero + safe actions -> "Why is this risky?" (Simple/Technical) -> Phase 5 panel -> Phase 4 content -> static findings.
- Minimal changes to older phases: `ThreatService` has an optional `onAssessed` hook; `FileEventService`/`MonitoringAgent` have an optional `isExcluded` (the quarantine folder is never monitored); `DetectedFile` has `quarantineState/quarantineId/quarantinedAt`; new event types; the Phase 5 QUARANTINE recommendation *text* was updated (no scoring change, `ENGINE_VERSION` unchanged).
- Persistence: `userData/security/{settings,alerts,history,secrets}.json`, `userData/quarantine/{quarantine.json,files/}`, `userData/explanations/<id>.json` (optional AI results only).
- Defaults: AI OFF, auto-quarantine OFF, require confirmation ON, informational alerts OFF.

## Tests
284 tests in 12 files, all passing in the authoring environment: Phase 1-5 (126, unchanged apart from two unused-import fixes) + `ai.test.ts` (50), `quarantine.test.ts` (50), `protection.test.ts` (48: alerts, dedupe, auto-quarantine, open safety, rescan, history), `phase6.security.test.ts` (9, static boundary checks), `phase6.fullpipeline.test.ts` (1: real chokidar watcher -> Phase 3 -> real Phase 4 -> Phase 5 -> explanation -> alert -> notification -> quarantine -> restore).

## What was and was NOT verified (Phase 6, Linux sandbox)
VERIFIED: `npm install`, `npm run typecheck`, electron `tsc`, `vite build` (`npm run build`), `npm test` (284 pass). The real Electron 31 app was launched on Linux under Xvfb and probed through the DevTools protocol: the window loads, the preload bridge exposes 45 functions, `require`/`process` are undefined in the renderer, the new IPC handlers respond, a malformed id is rejected, Dashboard and sidebar render, and with the live watcher a disguised executable (`invoice.pdf.exe`) dropped into Downloads was assessed HIGH_RISK (77/100), produced an alert, a local explanation and a history entry, refused to open without confirmation, was physically moved into the quarantine folder on request, and could not be opened afterwards.
NOT VERIFIED: **Windows** runtime (Windows toast notifications and click-to-navigate, Windows path/permission behaviour, `safeStorage` on Windows - it was unavailable in the Linux sandbox, so key saving was only tested with a fake encryptor); the visual appearance of the new screens (not screenshotted); AI provider calls against the real Anthropic/OpenAI APIs (mocked `fetch` only); `electron-builder`/NSIS Windows packaging (not run); clicking through the confirmation dialogs in a real window; desktop notifications on Linux (no notification daemon).

## Known limitations / remaining work
- See `docs/PHASE6.md` "Limitations". Phase 5 limitations (`docs/THREAT_ENGINE.md`) still apply: heuristic, uncalibrated weights, engine on the main thread.
- Phase 7 / not done: installer, signing, release, tray/autostart (settings exist but are inert), UI automation tests, utility process for parsing, garbage collection of per-file JSON caches, quarantine encryption.

---
# Earlier phases (previous continuation notes, unchanged below)


## Current phase
**Phase 5 — Threat & Risk Detection Engine** (version 0.5.0). Cumulative: contains all of Phase 1 + 2 + 3 + 4 + 5. Do not start from scratch; extend this project. Full Phase 5 design: `docs/THREAT_ENGINE.md`.

## Completed
- **Phase 1** desktop foundation (Electron/React/TS shell, navigation, Dashboard, Files, Activity, Quarantine UI, Settings, File Detail).
- **Phase 2** automatic file monitoring (chokidar, stability check, temp-file filter, dedupe, persisted state, notifications).
- **Phase 3** static analysis (SHA-256, magic types, mismatch, double extension, PE/PDF/Office/ZIP/script, URL extraction).
- **Phase 4** content intelligence + safe preview (PDF/DOCX/XLSX/PPTX/image OCR/text/archive tree, sanitizer, limits).
- **Phase 5** threat & risk detection engine (below).

## Phase 5 implementation details
- `electron/threat/` — `types.ts` (ThreatAssessment, ThreatIndicator, categories...), `threatEngine.ts` (`assessThreat`, pure/deterministic; `RULES` registry; coverage + confidence + recommendations), `scoring.ts` (all weights/caps/thresholds, de-dup, diminishing returns, correlation + breadth bonus, severity guards), `urlAnalyzer.ts`, `lure.ts` (phrase library, negation, script sniffing), `rules/{fileRules,executableRules(+scriptContentRules),documentRules(pdf/office/html),archiveRules,urlRules,contentRules,socialEngineeringRules,util}.ts`, `threatService.ts` (queue, persistence in `userData/threat/<id>.json`, FileRecord summary fields, events), `index.ts`.
- Pipeline: `main.ts` creates `ThreatService`; `ContentService.onFinished` and `AnalysisService.onFailed` enqueue it; `threat.resume()` on start-up. Re-analysis resets stale verdicts (`riskLevel` back to `unknown`) until the new assessment is stored. `FileRecord.riskLevel` is now `safe|low|suspicious|high|critical|unknown`.
- IPC/preload: `threat:get`, `threat:rerun` (`getThreat`, `rerunThreat`); input validated (id string; id format checked before reading disk).
- Events: `threat-started`, `threat-completed`, `threat-failed`, `suspicious-file-detected`, `high-risk-file-detected` (Activity shows risk for them).
- UI: `ThreatPanel.tsx` at the top of File Detail (status, score, confidence, "Why?", recommendations, indicators with severity/category/evidence/source, analysis coverage, score breakdown, limitations, disclaimer); Files page = filter chips (All, No indicators, Low, Suspicious, High, Critical, Unknown) + table (Filename, Type, Detected type, Risk, Score, Status, Detected); Dashboard (Files scanned, Suspicious, High-risk, Critical, Requiring review, Recent threat activity — all from persisted results); Activity shows threat events. Wording never says "safe/virus-free"; SAFE displays as "No indicators detected".
- Privacy/security: no network/process/eval APIs in `electron/threat` (enforced by a test); URLs are parsed as strings only; nothing uploaded.

## Tests
- Phase 1-4: 60 tests (unchanged; `tests/agent.test.ts`, `analysis.test.ts`, `content.test.ts`, `format.test.ts`).
- Phase 5 new: `tests/threat.test.ts` (62 cases: file types/extension disguise, double extension, PDF, Office, archives, content/phishing/scam, URLs, correlation, de-dup, false-positive protection, partial/failed/unsupported/truncated => never SAFE, determinism, wording, engine-security), `tests/threat.pipeline.test.ts` (3 cases: real Phase 3 -> content stub -> ThreatService -> persistence -> events; failed static analysis -> UNKNOWN; engine exception -> FAILED), `tests/threat.fullpipeline.test.ts` (1 case: real chokidar watcher -> Phase 3 -> real Phase 4 extractors -> Phase 5 -> persisted -> events). `tests/helpers/threat.ts` builds Phase 3 results from real files and synthetic Phase 4 results.

## What was and was NOT verified in the authoring environment
VERIFIED: the new `electron/threat` code and `threatService` type-check under `strict` (tsc, with `@types/node`); `tests/threat.test.ts` (62) and `tests/threat.pipeline.test.ts` (3) pass when run through a small stand-in for vitest (`describe/it/expect` subset) against the REAL Phase 3 analyzer (yauzl 2.x from a local copy); `tests/format.test.ts` passes the same way.
NOT VERIFIED: the sandbox had no access to the npm registry, so `npm install`, **real `vitest`, `npm run typecheck`, `npm run build` (vite) and `electron-builder` were not run**; the renderer (React/TSX) was only checked for syntax and non-JSX type errors; `tests/threat.fullpipeline.test.ts` (needs chokidar, pdfjs, fast-xml-parser, tesseract) and the existing Phase 1-4 tests that need those packages (`agent`, `analysis`, `content`) were **not run after the Phase 5 changes** — run `npm install && npm test` first. Electron has still never been launched (no display): window, IPC bridge, notifications and the new UI are untested at runtime.

## Known limitations (Phase 5)
- Heuristic, hand-tuned weights not calibrated on any corpus; expect false positives (legitimate urgent/financial letters, scripts that download, installers) and false negatives (novel, obfuscated, encrypted, image-only or non-English content). See `docs/THREAT_ENGINE.md`.
- PE: no signature verification, DLL-level imports only, no entropy/strings/resources. OLE2 macros and RAR/7z/GZIP contents are not inspected. Scanned PDFs are not OCR'd. Brand look-alike table is small.
- Threat results are not garbage-collected when a file record is dropped (`userData/threat/`, like `content/`).
- Engine runs on the main thread (rules are linear-time regexes over <= 200 KB of text; a worker/utility process is still the top hardening item).
- Phase 3/4 text-to-URL extraction covers only what those phases extract.
- Files page replaced the narrow side list with a table + detail below; no sorting/pagination yet.

## What Phase 6 must build
AI explanation (opt-in, local-first; consume `ThreatAssessment.reasons/indicators/evidence/limitations` — never raw files unless the user explicitly consents) + human-readable threat explanations + alerts (native notifications that include the Phase 5 status) + quarantine/protection (isolated storage, restore/delete, user decisions; the `QUARANTINE` recommendation is advice only today). Do not change the scoring semantics without updating `docs/THREAT_ENGINE.md` and the tests.

## Phase 4 notes (still valid)
Phases 1-3 are unchanged in behaviour (see "Phase 3 notes" below). Phase 4 adds `electron/content/`:
- `extractor.ts` pipeline + `ContentExtractor` interface + registry (pdf, docx, xlsx, pptx, image, archive, text). Per-file timeout (30 s; OCR 90 s), every parser failure becomes a `PARTIAL`/`FAILED` result, never an exception. Executables are never handed to any extractor.
- `pdfExtractor.ts` pdf.js 3.11 legacy CJS build (text, per-page text, link annotations, metadata, page count). No canvas rendering, no scripting, no navigation. Encrypted -> PARTIAL; corrupt -> FAILED; max 50 pages.
- `officeExtractor.ts` own OOXML parsers (yauzl + fast-xml-parser, DOCTYPE stripped): DOCX (headings via styles, paragraphs, tables in order, hyperlinks, images listed, core properties), XLSX (sheets, dimension, cells via shared strings, cached formula values only - formulas are never evaluated, hyperlinks, external-link warning), PPTX (slide order, titles, text, notes, hyperlinks). Macros/ActiveX/embedded objects (from Phase 3) -> "Embedded content detected. SafePeek has not executed this content."
- `imageExtractor.ts` + `ocr.ts` local OCR with tesseract.js 5 and the bundled English model (`@tesseract.js-data/eng`, no download, no network). Dimensions parsed from headers (PNG/JPEG/GIF/WebP). Inline preview = data: URI of the original bytes (<= 4 MB). OCR skipped above 25 MP.
- `textExtractor.ts` bounded read (first 100 KB only), BOM/UTF-16/UTF-8/Latin-1 fallback, binary detection, CSV/TSV -> table, HTML and scripts shown as inert text.
- `archiveExtractor.ts` ZIP/JAR entry tree from the Phase 3 listing (never extracted); flags executable/script entries, unsafe paths, encrypted entries; marks which entries are of an inspectable type. gz/7z/rar -> "Archive type detected. Content preview unavailable."
- `summarizer.ts` deterministic local summary: document type guess by keywords, title, entities (organizations, people, amounts, dates, emails, phones), key sections. Wording is "appears to contain ..." - it is NOT a risk verdict.
- `previewService.ts` chooses preview mode (pdf/document/spreadsheet/presentation/image/text/archive/unsupported). `sanitizer.ts` strips control/bidi characters, escapes, caps length, allows only http(s)/mailto/ftp link data. `limits.ts` central limits.
- `contentService.ts` queue (concurrency 1) started by `AnalysisService.onAnalyzed`; full `ContentResult` saved to `userData/content/<id>.json`, FileRecord keeps only `contentStatus, contentType, documentType, previewType, previewAvailable, contentSummary, contentTruncated`. Resumes unfinished files on startup. Events: `content-started`, `content-completed|content-failed`, `preview-generated`.
- IPC: `content:get(id)` (read-only, id validated, no paths from renderer), `content:rerun(id)`; preload `getContent`, `rerunContent`.
- UI: File Detail restructured (What's inside? -> Safe Preview -> Extracted content -> Static findings -> Phase 3 cards -> File information); `SafePreview.tsx` renders everything as React text nodes (no innerHTML/iframes/links); Files list shows Static/Content/Preview state; Dashboard shows content statistics; Activity shows new events.
- Tests: 60 passing (27 Phase 1-3 + 33 Phase 4: `tests/content.test.ts`). Synthetic fixtures in `tests/fixtures/` (`npm run fixtures` regenerates all except `job-offer.png`, which was rendered once with Pillow).

## Verified in the authoring environment
`npm run typecheck`, electron `tsc`, `vite build`, `vitest` (60 tests incl. real chokidar watcher -> Phase 3 -> Phase 4 pipeline with PDF/TXT/ZIP/EXE), compiled CommonJS output run against all 7 demo fixtures (incl. real local OCR).

## NOT verified
- **Electron has never been launched** (no display here): window, notifications, IPC bridge, React UI at runtime, and `electron-builder` packaging (asarUnpack entries for tesseract/pdf.js are untested) are untested. UI compiles and builds only.
- The interactive acceptance flow (copying files into a real Downloads folder with the app running) was covered by the automated watcher test, not by running the app.
- WebP/GIF OCR support depends on the bundled Leptonica build; only PNG OCR is tested.

## Partial / known limitations
- **No worker threads / separate process for parsing.** pdf.js and OOXML parsing run asynchronously in the main process (XML parse of an <= 8 MB part is synchronous). Limits bound the cost but a hostile file can still cause short stalls. Timeouts reject the result but cannot cancel in-flight CPU work. OCR runs in tesseract's own worker thread. Moving extraction to a utility process is the top hardening item.
- PDF "Safe Preview" is per-page extracted text, not a rendered page image (deliberate: no renderer can be proven to neutralise PDF actions). Layout, images and scanned/image-only PDFs are not shown (no PDF OCR).
- DOCX: text boxes, footnotes, headers/footers, tracked-change insertions inside complex fields and embedded images are not rendered; images are only listed. XLSX: no number/date formatting (raw stored values; dates appear as serial numbers), cached formula values only. PPTX: grouped shapes/tables/charts text may be missed. Legacy .doc/.xls/.ppt (OLE2) and password-protected OOXML (OLE2-wrapped) are not extracted.
- Archives: only ZIP/JAR are listed. Clicking an entry to inspect it **is not implemented** (entries are only marked `inspectable`); nested archives are not opened.
- Entity extraction/document classification are simple regex/keyword heuristics (English-oriented, can be wrong or miss). OCR is English only.
- Content results are kept per file id and never garbage-collected when a file record is dropped from state (`userData/content/` can grow).
- `npm audit` reports advisories in transitive dev dependencies (electron-builder toolchain); not addressed.

## Not implemented (later phases)


## How to run
```
npm install        # package-lock.json included (add ELECTRON_SKIP_BINARY_DOWNLOAD=1 if Electron cannot be downloaded)
npm run dev        # compiles electron/, starts Vite :5173, launches Electron
npm run typecheck
npm test
npm run build
npm run fixtures   # regenerate synthetic demo files (except job-offer.png)
npm run package    # Windows installer (untested)
```

## How to test Phase 4 manually
Copy each file from `tests/fixtures/` into Downloads while `npm run dev` is running: `salary-increment.pdf`, `internship-offer.docx`, `project-data.xlsx`, `project-presentation.pptx`, `college-notice.txt`, `scholarship.zip`, `job-offer.png`. Each should reach "Static: Analyzed" then "Content: Complete"; open it on the Files page: "What's inside?", Safe Preview, Extracted content, links as text. Also try an `.exe` (renamed harmless file with MZ header): "Safe Preview unavailable ... will not execute". Activity shows "Content analysis started", "Content extracted", "Safe preview generated".

## (Archived) Phase 5 plan from Phase 4 handoff — now implemented
Implement a transparent, explainable risk assessment (implement `ThreatEngine` in `src/types/threat.ts`; keep it in the main process). Inputs:
- Phase 3 `FileRecord.analysis` (`indicators[].code`, identity, PE/PDF/Office/archive facts, URLs)
- Phase 4 `ContentResult` via `ContentService.get(id)` (`extractedText`/`ocrText`, `summary.entities`, `summary.documentType`, `links`, `archiveEntries`, `embeddedContentWarning`)
- file metadata and structure.
Produce a score + reasons that cite which indicators/content features contributed (e.g. payment request amounts + urgency wording in an "offer letter", type mismatch, executable inside a scholarship archive). Write `riskLevel` on the FileRecord. Do not upload files or content anywhere; any hash/URL reputation lookup must be opt-in and off by default. Phase 6 (AI) will consume the same structured data.

## Phase 3 notes (still valid)
### Phase 3 completed
- `electron/analysis/` (main process, async, nothing ever executed/opened/extracted to disk):
  - `hash.ts` streaming SHA-256 (local only, 4 GB cap). `magic.ts` own magic-byte detection (PDF, PNG, JPEG, GIF, WebP, ZIP, GZIP, 7z, RAR, PE, DOS/MZ, ELF, OLE2, text/script/HTML) + declared-vs-actual mismatch table (`EXPECTED`). No third-party type library (deliberate: small, auditable).
  - `extensions.ts` extensible dangerous/script/decoy lists, double-extension check. `pe.ts` bounds-checked PE parser (arch, kind, subsystem, entry RVA, sections, imports, .NET flag, signature-block *presence* only, NOT verified).
  - `pdf.ts` raw token scan (+inflates `/ObjStm`, capped): version, pages, encryption, JS/OpenAction/Launch/AA/SubmitForm, embedded files, annotations, URIs, metadata. `office.ts` OOXML via `yauzl` (docx/xlsx/pptx, macros/vbaProject, ActiveX, embeddings, external relationships, core metadata). `zip.ts` central-directory listing only (`decodeStrings:false`, Zip-Slip name flagging, entry cap 5000, in-memory 1 MB part cap). `script.ts` language id + URL extraction. `urls.ts` text URL extraction (never visited).
  - `analyzer.ts` orchestrates stages, each isolated; failures become `status: 'partial'|'failed'` with reasons. Indicators are facts (`code`, severity info/warning/high, evidence). **No risk score/verdict**: `riskLevel` stays `unknown`.
  - `service.ts` `AnalysisService`: queue (concurrency 2), hooked via `FileEventDeps.onFileRecorded`; sets `analysisStatus`, `sha256`, `mimeType`, `detectedType`, `detectedUrls`, `indicators`, `analysis`; resumes pending files on startup; `reanalyze(id)`. Events: `analysis-started/completed/failed` (2 per file, no flooding).
- IPC `analysis:rerun` + preload `reanalyzeFile`. Types mirrored in `src/types/analysis.ts`; `ThreatIndicator` gained optional `code`.
- UI: FileDetail (real info, static findings, PE/PDF/Office/script/archive/URL/embedded cards, partial/failed banners, re-run), Files list (detected type, size, state, indicator count), Dashboard (Files detected/analyzed, Static indicators, Executables & scripts, URLs; no "threats blocked"), Activity labels.
- Tests: 27 passing (`tests/analysis.test.ts`, `tests/helpers/fixtures.ts` generate benign PE-header/ZIP/DOCX/PDF/PNG fixtures in memory; includes full watcher -> analysis -> store pipeline with `.crdownload` ignored).

### Phase 3 partial / limitations
- Worker threads NOT used: all work is async streaming/capped reads in main. Caps: PDF 16 MB scanned, text 2 MB, PE 4 MB read.
- PDF analysis is a raw token scan, not a full parser: obfuscated names (#-escapes), non-Flate/encrypted object streams and encrypted PDFs are not inspected (reported as partial). Page count is best-effort.
- OLE2 (.doc/.xls/.ppt) identified only, macros not inspected. GZIP/7z/RAR identified, contents not listed; nested archives not opened. Password-protected ZIP entries listed but unreadable (partial).
- PE: no signature verification, no entropy/packing analysis, no resource/string parsing. Images not inspected beyond type. No URL extraction from compressed Office body text or PE strings.
- Mismatch table covers common extensions only; unknown extensions are not judged. No behavioral sandbox, no malware signatures, no reputation lookup (a future hash-only lookup must stay disabled until Phase 5/6).
- Electron itself has still not been launched in the authoring environment (no display): window/notification/IPC/UI are untested at runtime. Verified: `npm run typecheck`, electron `tsc`, `vite build`, vitest (27 tests).
- Notification text now says "analysis starting". Mock data (browser-only dev) has no Phase 3 analysis.

### How to test Phase 2
1. `npm run dev`; header shows "Protection Active · Monitoring Active"; Settings lists Downloads.
2. Copy `tests/fixtures/test-document.txt` into Downloads (or Settings > Developer > Create test file).
3. Expect: toast "New file detected — analysis pending", row on Files, "New file detected" on Activity, Dashboard counts update.
4. Create `x.crdownload`: nothing happens; rename to `x.pdf`: detected.
5. Copy a large file: recorded only after copying finishes.
6. Settings > Monitoring off: new files ignored; on: resumes. Quit and restart: state restored.

### How to test Phase 3 manually
Copy into Downloads: a real PDF, a text file renamed `fake.pdf`, `invoice.pdf.exe` (e.g. rename any harmless exe/text), a zip with a `.exe` inside, a docx, a png. Each should reach "Analyzed" with type/hash/indicators on the detail page; Activity shows "Static analysis started/completed".

