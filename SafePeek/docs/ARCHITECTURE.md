# SafePeek Architecture

Electron app: **main process** (`electron/`) owns filesystem access; **renderer** (`src/`, React) is sandboxed with `contextIsolation` and talks to main only through the narrow `window.safepeek` bridge (`electron/preload.ts`, typed in `src/types/global.d.ts`).

```
Renderer pages -> services (fileService, scanService, storageService, notificationService)
                    |-> Repository interface (MockRepository only in browser preview mode; the packaged app always uses the real repository backed by the Electron agent)
                    |-> Analyzer[] / PreviewService / ThreatEngine interfaces (src/types)
Renderer -> preload bridge -> electron/ipc/index.ts (validated, read-only operations)
```

## Extension points
- `Repository` (storageService.ts): swap `MockRepository` for a real store.
- `Analyzer` (types/scan.ts): register with `scanService.register()`. Phase 3 static, Phase 4 content, Phase 5 threat.
- `PreviewService` (types/scan.ts): sanitized representations only.
- `ThreatEngine` (types/threat.ts): scores indicators into a risk level.
- IPC: add handlers in `electron/ipc/index.ts`; expose each in `preload.ts`.

## Security principles
1. Never execute an incoming file automatically.
2. Never launch suspicious files during analysis.
3. Never silently upload user files.
4. Never claim a file is "100% safe".
5. Treat file content as untrusted input.
6. Keep analysis modular (one Analyzer per concern).
7. Keep the original file separate from preview representations.
8. Quarantine is an isolated storage concept (own directory, renamed/neutralized files).
9. Validate file paths (`validatePath` in the IPC layer).
10. Avoid shell execution of untrusted filenames/content (no `exec`/`shell.openPath` on analyzed files).

## Phase 2: monitoring pipeline (electron/agent/)
```
chokidar watcher (one per enabled folder, MonitoringAgent)
  -> FileEventService.handle(): in-folder check, temp-file filter (config.ts), in-flight dedupe
  -> waitForStable(): async stat() polling until size+mtime unchanged N checks (never reads content)
  -> signature dedupe (path + size:mtime) -> DetectedFile record -> StateStore (userData/safepeek-state.json, atomic write)
  -> AgentEvent log + notify() (Electron Notification, honors settings.json `notifications`) + 'agent:changed' push to renderer
Renderer: IpcRepository (storageService) -> useLive() hook reloads on 'agent:changed'.
```
- Electron-free modules (agent/*) are unit/integration tested with real chokidar in `tests/agent.test.ts`; Electron glue lives only in `main.ts` and `ipc/index.ts`.
- IPC exposes only: monitoring status/enable, add folder (picker runs in main), remove/enable folder, list files/events, dev test-file creation. The renderer never supplies paths to watch.
- Shared types are mirrored in `electron/agent/types.ts` and `src/types/monitoring.ts` (renderer cannot import from electron/). Keep in sync.
- Corrupted state is renamed `*.corrupt-<ts>` and defaults are used. Downloads path is resolved with `app.getPath('downloads')` at every start.

## Phase 3 — Static analysis pipeline
```
chokidar -> FileEventService (temp filter, stability, dedupe) -> DetectedFile (pending)
         -> onFileRecorded -> AnalysisService queue -> analyzeFile():
            stat -> SHA-256 (stream) -> magic-byte type -> container inspectors (PE | PDF | OOXML/ZIP | script/text)
            -> static indicators -> AnalysisResult -> StateStore (persisted) -> agent:changed -> UI
```
Files are only read as bytes. Archives are never extracted to disk (entry names are flagged for Zip Slip). Indicators carry a machine-readable `code` for the Phase 5 engine; no scoring exists in Phase 3. Types: `electron/analysis/types.ts` mirrored in `src/types/analysis.ts`.


## Phase 4 — Content Intelligence + Safe Preview
```
FILE ARRIVES -> Phase 2 watcher -> FileRecord -> Phase 3 AnalysisService (static facts)
   -> onAnalyzed -> ContentService queue -> extractContent():
        pickExtractor (pdf|docx|xlsx|pptx|image|archive|text; never executables)
        -> extractor output -> sanitize (control/bidi chars, caps) -> links filter -> summarizer -> previewService
   -> userData/content/<fileId>.json  (full ContentResult)  +  light fields on FileRecord
   -> IPC content:get(id) -> FileDetail / SafePreview (React text nodes only)
```
Principles: local only (no network code in `electron/content`, enforced by a test), nothing executed or opened, archives never extracted, URLs are data, no verdict (Phase 5).

### Extraction limits (`electron/content/limits.ts`)
| Limit | Default |
|---|---|
| MAX_FILE_SIZE (PDF/Office/image read into memory) | 50 MB |
| TEXT_PREVIEW_BYTES (plain text read) | 100 KB |
| MAX_TEXT_LENGTH (chars kept) | 200,000 |
| MAX_PDF_PAGES / MAX_PDF_PAGE_CHARS | 50 / 20,000 |
| MAX_OFFICE_PART_BYTES (uncompressed per package part) | 8 MB |
| MAX_ARCHIVE_ENTRIES / MAX_ARCHIVE_DEPTH (indentation) | 1000 / 12 |
| MAX_OCR_PIXELS | 25,000,000 |
| MAX_IMAGE_PREVIEW_BYTES | 4 MB |
| Sheets / rows / cols / slides / tables / links | 20 / 200 / 30 / 100 / 50 / 200 |
| TIMEOUT_MS / OCR_TIMEOUT_MS | 30 s / 90 s |
Memory is bounded indirectly by these caps (no separate heap quota).

### ContentResult statuses
`NOT_STARTED, QUEUED, ANALYZING, COMPLETED, PARTIAL, UNSUPPORTED, FAILED`. Types are mirrored in `src/types/content.ts`.


## Phase 5 — Threat & Risk Detection Engine (v0.5.0)
```
Watcher -> AnalysisService (static) -> ContentService -> ThreatService -> assessThreat() [pure rules + scoring]
   -> userData/threat/<fileId>.json (full ThreatAssessment) + FileRecord summary (riskLevel, threatStatus, threatScore, ...)
   -> IPC threat:get(id) / threat:rerun(id) -> FileDetail ThreatPanel, Files, Dashboard, Activity
```
Hooks: `ContentService.onFinished`, `AnalysisService.onFailed`. New events: `threat-started`, `threat-completed`, `threat-failed`, `suspicious-file-detected`, `high-risk-file-detected`. Full design, scoring and limitations: `docs/THREAT_ENGINE.md`.


## Phase 6 additions
`electron/ai/` (explanations, prompt builder, output validation, secret store) and `electron/protection/` (quarantine, alerts, history, open safety, settings, orchestrator). `ThreatService.onAssessed` hands each stored Phase 5 assessment to `ProtectionService`. See `docs/PHASE6.md`.
