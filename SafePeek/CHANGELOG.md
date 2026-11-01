# Changelog

All notable changes to SafePeek. Versions before 1.0.0 were internal development milestones.

## 1.1.0 - Visual & cross-modal threat intelligence (Phase 8)
- **Fixed: image OCR "Extraction timed out" / UNKNOWN.** Root cause found by running the pipeline under Electron's runtime: tesseract.js detects `process.versions.electron`, treats the local language-data path as a web address and never finishes starting, and the error was swallowed, so every image waited out the 90 s budget. Fixed by staging the bundled model in a plain directory and loading it through the engine's read-only cache. Also fixed: no downscaling (a ~12 MP dense image took 70 s on a fast machine), a timed-out OCR call kept running and blocked the next one, a crashed worker thread hung silently, and unneeded hOCR/TSV output was generated.
- **New safe image pipeline** (`sharp`): bounded decode, EXIF orientation, transparency flattening, downsampling (or enlargement of tiny images), grayscale + contrast normalization, dark-background inversion, banded OCR for dense pages.
- **Scanned / image-only / mixed PDFs**: pages without a text layer are OCR'd from their embedded images; text pages are not; direct text and OCR text are combined and distinguished in the UI.
- **QR codes** in images and PDF pages (several per image): decoded as text, classified, never opened.
- **URL extraction from OCR/QR text** (including scheme-less `www.` / path-bearing addresses) into the existing URL analyzer; URL analyzer gained deceptive-hostname, stacked-subdomain and many-hyphen checks.
- **Cross-modal correlation** rules (message + link through different channels, QR + pressure wording, text only in an image, file name vs lure theme, disguised image) using the existing scoring, correlation cap and de-duplication; evidence is **de-duplicated across extraction paths**.
- **Evidence sources**: every indicator/evidence item carries its origin (document text, OCR, QR code, static analysis, archive, combined).
- UI: Visual Analysis card, QR Codes Detected, Content sources, sourced "Why SafePeek flagged this", partial-analysis banner.
- SHA-256-keyed OCR cache; file-changed-during-analysis detection.
- Tests: 477 (424 existing + 53 new), plus `npm run verify:ocr` (Electron-runtime check).

## 1.0.0 - Final release candidate

### Added
- Automatic file monitoring of Downloads and custom folders, with file-stability detection, temporary-file filtering, duplicate-event prevention and persisted state
- Static file analysis: SHA-256, magic-byte type detection, extension mismatch, double extensions, executable/script detection, PE, PDF, Office and ZIP inspection, URL extraction
- Content intelligence: PDF, DOCX, XLSX, PPTX, text/CSV/JSON/log extraction, archive trees, local English OCR
- Safe, inert previews and plain-language content summaries
- Threat engine with deterministic rules, heuristic risk score, confidence, evidence and recommendations (phishing/scam, executable, document, URL and archive risk)
- Risk levels: Safe, Low risk, Suspicious, High risk, Critical, Unknown
- Local (offline) explanations with Simple and Technical views; optional, opt-in external AI wording (Anthropic / OpenAI)
- Security alerts and Windows notifications with per-severity settings and de-duplication
- Quarantine, hash-verified restore and confirmed permanent deletion
- Safe opening with confirmation for risky, unanalyzed and executable files
- Protection settings (optional automatic quarantine of Critical files, off by default)
- Threat history
- Dashboard, Files, File Detail, Alerts, Activity, Threat history, Quarantine and Settings screens
- Optional start-with-Windows (minimized)
- Windows packaging configuration (Electron Builder, NSIS, x64, icon) - installer not yet built or run
- Documentation: README, User Guide, Security document, architecture, threat engine, phase notes, final test report

### Security
- Hardened IPC: sender gate, strict id validation, boolean-only confirmations, normalized settings
- Path validation (traversal, device paths, alternate data streams, UNC and symlink folders)
- Quarantine, restore and delete validation with SHA-256 re-checks and vault containment
- Renderer isolation: context isolation, no Node integration, sandbox, strict CSP, blocked navigation, popups and permissions
- Prompt-injection defenses and AI output validation; local fallback; no automatic upload; API key stored only via OS encryption, redirects refused
- Race-condition and stale-verdict protection; file-change detection; analysis timeout

### Changed (final correction pass)
- Documentation rewritten to describe the completed release candidate; previous per-phase notes archived in `docs/CONTINUATION_HISTORY.md`
- User-facing messages no longer mention internal development phases
- Settings shows a message if saved settings cannot be loaded or saved
- Removed the unverified `homepage` field from `package.json`; `.gitignore` covers `.env*` and key files

### Known limitations
Heuristic detection; no signatures, reputation lookup or sandbox; RAR/7z/GZIP and legacy Office macros not inspected; closing the window quits the app (no tray); Windows runtime and installer not yet verified. See `docs/SECURITY.md`.

## Earlier milestones (internal)
- 0.7.0 - Phase 7A: integration review, race-condition fixes, IPC and path hardening, persistence resilience, error states
- 0.6.0 - Phase 6: explanations, alerts, notifications, quarantine, restore, delete, safe open, protection settings, threat history
- 0.5.0 - Phase 5: threat and risk engine
- 0.4.0 - Phase 4: content extraction, OCR, safe preview
- 0.3.0 - Phase 3: static analysis
- Phase 2: automatic file monitoring
- Phase 1: desktop application foundation
