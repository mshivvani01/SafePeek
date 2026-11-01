# Phase 6 — AI Explanation, Alerts, Quarantine & Protection (v0.6.0)

> SafePeek is a defensive analysis and protection assistant. It does not guarantee detection of every malicious file and does not replace a full endpoint security product.

## Architecture
```
FILE ARRIVES -> watcher -> Phase 3 static -> Phase 4 content -> Phase 5 threat engine (AUTHORITATIVE verdict)
                                                                        |  ThreatService.onAssessed
                                                                        v
                                                      ProtectionService.handleAssessment   (Phase 6)
                          history entry -> local explanation -> [auto-quarantine CRITICAL if enabled] -> alert -> desktop notification
                                                                        v
                                    user: Review / Quarantine / Restore / Delete / Open Anyway / Open folder / Copy path / Rescan
```
Phase 5 stays authoritative. Phase 6 only reads the stored `ThreatAssessment`; it never changes status or score, and there is no second scoring system.

| Module | Responsibility |
|---|---|
| `electron/ai/localExplanation.ts` | Deterministic offline explanation built only from Phase 5 indicators/categories/coverage (fixed templates keyed by rule id; other rules use their own title). `coerceAssessment` treats stored data as untrusted. |
| `electron/ai/promptBuilder.ts` | Prompt for the OPTIONAL provider: SYSTEM instructions / SECURITY EVIDENCE (JSON from Phase 5) / UNTRUSTED FILE CONTENT (opt-in snippets, JSON-encoded, delimited, delimiters neutralised). Builds the disclosure shown before anything is sent. |
| `electron/ai/explanationEngine.ts` | Validates AI output: JSON shape, length limits, sanitising; rejects malware family names, VirusTotal/AV claims, attribution, certainty/safety guarantees, links/markup, instructions to open/run, injection echoes, a different score, or a higher risk label than Phase 5. |
| `electron/ai/explanationService.ts` | `get()` always returns the local explanation. `requestAi()` contacts a provider only if enabled + provider + model + stored key + the user pressed the button and confirmed. Cached per assessment. Never changes the assessment. |
| `electron/ai/secretStore.ts` | API key encrypted via Electron `safeStorage`; saving is refused if OS encryption is unavailable; never sent to the renderer or logged. |
| `electron/protection/quarantineService.ts` | Physical quarantine (below). |
| `electron/protection/alertService.ts` | Alerts, deduplication, read/dismiss/action tracking. |
| `electron/protection/historyService.ts` | Threat history (every completed assessment + the decision taken). |
| `electron/protection/openSafety.ts` | Open decision table. |
| `electron/protection/protectionService.ts` | Orchestrator; the only code path that can launch a file (`openFile`, via an injected hook). |
| `electron/protection/settings.ts` | Security + AI settings with strict normalisation (wrong types fall back to safe defaults). |

## Privacy model
* Everything works with no key and no internet. The local explanation is the primary mode.
* Optional AI is OFF by default, cannot be enabled without a provider, and sends nothing until the user presses "Get AI-assisted explanation" on a file and confirms the disclosure (which shows the exact payload).
* Sent (when confirmed): status, heuristic score, confidence, categories, indicator titles/ids/severities, coverage. File name and short evidence snippets only with separate opt-ins. **Never sent:** the original file or bytes, extracted/OCR text, URLs, paths.
* The AI cannot change the verdict. Its text is labelled "AI-assisted explanation" and the threat engine is always named as the detector.
* Providers: Anthropic (`api.anthropic.com`), OpenAI (`api.openai.com`). Network code exists only in `explanationService.ts` (enforced by `tests/phase6.security.test.ts`).

## Alerts
Phase 5 status -> alert: SAFE/UNKNOWN none; LOW_RISK informational (only if "informational alerts" is on); SUSPICIOUS warning; HIGH_RISK strong warning; CRITICAL critical. The alert record for Suspicious+ is always kept; per-severity toggles control only the Windows desktop notification. Clicking a notification focuses SafePeek and opens that file's detail screen (the file is not opened). Dedup key = file hash (or id) + file name + status + fingerprint of the indicator set, so rescans, restarts and UI refreshes never re-alert, while a changed outcome does. Persisted in `userData/security/alerts.json`.

## Quarantine
* `userData/quarantine/files/<sha256-prefix>_<id>_<sanitised-name>.quarantine` (non-launchable suffix); metadata in `userData/quarantine/quarantine.json`.
* Move order: validate path (absolute, no `..`/NUL) -> `lstat` (refuse symlinks/non-files) -> refuse if the vault is a symlink -> hash -> `rename` (or copy+verify+delete across drives, rolling back on failure, never overwriting) -> verify size -> only then write metadata. A failure never claims success.
* Restore: explicit confirmation for Suspicious/High/Critical; re-validates the stored vault path (tampered metadata rejected); verifies SHA-256; refuses symlinked destination folders; never overwrites (adds "(restored)"); can fall back to Downloads if the original folder is gone; then re-runs Phase 3->4->5->6. The file is never executed.
* Delete: explicit confirmation; deletes only the vault copy; the record is kept as DELETED.
* The quarantine folder is excluded from monitoring. Quarantined files are never opened, previewed, rescanned or revealed.

## Protection mode
`Protection: ON` = monitoring is active. **Automatic quarantine of CRITICAL files is OFF by default.** When on, it moves only CRITICAL files, creates the alert and notification, and never deletes anything. A file the user restored is not auto-quarantined again. If the automatic move fails, the alert says so.

## Safe opening
SAFE/LOW_RISK open normally. SUSPICIOUS, unanalysed (UNKNOWN) and CRITICAL always need "Open Anyway"; HIGH_RISK needs it unless the user disables "require confirmation" (CRITICAL cannot be relaxed). A file that changed since analysis, a symlink, or a missing file is not opened. "Open containing folder" is offered instead.

## IPC surface (Phase 6)
Ids and booleans only; ids must match `^[A-Za-z0-9-]{8,64}$`; confirmation flags must be exactly `true`; the renderer never supplies a path or destination; the internal vault path is stripped from quarantine listings.

## Limitations
* Explanation templates cover the common Phase 5 rules; other rules use the rule's own title.
* Explanations inherit Phase 5's limits (heuristic, English-oriented, no signatures/reputation/sandbox).
* Windows toast behaviour, packaging and the installer are NOT verified (see CONTINUATION.md).
* Quarantine does not stop software that already opened the file; files are moved, not encrypted or defanged.
* History/alerts are capped (2000/500 entries). The explanation cache is not garbage-collected.
