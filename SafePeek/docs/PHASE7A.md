# Phase 7A — Final integration, runtime hardening, testing (v0.7.0)

Phase 7A adds no product features. It audits Phases 1-6 as one system and fixes what the audit found.

## Pipeline (unchanged, verified)
watcher -> stability -> Phase 3 static -> Phase 4 content -> Phase 5 threat -> Phase 6 (history, explanation, optional auto-quarantine, alert, notification). One chain, wired in `electron/main.ts`; no duplicate pipeline. Phase 5 stays authoritative: explanation/AI code only reads the assessment.

## Defects found and fixed
| Area | Problem found | Fix |
|---|---|---|
| Race | A quarantined file could have its verdict overwritten by a late analysis or rescan (the file was gone, so the result became UNKNOWN) | `isSkipped` hook on Analysis/Content/Threat services: stages skip or discard results for quarantined files; `reanalyze` ignores them |
| Race | Re-downloading a file with the same name deleted the quarantined file's record | Watcher keeps `QUARANTINED` records; the new file gets its own record |
| Staleness | An old SAFE verdict stayed valid while a rescan was running | `reanalyze` clears the verdict immediately; the open decision treats a busy pipeline as UNKNOWN |
| Change detection | A file modified *during* analysis produced a result describing old bytes | size+mtime compared before/after; bounded re-analysis (3 tries), then flagged partial |
| Timeout | Static analysis had no limit | 120 s limit -> `failed` / incomplete (never SAFE) |
| Stability | Exclusive-lock writers (Windows) with steady size/mtime passed the check | A stable file must also be openable for read (EBUSY/EPERM/EACCES keeps waiting); files that never settle emit a visible `watcher-error` event |
| Safe open | Only size+mtime checked; executables with a SAFE verdict opened silently | SHA-256 re-check (files <= 512 MB); path re-validated; executables/scripts always need confirmation; "Analysis is outdated... Rescan" message |
| Quarantine | Verified by size only; could follow a symlinked parent into the vault | SHA-256 re-read from the vault copy (recorded hash; mismatch with the analyzed version is flagged); realpath containment; restore hash-verified; restore into the vault refused |
| Paths | `\\?\`, `\\.\` device paths and NTFS alternate data streams were accepted | Rejected in `validatePath`; UNC / symlink folders refused as new monitored folders |
| IPC | `files:stat` returned metadata for any renderer-supplied path; `settings:set` wrote any object non-atomically; folder ids unvalidated; no sender check | `files:stat` and `pickFolder` removed; settings normalized to known keys, atomic write; strict id validation; one gate accepting only SafePeek's own page (`electron/ipc/validate.ts`) |
| Persistence | One malformed record in a JSON store could crash lookups; corrupt copies unbounded; Windows rename-over-existing could fail | Per-record validation (state, alerts, history, quarantine); `electron/util/atomicWrite.ts` (unique temp names, retry on EPERM/EBUSY, corrupt copies capped at 3) |
| Main process | Production window could navigate to localhost:5173; async quit; swallowed errors; no AppUserModelID | Trusted-URL check, popups and permissions denied, renderer-crash recovery, process-level error logging, flush on quit (3 s cap), `setAppUserModelId('com.safepeek.app')` |
| AI | A redirect would carry the API key | `redirect: 'error'` |
| UI | List pages swallowed load errors; unhandled IPC rejections | `useLiveState` + `LoadState` (loading/error/retry) on Dashboard, Files, Alerts, Activity, Quarantine, Threat history; protection actions return a failed result instead of throwing; long names wrap; focus outlines |

## Decisions worth knowing
- Quarantining a file that changed since analysis is **allowed** (isolating is the safe direction); the record says so and stores the hash of the file actually quarantined. Open and Restore refuse changed files.
- UNC paths are not refused for already-tracked files (redirected Downloads) but cannot be added as monitored folders.

## Tests
`npm test`: 19 files, 424 tests = 284 from Phase 6 + 140 new in `tests/phase7a.*.test.ts` (paths/IPC, watcher/stability, quarantine/restore/delete, protection and races, AI fallback and injection, persistence, 6 end-to-end scenarios with the real chokidar watcher and real Phase 3/4/5/6 code).

## Known limitations
- The real engine rates the synthetic fake `.pdf.exe` HIGH_RISK (71-77), not CRITICAL, so scenario 4 (auto-quarantine of CRITICAL) is covered with forced statuses in `phase7a.protection.test.ts`, not a naturally CRITICAL file.
- The threat engine is synchronous on the main thread and has no preemptive timeout (utility process is the proper fix). Content extraction keeps its Phase 4 timeouts (which do not cancel the underlying work).
- Per-file JSON caches (`content/`, `threat/`, `explanations/`) are not garbage-collected.
- No `unlink` handling: records of files deleted outside SafePeek stay listed.
- Junctions, ACL errors and Windows locking are covered by code paths and mocked errors, not by a Windows run.
