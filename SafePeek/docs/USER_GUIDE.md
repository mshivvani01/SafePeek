# SafePeek User Guide

**Know what's inside before you open it.**

SafePeek checks the files you download *before* you open them, tells you what is inside, and warns you if something looks risky. This guide is for everyday Windows users - no technical knowledge needed.

> SafePeek is a helper, not a guarantee. It cannot catch every dangerous file and does not replace an antivirus program. Keep Windows Security (or your antivirus) turned on.

---

## 1. Installation
1. Double-click **SafePeek-Setup-1.1.0.exe**.
2. Windows may show a blue "Windows protected your PC" (SmartScreen) message because the installer is not digitally signed yet. If you trust where you got the installer, choose **More info -> Run anyway**.
3. In the setup wizard, choose the install folder (or keep the default) and finish. Shortcuts are added to the desktop and Start menu.
4. To remove SafePeek later: **Settings -> Apps -> Installed apps -> SafePeek -> Uninstall**. Your SafePeek data (history, quarantine) is kept unless you delete it yourself.

## 2. First launch
- SafePeek opens on the **Dashboard**. The top of the window shows **Monitoring Active** when it is watching your **Downloads** folder.
- Nothing needs to be set up. From now on, new files in Downloads are checked automatically.
- You can add more folders under **Settings -> Monitoring -> Protected folders -> Add folder**.
- To see it work, go to **Settings -> Advanced -> Self-test -> Create test file**. SafePeek creates one harmless text file and detects it.

**Important:** SafePeek only watches while it is running. Closing its window **quits** the program. Minimize it instead, or turn on **Settings -> Advanced -> Start SafePeek when I sign in to Windows** so it starts for you (minimized).

## 3. Monitoring
- SafePeek notices a new file, but waits until the download has **finished** (it ignores `.crdownload`, `.tmp` and similar half-finished files).
- It never opens, runs or changes your file while checking it. It also never visits links found inside files.
- You can pause and resume monitoring in **Settings -> Monitoring**. Your choice is remembered when you restart.

## 4. How a file is analyzed
Each file passes through these steps, shown on the **Files** page:

```
Detected -> Analyzing -> Content analysis -> Threat assessment -> Result
```

1. **Detected** - SafePeek saw the new file.
2. **Analyzing** - checks what the file really is (not just its name), computes a fingerprint, and looks at its structure.
3. **Content analysis** - reads the text, tables and images safely so it can tell you what is inside.
4. **Threat assessment** - compares everything against its rules (disguised programs, scam wording, suspicious links...).
5. **Result** - a risk level, a score, the reasons, and a recommendation. Most files finish in seconds; large files take longer.

## 5. Risk levels
| Level | Meaning | What to do |
|---|---|---|
| 🟢 **Safe** | No suspicious indicators were found. | Normal caution still applies - this is *not* a guarantee. |
| 🟡 **Low risk** | Minor indicators. | Usually fine; glance at the reasons. |
| 🟠 **Suspicious** | Review recommended. | Read "Why is this risky?" before opening. |
| 🔴 **High risk** | Do not open without verification. | Verify the sender; consider quarantine. |
| ⛔ **Critical** | Strong protection recommended. | Do not open. Quarantine it. |
| ❔ **Unknown** | Not fully assessed (still running, unreadable, too large, or unsupported). | Wait, or press **Rescan**. Unknown is *not* the same as safe. |

The number next to the level (0-100) is a rough **risk score**. It is an estimate, not a probability, and a low score is not a promise of safety.

## 6. File Detail
Click a file on the **Files** page (or click an alert) to open its detail screen. From top to bottom it shows:
- **What the file is** - its real type, size, and fingerprint.
- **Why is this risky?** - a plain-language explanation. Switch between **Simple** and **Technical** wording.
- **What SafePeek recommends** - concrete next steps.
- **What's inside** - a safe preview and the extracted text, tables and links. Links are shown as plain text; clicking them does nothing.
- **Findings** - each indicator with its evidence, so you can see exactly why something was flagged.
- **Analysis coverage** - what could and could not be checked.

Buttons on this screen: **Mark reviewed**, **Rescan**, **Show in folder**, **Copy path**, **Quarantine**, and **Open** / **Open anyway**.

## 7. Alerts
- Files rated Suspicious, High risk or Critical create an **alert** (the **Alerts** page, with a red count in the sidebar) and, by default, a **Windows notification**.
- Click a notification or an alert to jump to that file's detail screen. This does **not** open the file itself.
- The same finding is not repeated every time you restart; a changed result raises a new alert.
- In **Settings -> Notifications** you choose which levels show a Windows notification. Alerts for Suspicious or worse are always recorded in the app.
- **Threat history** lists every completed check and what was decided.

## 8. Quarantine
Quarantine moves a file into SafePeek's protected folder so you cannot open it by accident.
- **Quarantine** - on File Detail, press **Quarantine** and confirm. SafePeek can also do this automatically for **Critical** files, but that is **off by default** (**Settings -> Protection**).
- **Restore** - on the **Quarantine** page press **Restore...**. For risky files SafePeek shows a warning and asks you to confirm. The file goes back to its original folder (or Downloads if that folder is gone), never overwrites an existing file, and is re-checked. SafePeek does not open it.
- **Delete permanently** - on the **Quarantine** page press **Delete permanently...** and confirm. **This cannot be undone.** Only the quarantined copy is deleted.
- Quarantined files are never previewed, opened or run.

## 9. Safe Open
- Files rated Safe or Low risk open normally.
- Files that are **Suspicious**, **Critical**, **Unknown/not yet analyzed**, or that are **programs or scripts** (for example `.exe`, `.bat`, `.ps1`) ask for confirmation first (**Open anyway...**). High risk files ask unless you changed that in Settings; Critical files always ask.
- SafePeek refuses to open a file that changed after it was checked, and tells you to **Rescan**. If a file cannot be opened, use **Show in folder** instead.
- Opening a file after confirmation means you accepted the risk - SafePeek cannot protect you once you run it.

## 10. AI explanation
- SafePeek's **rule engine decides** the risk level. The "Why is this risky?" text is an explanation layer written *from* those results.
- By default the explanation is produced **on your PC, offline**. It works without an account, an API key or internet.
- You may optionally turn on an AI provider (**Settings -> AI Explanation**) for nicer wording. AI **cannot change** the risk level or score, and SafePeek rejects AI text that contradicts the engine or claims certainty.
- Nothing is sent until you press **Get AI-assisted explanation** on a file and confirm a message that shows exactly what will be sent.

## 11. Privacy
- SafePeek is **local-first**: your files are analyzed on your computer and **never uploaded**.
- No file, text, link or file path is sent anywhere unless you explicitly enable external AI, and even then the original file and its contents are never sent - only a short summary of the findings (the file name and evidence snippets only if you separately allow them).
- A stored API key is encrypted with Windows. If Windows encryption is unavailable, SafePeek refuses to store the key.

## 12. Troubleshooting
| Problem | What to do |
|---|---|
| **A file does not appear** | It may still be downloading - SafePeek waits for it to finish. Check that Monitoring is Active and the folder is listed in Settings. |
| **"File is in use" / locked** | Another program is still using the file. Close that program or wait; SafePeek keeps retrying and records an event if the file never settles. Press **Rescan** later. |
| **Permission denied** | SafePeek cannot read the file or folder. Check the file's Windows permissions, or move the file to a normal folder. |
| **Unsupported file** | SafePeek can still check its type and structure, but cannot show a preview. The result may be Unknown. |
| **Analysis failed / Unknown** | Press **Rescan**. If it keeps failing, treat the file with caution. Failed is never shown as Safe. |
| **OCR unavailable or no text found** | OCR (reading text in images) is English-only and skipped for very large images. Scanned PDFs are not OCR'd. |
| **AI unavailable** | The offline explanation is always shown. For external AI, check the provider, model, API key and internet connection. A failure never changes the risk level. |
| **No Windows notifications** | Check Windows **Settings -> System -> Notifications** and **Focus assist**, and the toggles in SafePeek **Settings -> Notifications**. |
| **SafePeek stopped checking files** | You may have closed the window (which quits the app). Start it again, or enable "Start SafePeek when I sign in". |
| **Restore says the original folder is missing** | Choose **Restore to Downloads** when offered. |

If something looks wrong, keep the file closed and use **Quarantine** until you can verify where it came from.


---

## Images, scanned documents and QR codes (new in 1.1)
SafePeek now looks *inside* pictures. For an image file, or a PDF made of scanned pages, it reads the visible text on your computer (**OCR**), looks for **QR codes**, and checks any web addresses it finds with the same rules it uses for ordinary text.

- **File Detail -> Visual Analysis** shows how many images were analyzed, how many PDF pages needed OCR, how many QR codes and web addresses were found, and the **OCR status** (Complete / Partial / Failed / Unsupported).
- **Content sources** shows where the text came from: *PDF text extracted*, *OCR text extracted from N pages*, *QR code content decoded*.
- **QR Codes Detected** lists each code's decoded content as plain text. SafePeek **never opens** a QR code or the address inside it. Codes that are not web addresses (Wi-Fi, phone, e-mail ...) are shown as text only. If a file has no QR code, nothing is shown.
- **Why SafePeek flagged this** now says where each finding came from, for example *Source: OCR (text read from an image)* or *Source: QR code*.
- **Partial results are never reassuring.** Very large or unusual images, very long scanned PDFs, or OCR that took too long are marked *Partial* with "Some visual content could not be fully analyzed". SafePeek then shows **Unknown** rather than Safe.
- **Limits:** OCR is not guaranteed to read every image, font, language or low-quality scan correctly (English only). In PDFs SafePeek reads pages that are made of embedded images (scans); text drawn as vector shapes is not read. Nothing is uploaded: images are read on your computer.
