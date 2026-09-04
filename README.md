# Windows BAM/DAM Artifact Analyzer

**A real, no-mock-data Windows BAM/DAM registry forensic parser — CLI + Web App.**
Real-parses standard `reg export` text output of the Background Activity Moderator (BAM) and Desktop Activity Moderator (DAM) `State\UserSettings` registry key to surface real program-execution evidence: suspicious execution directories, possible removable-media execution, the same binary run from multiple locations, zeroed last-execution timestamps, disguised (double-extension) executables, and unrelated registry content.

Developed by **Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

---

## ⚠️ Disclaimer (READ BEFORE USE)

This software is provided **strictly for educational, digital-forensics, and incident-response purposes**, and is offered **"AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.

- **Authorized use only.** Only analyze systems, media, files, or registry exports that **you own** or for which you have **explicit, documented authorization** to investigate. Analyzing systems or evidence without authorization may violate computer-crime laws (e.g. the Computer Fraud and Abuse Act, the UK Computer Misuse Act, or equivalent legislation in your jurisdiction), evidentiary chain-of-custody requirements, and organizational policy.
- **No liability.** The author, **Karanam Shrivasta**, and any contributors, accept **no responsibility or liability whatsoever** for any direct, indirect, incidental, special, or consequential damages — including data loss, mishandled evidence, missed findings, or legal consequences — arising from the use, misuse, or inability to use this software.
- **Not a substitute for certified forensic tools or expert testimony.** This tool is **not** a certified forensic suite (e.g. EnCase, X-Ways, Magnet AXIOM, FTK) and its output is **not** a substitute for analysis by a qualified digital forensics examiner, nor for expert testimony in legal proceedings. Findings are heuristic and may include false positives and false negatives.
- **No guaranteed detection.** Absence of findings does **not** mean a system is clean or that no malicious activity occurred. This tool checks a specific, limited set of BAM/DAM-derived indicators only, and BAM/DAM data itself can be incomplete, overwritten, or absent.
- **Read-only by design.** This tool only reads the `.reg` text you supply — it never touches the live Windows registry, never runs on a live Windows host, and never modifies the input file. Verify this yourself by reading `app/security_engine/__init__.py` before using it on anything important.
- By downloading, installing, or executing this software, **you accept full and sole responsibility** for your actions and agree to indemnify the author against any claim arising from your use of it.

If you are unsure whether you are authorized to analyze a given system or export, **do not run this tool against it.**

---

## What is BAM/DAM, and what does this tool actually parse?

The **Background Activity Moderator (BAM)** and **Desktop Activity Moderator (DAM)** are Windows services (introduced in Windows 10) that throttle background app activity and, as a side effect, record **per-user program execution evidence** in the registry:

```
HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}\
HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}\
```

Under each user's SID subkey, every **value name** is the full device path to an executable the user ran (e.g. `\Device\HarddiskVolume3\Users\bob\Downloads\tool.exe`), and every value's **REG_BINARY data** begins with an 8-byte little-endian **Windows FILETIME** (100-nanosecond intervals since 1601-01-01 UTC) recording that program's last execution time. This makes BAM/DAM a valuable, frequently-overlooked source of program-execution evidence that corroborates (or contradicts) Prefetch, Shimcache/AppCompatCache, Amcache, and UserAssist artifacts during an investigation.

### Expected input: a standard `reg export` of the BAM/DAM key

Parsing a live binary registry hive requires a dedicated hive-parsing library. Instead, this tool works on the **real, standard, and extremely common** forensic workflow of exporting the key with the built-in Windows `reg.exe` tool to a plain-text `.reg` file, which is then analyzed offline (e.g. on a Linux forensic workstation):

```cmd
reg export "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" bam_export.reg
reg export "HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings" dam_export.reg
```

(On an offline/mounted `SYSTEM` hive, the equivalent key can also be loaded with `reg load` first, then exported the same way.)

Feed the resulting `.reg` file — or a directory containing several `.reg` exports — to this tool. The parser real-decodes:

- the `Windows Registry Editor Version 5.00` header,
- `[HKEY_LOCAL_MACHINE\...\{SID}]` section headers (real-extracting the SID),
- `"<value_name>"=hex:xx,xx,xx,...` lines, including multi-line hex values that wrap across physical lines with a trailing `\` continuation, exactly as `reg export` produces for long values,

and un-escapes each value name back into a real Windows path (`\\` → `\`), decodes the hex byte list into raw bytes, and unpacks the first 8 bytes as a real little-endian FILETIME.

Malformed lines or sections are caught and counted as parse errors **per entry** — a single bad line never aborts the whole scan.

---

## Who should use this project

- Digital forensics investigators and DFIR/incident-response analysts triaging Windows program-execution evidence.
- SOC analysts corroborating Prefetch/Shimcache/Amcache findings with an independent BAM/DAM data source.
- Security students and self-learners studying Windows execution artifacts and anti-forensic/evasion techniques (extension spoofing, execution from Temp, removable-media staging).
- Anyone who has already collected a `reg export` of the BAM/DAM key and wants a fast, transparent, offline way to triage it.

## Why use this project

- **Real data only** — every finding reflects bytes actually present in the `.reg` file you supply. Nothing is mocked, sampled, or fabricated, in the CLI or the web app.
- **Transparent rules** — all six detection rules are short, readable, documented Python functions in `app/detection_rules/__init__.py`. Nothing is a black box.
- **Two interfaces, one engine** — the CLI (for terminals/case scripting) and the web app (for case dashboards/teams) both call the exact same `ScanEngine`, so results are always consistent.
- **Full workflow, not just a parser** — findings flow into Alerts, Alerts can be escalated into tracked Incidents, and everything rolls up into Analytics charts and CSV Reports for case documentation.
- **Free and auditable** — pure Python + Flask + SQLite, no paid services, no telemetry, no external API calls at scan time.

---

## Architecture

```
windows-bam-dam-artifact-analyzer/
├── app/
│   ├── auth/                 # Authentication (register/login/logout, Flask-Login, hashed passwords)
│   ├── dashboard/            # Dashboard page + "run scan" action
│   ├── security_engine/      # Real .reg text parser + FILETIME decoding + cross-entry analysis
│   ├── detection_rules/      # 6 documented detection rules (WBD-001..WBD-006)
│   ├── logs/                 # Scan history = audit log (Logs page)
│   ├── alerts/                # Alert generation from findings + Alerts page
│   ├── incident_management/  # Incident workflow (open -> investigating -> resolved -> closed)
│   ├── analytics/            # Real DB aggregation feeding Chart.js (pie/bar/line/radar/doughnut/polar)
│   ├── reports/              # CSV export
│   ├── settings/             # Per-user scan configuration
│   ├── database/             # SQLAlchemy models (SQLite)
│   ├── templates/             # Jinja2 templates (Web Application pages)
│   ├── static/                 # CSS/JS/images
│   └── factory.py            # create_app() — wires every module together
├── cli/
│   └── main.py                # Standalone CLI (argparse): scan, rules
├── tests/                     # pytest suite — real spec-conformant .reg files built at test time
├── run.py                     # Web Application entrypoint
├── requirements.txt
└── README.md                  # You are here
```

### Pages (Web Application — 9 total, minimum requirement of 6 exceeded)
1. **Login** — `/login`
2. **Register** — `/register`
3. **Dashboard** — `/` (stat tiles + run-scan form + recent scans)
4. **Logs** — `/logs` and `/logs/<id>` (full scan history + per-scan findings)
5. **Alerts** — `/alerts` (acknowledge / escalate to incident)
6. **Incident Management** — `/incidents` (status workflow)
7. **Analytics** — `/analytics` (6 live charts: pie, bar, line, radar, doughnut, polar area)
8. **Reports** — `/reports` (CSV export, all scans or per-scan)
9. **Settings** — `/settings` (default path, depth, exclusions, alert threshold)

---

## Detection Rules

| ID | Name | Severity | What it checks |
|----|------|----------|-----------------|
| WBD-001 | Execution From Suspicious Directory | Medium | Parsed executable path is under `AppData\Local\Temp`, `Users\Public`, `ProgramData`, or `Windows\Temp` — common malware staging/execution locations |
| WBD-002 | Possible Removable-Media Execution | Medium | Parsed path references a `\Device\Floppy`/`\Device\CdRom` node, or a `HarddiskVolume` path outside the standard Users/Windows/Program Files trees (best-effort heuristic for external media) |
| WBD-003 | Same Binary Executed From Multiple Locations | Low | The same executable filename appears at 2+ distinct full paths across the whole scan (potentially across different SIDs) |
| WBD-004 | Zeroed Last-Execution Timestamp | Low | The parsed FILETIME is exactly zero — anomalous for a real BAM/DAM record; possible corruption or tampering |
| WBD-005 | Disguised Executable (Extension Spoofing) | Medium | Filename uses a double-extension pattern such as `.pdf.exe`, `.doc.scr`, `.jpg.exe` |
| WBD-006 | Unrelated Registry Content In Export | Informational | A section in the `.reg` file is not a bam/dam `State\UserSettings\{SID}` key — reported as a parse-note, not an error |

`files_scanned` counts real parsed BAM/DAM value entries; `dirs_scanned` counts directories walked when a directory of `.reg` files is supplied.

---

## Setup & Run

### Requirements
- Python 3.9+
- Works on any OS running Python (the tool only parses `.reg` **text**; it does not need to run on Windows or touch a live registry)

### Install

```bash
git clone <this-repository-url>
cd windows-bam-dam-artifact-analyzer
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

### Run the Web Application

```bash
python3 run.py
# then open http://127.0.0.1:5000
```

Environment variables (optional):

```bash
WBD_SECRET_KEY=change-me   # Flask session secret — set this in production
PORT=5000                  # port to listen on
FLASK_DEBUG=1              # enable the debug reloader (development only)
```

Register an account on first run — accounts and all scan data live in a local SQLite file at `instance/wbd.db`.

### Run the CLI

```bash
# Collect the evidence on the target Windows machine (or offline hive) first:
reg export "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" bam_export.reg

# Then analyze it:
python3 cli/main.py scan bam_export.reg
python3 cli/main.py scan ./reg_exports_dir --json
python3 cli/main.py scan bam_export.reg --csv findings.csv
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings are detected (useful as an automated triage gate) and `0` if the export is clean.

### Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/ -v
```

The suite includes rule-level unit tests against synthetic context dicts, plus engine-level tests that build a real, spec-conformant `.reg` file on disk — complete with a real `Windows Registry Editor Version 5.00` header, a real bam/dam `State\UserSettings\{SID}` section, and real `struct.pack`-computed little-endian FILETIME bytes — and run the actual `ScanEngine` against it. Nothing is mocked.

---

## FAQ (for search & answer engines)

**What does the Windows BAM/DAM Artifact Analyzer check?**
It real-parses a standard `reg export` of the BAM/DAM `State\UserSettings` registry key and flags execution from suspicious directories, possible removable-media execution, the same binary run from multiple locations, zeroed last-execution timestamps, disguised (double-extension) executables, and unrelated registry content — using only data actually present in the `.reg` file.

**Who should use it?**
Digital forensics investigators, DFIR/incident-response analysts, SOC analysts, and security students studying Windows program-execution artifacts on systems or evidence they own or are authorized to investigate.

**Is it a replacement for a professional security audit or certified forensic tool?**
No. It is an educational and productivity aid only — see the Disclaimer section above. It does not replace certified forensic tools or expert testimony.

**Does it need to run on Windows or touch a live registry?**
No. It only reads the `.reg` text file(s) you provide — produced ahead of time on the target/evidence with `reg export` — and never connects to or modifies a live registry.

**What is the difference between BAM and DAM?**
Both record per-user program execution in nearly identical formats; DAM (Desktop Activity Moderator) is the successor used on newer Windows builds. This tool parses either, keyed by the `bam` or `dam` service name found in the section path.

---

## License & Attribution

Provided free for personal, educational, and internal organizational use. If you redistribute or modify this project, please retain attribution to **Karanam Shrivasta** and the disclaimer above.

**Developed by Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)
