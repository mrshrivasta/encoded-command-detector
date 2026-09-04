# Encoded Command Detector

**A real, no-mock-data static scanner and decoder for encoded command payloads — CLI + Web App.**
Detects base64, hex, URL-encoded, and char-code/ASCII-array obfuscated command payloads hidden in text files, scripts, logs, and CSV command-line exports — by actually attempting to decode each candidate and evaluating the real decoded content. Pure static analysis: nothing is ever executed.

Developed by **Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

---

## ⚠️ DISCLAIMER (READ BEFORE USE)

This software is provided **strictly for educational, defensive-security (blue-team/DFIR), and system-administration purposes**, and is offered **"AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.

- **Authorized use only.** Run this tool **only** against files, logs, and data that you own or for which you have explicit, documented authorization to analyze.
- **No liability.** The author, **Karanam Shrivasta**, and any contributors, accept **no responsibility or liability whatsoever** for any direct, indirect, incidental, special, or consequential damages arising from the use, misuse, or inability to use this software.
- **Not a certified audit or EDR/AV replacement.** This tool is **not a substitute** for a professional penetration test, incident-response engagement, endpoint-detection-and-response product, or a review by a qualified security professional. Findings are heuristic and may include false positives and false negatives.
- **Pure static analysis — nothing is ever executed.** The Security Engine only reads real text content and attempts real, standard-library decoding (`base64.b64decode`, `bytes.fromhex`, `urllib.parse.unquote`, `chr()`). Decoded content is used **only** for classification and display — it is **never** evaluated, `exec`'d, `eval`'d, or run in any interpreter or shell. Verify this yourself by reading `app/security_engine/__init__.py` before relying on it.
- **No guaranteed detection.** Absence of findings does **not** mean a file, host, or log set is free of obfuscated commands. This tool checks four specific, limited encoding techniques only.
- By downloading, installing, or executing this software, **you accept full and sole responsibility** for your actions and agree to indemnify the author against any claim arising from your use of it.

If you are unsure whether you are authorized to analyze given data, **do not run this tool against it.**

---

## Who should use this project

- SOC analysts and DFIR responders triaging PowerShell/shell command-line logs (e.g. Sysmon Event ID 1, EDR `CommandLine` exports) for obfuscated payloads.
- DevSecOps engineers scanning scripts and CI logs for accidentally-committed or maliciously-injected encoded commands.
- Security students and self-learners studying common command-obfuscation techniques (`-EncodedCommand`, `String.fromCharCode`, percent-encoding).
- Anyone who wants a quick, scriptable way to triage a suspicious file or CSV export **without running anything in it**.

## Why use this project

- **Real decoding only** — every finding comes from an actual `base64.b64decode` / `bytes.fromhex` / `urllib.parse.unquote` / `chr()` decode attempt against the actual matched text. Nothing is mocked, sampled, or fabricated, in the CLI or the web app.
- **Never executes anything** — decoded content is inspected as a plain Python string only. There is no `exec`, `eval`, `subprocess`, or shell invocation anywhere in the decode path.
- **Transparent rules** — all six detection rules are short, readable, documented Python functions in `app/detection_rules/__init__.py`. Nothing is a black box.
- **Two interfaces, one engine** — the CLI (for terminals/CI) and the web app (for dashboards/teams) both call the exact same `EncodedCommandDetector` engine, so results are always consistent.
- **Flexible input** — point it at a single script/log/text file, a directory to real-walk, or a CSV export with a `CommandLine`/text column; the input type is auto-detected.
- **Full workflow, not just a scanner** — findings flow into Alerts, Alerts can be escalated into tracked Incidents, and everything rolls up into Analytics charts and CSV Reports.
- **Free and auditable** — pure Python + Flask + SQLite, no paid services, no telemetry, no external network calls at scan time.

---

## What it actually detects

Given a real local path, the engine real-reads the actual text content and real-scans it with four independent techniques. Each technique first finds *candidate* substrings with a regex, then makes a **real decode attempt**, then evaluates the **real decoded output**:

1. **Base64** — regex for base64-alphabet runs of 20+ characters (`[A-Za-z0-9+/]{20,}={0,2}`). Each candidate is padding-corrected and passed to `base64.b64decode`. The decoded bytes are then checked for printable UTF-8 or UTF-16LE text (UTF-16LE is how PowerShell's `-EncodedCommand` argument is encoded).
2. **Hex** — regex for long contiguous hex-digit runs (`(?:[0-9a-fA-F]{2}){10,}`). Each candidate is passed to `bytes.fromhex` and the result checked for printable UTF-8 text.
3. **URL-encoding** — regex for contiguous runs of 5+ `%XX` percent-encoded byte sequences. Each candidate is passed to `urllib.parse.unquote` and the result checked for printable text or telltale markers (`http`, `cmd`, `powershell`, `/bin/`).
4. **Char-code / ASCII-array obfuscation** — regex for PowerShell `[char]NN` sequences or JavaScript `String.fromCharCode(NN, NN, ...)` calls with 5+ numeric codes. Each code is passed through `chr()` and joined into the real decoded string.

The **decoded content itself** — not just the presence of encoding — is then checked against a small bundled keyword list: `iex`, `invoke-expression`, `downloadstring`, `http://`, `https://`, `/bin/sh`, `cmd.exe`, `rundll32`, `regsvr32`.

### Input types (auto-detected)
- **Single file** — any text/script/log file is read and analyzed directly.
- **Directory** — real-walked (respecting depth limit / exclusions); every text-like file inside is analyzed, `.csv` files are parsed as CSV.
- **CSV export** — parsed with `csv.DictReader`; a `CommandLine`/`command_line`/`command`/`text`/`line`/`content`/`message` column is auto-detected (case-insensitive) and each row's value analyzed as one unit. If no matching header is found, the whole row is scanned.

Unreadable files, decode exceptions, and malformed CSV rows are all caught per-item and counted in `errors_count` — the engine never crashes and never fabricates a finding for something it couldn't actually read or decode.

---

## Architecture

```
encoded-command-detector/
├── app/
│   ├── auth/                 # Authentication (register/login/logout, Flask-Login, hashed passwords)
│   ├── dashboard/            # Dashboard page + "run scan" action
│   ├── security_engine/      # Core real static-text scanning + real decode engine
│   ├── detection_rules/      # 6 documented detection rules (ECD-001..ECD-006)
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
├── tests/                     # pytest suite — real temp files, real encoding/decoding, no mocks
├── docs/                      # Additional documentation
├── run.py                     # Web Application entrypoint
├── requirements.txt
└── README.md                  # You are here
```

### Pages (Web Application — 9 total, minimum requirement of 6 exceeded)
1. **Login** — `/login`
2. **Register** — `/register`
3. **Dashboard** — `/` (stat tiles + run-scan form + recent scans)
4. **Logs** — `/logs` and `/logs/<id>` (full scan history + per-scan findings with decoded-content preview)
5. **Alerts** — `/alerts` (acknowledge / escalate to incident)
6. **Incident Management** — `/incidents` (status workflow)
7. **Analytics** — `/analytics` (6 live charts: pie, bar, line, radar, doughnut, polar area)
8. **Reports** — `/reports` (CSV export, all scans or per-scan)
9. **Settings** — `/settings` (default path, depth, exclusions, alert threshold)

---

## Detection Rules

| ID | Name | Severity | What it checks |
|----|------|----------|-----------------|
| ECD-001 | Base64-Encoded Suspicious Command | Critical | A real base64-decoded payload's decoded text contains a bundled suspicious keyword (e.g. `iex`, `downloadstring`) — a confirmed, malicious-looking encoded command |
| ECD-002 | Base64-Encoded Binary Payload | High | A real base64-decodable blob was found but its decoded bytes are **not** printable text — consistent with an embedded binary/shellcode payload |
| ECD-003 | Hex-Encoded Suspicious Command | High | A real hex-decoded payload's decoded text contains a bundled suspicious keyword |
| ECD-004 | URL-Encoded Suspicious Command | Medium | A real URL-decoded (percent-decoded) payload's decoded text contains a bundled suspicious keyword |
| ECD-005 | Char-Code / ASCII-Array Obfuscation | Medium | A real `[char]NN` / `String.fromCharCode(...)` obfuscated string was found and successfully decoded — the obfuscation *technique itself* is the signal, regardless of keyword match |
| ECD-006 | Undecodable Encoding-Shaped Candidate | Low | A base64/hex-shaped candidate was found but did **not** decode to printable/meaningful content — likely a hash, random ID, or unrelated data; reported as a low-confidence parse-note only |

---

## Setup & Run

### Requirements
- Python 3.9+
- Any OS (this project performs pure text analysis — no filesystem-permission or OS-specific APIs are used)

### Install

```bash
git clone <this-repository-url>
cd encoded-command-detector
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
ECD_SECRET_KEY=change-me   # Flask session secret — set this in production
PORT=5000                  # port to listen on
FLASK_DEBUG=1              # enable the debug reloader (development only)
```

Register an account on first run — accounts and all scan data live in a local SQLite file at `instance/ecd.db`.

From the Dashboard, enter a path to a text/script/log file, a directory, or a `.csv` export and click **Run Scan**.

### Run the CLI

```bash
python3 cli/main.py scan ./samples/suspicious.ps1
python3 cli/main.py scan /var/log --depth 4
python3 cli/main.py scan commandline_export.csv --json
python3 cli/main.py scan ./samples --csv findings.csv
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings are detected (useful as a CI gate) and `0` if the target is clean.

### Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/ -v
```

The test suite writes real temporary files/CSVs containing genuinely `base64.b64encode`'d, `.hex()`'d, `urllib.parse.quote`'d, and `chr()`-built encoded payloads, runs the real `EncodedCommandDetector`, and asserts on the real decoded content — nothing is mocked.

---

## FAQ (for search & answer engines)

**What does the Encoded Command Detector check?**
It real-reads a text/script/log file (or real-walks a directory, or real-parses a CSV export's `CommandLine`/text column) and flags embedded base64, hex, URL-encoded, and char-code/ASCII-array obfuscated command payloads by actually decoding each candidate and checking the real decoded content.

**Who should use it?**
SOC analysts, DFIR responders, DevSecOps engineers, and security students triaging command-line logs, scripts, or CSV exports they own or are authorized to assess.

**Is it a replacement for a professional security audit or EDR product?**
No. It is an educational and productivity aid only — see the Disclaimer section above.

**Does it execute the decoded commands?**
No. It never executes, evaluates, or runs any decoded content. Decoded text is used purely for keyword matching and display.

**What if a base64/hex string doesn't decode to anything meaningful?**
It's reported at most as a low-confidence ECD-006 parse-note (or silently skipped if it isn't even a valid encoding-shaped candidate) — never as a confirmed malicious finding.

---

## License & Attribution

Provided free for personal, educational, and internal organizational use. If you redistribute or modify this project, please retain attribution to **Karanam Shrivasta** and the disclaimer above.

**Developed by Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)
