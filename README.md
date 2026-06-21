# IDOR Hunter Pro

**Autonomous IDOR vulnerability scanner with HackerOne-ready report generation.**

Part of the RedMind Suite — a collection of focused, niche penetration testing tools built for precision over breadth.

---

## What it does

IDOR Hunter Pro detects Insecure Direct Object Reference vulnerabilities — the pattern where an API returns another user's data just because you changed a number in the URL. It automates the entire workflow: discovery, enumeration, confirmation, and submission-ready reporting.

```
DISCOVER → ENUMERATE → DIFF → CONFIRM → REPORT
```

## Three ways to find targets

**Manual URL Mode** — paste a list of known endpoints, the engine detects ID parameters automatically and tests them.

**Proxy Mode** — route your browser through the built-in mitmproxy addon. Every authenticated request you make gets captured and scanned in real time. No manual URL collection.

**Crawl Mode** — a headless Playwright browser logs in (cookies or credentials), crawls the site up to 4 levels deep, clicks through nav menus and tabs, and captures every API call automatically. No proxy, no certificate setup.

All three modes feed into the same detection engine and produce the same evidence format.

## Detection engine

- Detects numeric IDs and UUIDs in URL paths, query strings, and JSON bodies
- Generates ~30 targeted probe IDs per parameter (adjacent values, enumeration ranges, high-value specials, random UUIDs)
- Multi-axis diff engine: status code, response size, structural fingerprint, sensitive field presence
- Requires 3 independent confirmations before flagging anything as "confirmed" — minimizes false positives
- Auto-scores CVSS 3.1 based on exposed data sensitivity
- Domain allowlist filters out third-party noise (Google Analytics, Facebook Pixel, Fullstory, Datadog, and 20+ other trackers) so scans stay focused on the actual target

## Report generation

Every confirmed finding can be exported as:
- **HTML** — styled, dark-mode report ready to copy into HackerOne
- **PDF** — downloadable, attachable to any bug bounty submission

Both include: title, CVSS score and vector, affected URL, numbered steps to reproduce, side-by-side request/response evidence, exposed sensitive fields, impact statement, and recommended fix.

## Stack

- **Backend:** Flask, Python
- **Proxy interception:** mitmproxy
- **Browser automation:** Playwright (Chromium headless)
- **PDF generation:** ReportLab
- **Frontend:** Vanilla JS + Server-Sent Events for live scan monitoring

## Quick start

```bash
git clone https://github.com/IbrahimAbdulqadir/idor-hunter-pro.git
cd idor-hunter-pro
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium
playwright install-deps chromium
python app.py
```

Open `http://127.0.0.1:5000`

## Usage

1. Go to **New Scan**
2. Choose your mode:
   - **Manual** — paste endpoint list, paste cookies
   - **Proxy** — toggle on, run `mitmdump -s proxy_addon.py --listen-port 8080 --ssl-insecure` in a separate terminal, configure browser proxy to `127.0.0.1:8080`, browse your target
   - **Crawl** — enter base URL + cookies (or credentials), set crawl depth, hit Start
3. Set a **Target Domains allowlist** (e.g. `api.target.com, app.target.com`) to filter out tracker noise
4. Watch findings appear live on the dashboard
5. Click any confirmed finding → **Generate Report** → download HTML or PDF

## Project structure

```
idor_hunter/
├── app.py                     # Flask app — all routes
├── requirements.txt
├── proxy_addon.py             # mitmproxy interceptor script
├── core/
│   ├── engine.py              # Detection, enumeration, diff, CVSS, domain filtering
│   ├── proxy_session.py       # Proxy mode auto-scan pipeline
│   ├── crawl_session.py       # Crawl mode (Playwright) auto-scan pipeline
│   └── report_generator.py    # HTML + PDF report generation
└── templates/
    ├── base.html               # Layout + design system
    ├── index.html              # Dashboard
    ├── new_scan.html           # Mission setup — all 3 modes
    ├── monitor.html            # Live scan monitor (manual mode)
    ├── findings.html           # Findings board (Kanban)
    ├── finding_detail.html     # Evidence viewer
    ├── report_builder.html     # Report export UI
    └── 404.html
```

## Roadmap

- [x] Manual URL enumeration engine
- [x] HackerOne HTML/PDF report generator
- [x] Proxy mode (mitmproxy)
- [x] Crawl mode (Playwright)
- [ ] Persistent storage (currently in-memory, resets on restart)
- [ ] Multi-target campaign management
- [ ] Burp Suite project file import

## Disclaimer

This tool is built for authorized security testing only — bug bounty programs you're enrolled in, or systems you have explicit written permission to test. Do not use against systems without authorization. The author is not responsible for misuse.

## Author

Ibrahim Abdulqadir — Cybersecurity researcher, BSc Cybersecurity (Bayero University Kano), independent bug bounty hunter.

[LinkedIn](https://linkedin.com/in/ibrahimabdulqadir) · [Portfolio](https://ibrahimabdulqadir.github.io)
