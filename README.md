# PhishScope v0.2

PhishScope is a defensive phishing-investigation and passive threat-intelligence platform. Upload an RFC 822 `.eml` file to preserve evidence, extract indicators, score common phishing signals, enrich domains through passive sources, manage analyst notes/status, and generate starter detection artifacts.

## v0.2 capabilities

- Evidence preservation with SHA-256 for the original message and attachments
- Sanitized attachment extraction into each case evidence directory
- URL, domain and public-IP extraction
- SPF/DKIM/DMARC and From/Reply-To mismatch findings
- Risk score, severity, case status and analyst notes
- MITRE ATT&CK phishing/user-execution mapping
- Passive RDAP domain enrichment
- Certificate Transparency enrichment via crt.sh
- Optional VirusTotal domain reputation enrichment
- Sigma starter-rule generation
- YARA starter-rule generation
- STIX 2.1 indicator bundle export
- Per-signal risk breakdown (points each finding added to the score)
- Analyst console: case queue, 14-day intake chart, IOC tables with defanged values, enrichment cards and detection-content tabs
- Persistent case browser and Docker deployment

## Dashboard

The analyst console at `http://localhost:8000` is served from `frontend/index.html` and talks only to the local API. It includes:

- **Intake**: drag-and-drop `.eml` upload, plus headline counts for open cases, critical + high cases, extracted indicators and DMARC failures
- **Cases opened, last 14 days**: stacked by severity, with hover details and a table view
- **Case queue**: sorted newest first, filterable by All / Open / Critical / High
- **Case view**: risk meter with the 30 / 60 / 80 severity thresholds and per-signal points, SPF/DKIM/DMARC results, From vs Reply-To mismatch highlighting, MITRE ATT&CK techniques, defanged IOCs with copy-raw buttons, passive enrichment results, Sigma / YARA / STIX 2.1 output, case status and analyst notes

Fonts load from Google Fonts. Without internet access the page falls back to system fonts.

### Standalone demo

`demo/dashboard.html` is a self-contained version of the console with fictional sample cases (reserved `.example` domains and documentation IP ranges). Open it directly in a browser; no backend is needed. Uploading an `.eml` there parses and scores it in the browser only, and enrichment results are simulated.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Version and whether VirusTotal is configured |
| POST | `/api/analyze` | Upload an `.eml` (multipart field `file`, 20 MB max) and create a case |
| GET | `/api/cases` | Case summaries: id, filename, created time, risk score, severity, status, subject, sender, DMARC result, indicator count |
| GET | `/api/cases/{case_id}` | Full case report |
| POST | `/api/cases/{case_id}/enrich` | Run RDAP, crt.sh and optional VirusTotal lookups (first 10 domains) |
| POST | `/api/cases/{case_id}/notes` | Add an analyst note: `{"text": "..."}` |
| POST | `/api/cases/{case_id}/status` | Set status: `new`, `investigating`, `contained` or `closed` |
| GET | `/api/cases/{case_id}/sigma` | Sigma starter rule (text) |
| GET | `/api/cases/{case_id}/yara` | YARA starter rule (text) |
| GET | `/api/cases/{case_id}/stix` | STIX 2.1 indicator bundle (JSON) |

Case reports include `signals` (each finding with its points) and `raw_score` (the uncapped total). Reports created before this field existed still load; the dashboard shows their findings without points.

## Run with Docker

```bash
docker compose up --build
```

Open `http://localhost:8000`.

### Optional VirusTotal enrichment

Copy `.env.example` to `.env` and add your API key:

```text
VIRUSTOTAL_API_KEY=your_key_here
```

Do not commit `.env` or API keys to source control.

## Local Python run

Requires Python 3.10 or newer (the Docker image uses 3.12).

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

## Case evidence

Cases are stored under `cases/<case-id>/` with `original.eml`, `report.json`, and extracted `attachments/`. Treat case directories as potentially malicious evidence. Do not open attachments on your normal workstation.

## Safety boundary

PhishScope v0.2 performs local evidence analysis and passive intelligence collection. It does not exploit, scan, compromise, credential-test, DDoS, deploy payloads to, or otherwise obtain unauthorized access to third-party infrastructure. Use external services according to their terms and only investigate systems/data you are authorized to handle.

## Known issues

- Public IP extraction currently returns no results: `IP_RE` in `backend/app/main.py` uses doubled backslashes inside a raw string, so the pattern never matches. The IP indicator count, STIX IP indicators and the IPs tab stay empty until it is fixed.

## Detection caveat

Generated Sigma and YARA content is intentionally a starting point. Review and tune it before production deployment; indicators can be shared by legitimate infrastructure and may create false positives.
