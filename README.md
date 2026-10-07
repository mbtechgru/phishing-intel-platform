# PhishScope v0.3

PhishScope is a defensive phishing-investigation and passive threat-intelligence platform. Upload an RFC 822 `.eml` file to preserve evidence, extract indicators, score common phishing signals, enrich domains through passive sources, manage analyst notes/status, and generate starter detection artifacts. v0.3 adds cross-case IOC correlation, an infrastructure relationship graph, SOC metrics, case tags and a printable investigation report.

## Capabilities

- Evidence preservation with SHA-256 for the original message and attachments
- Sanitized attachment extraction into each case evidence directory
- URL, domain (including the From domain) and public-IP extraction
- SPF/DKIM/DMARC and From/Reply-To mismatch findings
- Risk score, severity, case status and analyst notes
- Analyst verdict (malicious, suspicious, spam, benign or phishing simulation) with a required reason and change history, kept separate from the risk score
- Newly registered domain signal: after enrichment, +20 points if any domain was registered under 30 days ago
- Attachment risk weighting: executables, scripts, shortcuts, disk images and OneNote files (+30); HTML/SVG attachments used for credential pages and HTML smuggling (+20); macro-enabled Office files (+20); password-protected ZIP archives (+20). ZIP contents are inspected, so a shortcut hidden inside an archive is still flagged
- Lookalike domain detection (+30) against your own domains (`PROTECTED_DOMAINS`) and commonly impersonated brands (`rules/brands.json`): character substitution (`rnicrosoft`, `paypa1`), Unicode look-alikes (punycode), names embedded in unrelated domains (`microsoft-login.net`, `login.microsoft.com.verify-acct.xyz`), near misspellings and the same name on a different domain ending
- Sender display-name impersonation (+15): a display name such as "Microsoft 365" or your company name on mail from an unrelated domain
- Rescan: re-parse preserved originals with the current rules, keeping status, verdict, notes, tags and enrichment
- MITRE ATT&CK mapping: phishing, spearphishing link/attachment, user execution, HTML smuggling (T1027.006), domain acquisition (T1583.001) and impersonation (T1656)
- Passive RDAP domain enrichment
- Certificate Transparency enrichment via crt.sh
- Optional VirusTotal domain reputation enrichment
- Sigma starter-rule generation
- YARA starter-rule generation
- STIX 2.1 indicator bundle export
- Per-signal risk breakdown (points each finding added to the score)
- Cross-case IOC correlation: finds other cases sharing a domain, IP, URL or attachment hash
- Infrastructure relationship graph (case, sender, URLs, domains, IPs, attachments, certificate names)
- SOC metrics: unique and reused indicators across all cases
- Cross-case intelligence view: domain registration age, registrar, name servers, shared infrastructure and recurring indicators across all cases
- Combined detections: one merged Sigma rule, YARA rule or STIX 2.1 bundle across selected cases
- Case tags
- Printable investigation report (browser Print / Save PDF)
- Analyst console: case queue, 14-day intake chart, IOC tables with defanged values, enrichment cards and detection-content tabs
- Persistent case browser and Docker deployment

## Dashboard

The analyst console at `http://localhost:8000` is served from `frontend/index.html` and talks only to the local API. It includes:

- **Intake**: drag-and-drop `.eml` upload, plus headline counts for open cases, critical + high cases, unique indicators (and how many recur across cases) and DMARC failures
- **Cases opened, last 14 days**: stacked by severity, with hover details and a table view
- **Case queue**: sorted newest first, filterable by All / Open / Critical / High
- **Intelligence** (`#intelligence`): every domain seen across cases with its registration age (newly registered domains under 30 days flagged), registrar, name servers, certificate transparency name count and the cases it appeared in, filterable by All / Newly registered / In open cases / Not enriched. It also lists name servers and registrars shared by two or more domains, and indicators recurring in two or more cases. Domains show lookup data once enrichment has been run on a case containing them. Case IDs link back to the case view.
- **Detections** (`#detections`): choose cases by scope (Open / Critical + high / All) and tick or untick individual cases to generate one merged Sigma rule, YARA rule or STIX 2.1 bundle with duplicates removed. Sigma output carries ATT&CK tags and the STIX bundle adds attachment-hash indicators. Copy or download as `.yml`, `.yar` or `.json`. Closed cases and cases with a benign or simulation verdict start unticked, since their indicators are often legitimate (including your own domains).
- **Case view**: tags and a link to the printable report, analyst verdict with reason (shown as a badge in the queue and in the printable report), a **Rescan with current rules** button, risk meter with the 30 / 60 / 80 severity thresholds and per-signal points, SPF/DKIM/DMARC results, From vs Reply-To mismatch highlighting, MITRE ATT&CK techniques, defanged IOCs with copy-raw buttons, passive enrichment cards (domain age, registrar, domain status in plain language with holds, expiry and recent registration highlighted, name servers with the DNS provider, registry ID and certificate names), correlated cases, a radial infrastructure graph, Sigma / YARA / STIX 2.1 output, case status and analyst notes

Fonts load from Google Fonts. Without internet access the page falls back to system fonts.

### Standalone demo

`demo/dashboard.html` is a self-contained version of the v0.3 console (including correlations, the infrastructure graph, tags and the printable report) with fictional sample cases (reserved `.example` domains and documentation IP ranges). Open it directly in a browser; no backend is needed. Uploading an `.eml` there parses and scores it in the browser only, and enrichment results are simulated.

The demo also includes the Intelligence and Detections views, computed in the browser from the sample cases.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Version, whether VirusTotal is configured, the protected domains and the number of brands loaded from `rules/brands.json` |
| POST | `/api/analyze` | Upload an `.eml` (multipart field `file`, 20 MB max) and create a case |
| GET | `/api/cases` | Case summaries: id, filename, created time, risk score, severity, status, verdict, subject, sender, DMARC result, indicator count, tags |
| GET | `/api/metrics` | Case counts by severity, status and verdict, unique and reused indicators, top reused indicators |
| GET | `/api/intel` | Cross-case rollup of saved enrichment: domains with registration age, registrar, name servers and cases; shared name servers and registrars; indicators recurring in 2+ cases |
| GET | `/api/detections?cases=id1,id2&format=sigma` | One merged Sigma (text), YARA (text) or STIX 2.1 (JSON) artifact across the listed cases; `format` is `sigma`, `yara` or `stix` |
| GET | `/api/cases/{case_id}` | Full case report |
| GET | `/api/cases/{case_id}/correlations` | Other cases sharing indicators with this one, most shared first |
| GET | `/api/cases/{case_id}/graph` | Infrastructure graph as `nodes` and `edges` |
| GET | `/api/cases/{case_id}/report` | Printable HTML investigation report |
| POST | `/api/cases/{case_id}/enrich` | Run RDAP (including registrar name), crt.sh and optional VirusTotal lookups (first 10 domains), then rescore the case (adds the newly registered domain signal when it applies) |
| POST | `/api/cases/{case_id}/notes` | Add an analyst note: `{"text": "..."}` |
| POST | `/api/cases/{case_id}/rescan` | Re-parse this case's preserved `original.eml` with the current rules and rescore it; status, verdict, notes, tags and enrichment are kept |
| POST | `/api/rescan` | Rescan every case, for example after editing `rules/brands.json` or `PROTECTED_DOMAINS`. Returns the count and any failures |
| POST | `/api/cases/{case_id}/verdict` | Record the analyst verdict: `{"verdict": "malicious", "reason": "..."}`. Verdict is `malicious`, `suspicious`, `spam`, `benign` or `simulation`; reason is required (1000 characters max). Earlier verdicts are kept in `verdict_history` |
| POST | `/api/cases/{case_id}/status` | Set status: `new`, `investigating`, `contained` or `closed` |
| POST | `/api/cases/{case_id}/tags` | Replace tags: `{"tags": ["..."]}` (20 max, 40 characters each) |
| GET | `/api/cases/{case_id}/sigma` | Sigma starter rule (text) |
| GET | `/api/cases/{case_id}/yara` | YARA starter rule (text) |
| GET | `/api/cases/{case_id}/stix` | STIX 2.1 indicator bundle (JSON) |

Case reports include `signals` (each finding with its points) and `raw_score` (the uncapped total). Reports created before this field existed still load; the dashboard shows their findings without points, and enrichment does not rescore them (re-upload the `.eml` to get the newly registered domain signal).

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

### Protect your own domains

Set your organization's email domains in `.env` so lookalikes of them (and sender display names that use your company name) are flagged:

```text
PROTECTED_DOMAINS=example.com,example-corp.com
```

The header shows a warning chip until this is set. Restart the container after changing `.env` (`docker compose up -d`), then rescan existing cases with `curl -X POST http://localhost:8000/api/rescan`.

### Maintaining detection rules

`rules/brands.json` lists commonly impersonated brands and each brand's real domains, which are never flagged. Add the vendors, banks and SaaS tools your organization uses, and add a brand's legitimate domain when one is flagged by mistake. `_display_name_ignore` holds brands that are also common words or first names (such as Chase or Apple), which are checked in domains only. Docker mounts `rules/` read-only and the file is reread on every upload and rescan, so edits apply without a rebuild. Run `POST /api/rescan` to apply them to existing cases.

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

PhishScope performs local evidence analysis and passive intelligence collection. It does not exploit, scan, compromise, credential-test, DDoS, deploy payloads to, or otherwise obtain unauthorized access to third-party infrastructure. Use external services according to their terms and only investigate systems/data you are authorized to handle.

## Detection caveat

Generated Sigma and YARA content is intentionally a starting point. Review and tune it before production deployment; indicators can be shared by legitimate infrastructure and may create false positives.
