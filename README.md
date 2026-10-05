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
- Persistent case browser and Docker deployment

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

## Detection caveat

Generated Sigma and YARA content is intentionally a starting point. Review and tune it before production deployment; indicators can be shared by legitimate infrastructure and may create false positives.
