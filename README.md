# IOC Analyzer

A Django web app and REST API that automates the first steps of SOC phishing and alert triage.

Paste an **IP address, domain, URL or file hash** and it queries **VirusTotal, AbuseIPDB and urlscan.io** in parallel, combines their results into a single risk score and verdict, and saves every lookup to a searchable history. A separate **email header analyzer** flags SPF/DKIM/DMARC failures, spoofed senders and Reply-To tricks, and lists the relay IPs and domains worth investigating.

It automates the manual OSINT workflow I used as a SOC Analyst: checking an indicator across several threat-intel sites, then deciding whether to escalate.

## Features

- **Indicator detection**: recognises IPv4/IPv6, domains, URLs and MD5/SHA1/SHA256 hashes, and accepts *defanged* input (`hxxps://evil[.]com`, `1[.]2[.]3[.]4`).
- **Parallel threat-intel lookups**: VirusTotal (all types), AbuseIPDB (public IPs), urlscan.io (domains/URLs/IPs). Private IPs are never sent out.
- **Verdict engine**: each source gives a 0–100 score; the strongest signal sets the verdict (*Malicious*, *Suspicious*, *No detections*, *Unknown*).
- **Fault tolerant**: a missing API key, rate limit or network error is reported per source and never breaks the analysis.
- **Email header triage**: runs offline (headers never leave the server). Checks SPF/DKIM/DMARC, From vs Reply-To/Return-Path mismatches and display-name spoofing, and extracts relay IPs. One click sends any extracted indicator to the analyzer.
- **REST API** built with Django REST Framework, with rate limiting and pagination.
- **Safe display**: indicators are shown defanged so they can't be clicked by accident.
- **CI/CD**: GitHub Actions runs lint (ruff), Django deploy checks, a migrations check and the test suite on Python 3.11 and 3.12, then triggers a deploy to Render.

## Tech stack

Python 3.12 · Django 5.1 · Django REST Framework · Requests · SQLite · WhiteNoise · Gunicorn · GitHub Actions · Render

## Quick start

```bash
git clone https://github.com/<your-username>/ioc-analyzer.git
cd ioc-analyzer
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        # then add your free API keys
python manage.py migrate
python manage.py runserver
```

Open http://127.0.0.1:8000. The app works without keys: urlscan.io needs none, and sources without keys show as "not configured".

The environment variables are listed in [`.env.example`](.env.example). Export them in your shell, or set them in your hosting provider's dashboard.

## REST API

| Method | Endpoint | Body / params | Description |
|---|---|---|---|
| `POST` | `/api/analyze/` | `{"indicator": "8.8.8.8"}` | Analyze an indicator, returns the saved lookup |
| `POST` | `/api/headers/` | `{"headers": "<raw headers>"}` | Analyze email headers |
| `GET` | `/api/lookups/` | `?verdict=malicious&q=example` | Paginated lookup history |
| `GET` | `/api/lookups/<id>/` | | One lookup |
| `GET` | `/api/health/` | | Health check and which sources are enabled |

```bash
curl -X POST http://127.0.0.1:8000/api/analyze/ \
  -H "Content-Type: application/json" \
  -d '{"indicator": "hxxp://example[.]com"}'
```

## Tests

```bash
python manage.py test analyzer
```

22 tests cover indicator parsing, each threat-intel client (mocked HTTP, so no keys or network are needed), the verdict logic, email header analysis, the API and the web pages.

## Deploy (free) on Render

1. Push this repo to GitHub.
2. On [Render](https://render.com), choose **New + → Blueprint** and select the repo. `render.yaml` configures everything.
3. Add `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` in the service's **Environment** tab.
4. Optional: copy the service's **Deploy Hook** URL into the GitHub repo secret `RENDER_DEPLOY_HOOK`, so CI deploys only after tests pass.

## Project structure

```
analyzer/
  indicators.py     # refang/defang + indicator type detection
  intel.py          # VirusTotal, AbuseIPDB, urlscan.io clients
  services.py       # parallel lookups + verdict scoring
  email_headers.py  # SPF/DKIM/DMARC + spoofing checks
  views.py          # web pages + REST API
  tests.py          # test suite (mocked external APIs)
config/settings.py  # env-driven settings, secure defaults in production
.github/workflows/ci.yml
render.yaml
```

## Roadmap

- Bulk lookups (paste a list or upload a CSV of IOCs)
- MITRE ATT&CK mapping for common phishing findings
- Optional LLM summary of a lookup for incident tickets
- Export a lookup as a ServiceNow/Jira-ready incident note

---

Built by Mohammed Muddassir Ahmed: SOC Analyst, CompTIA Security+.
