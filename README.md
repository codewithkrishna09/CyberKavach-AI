# CyberKavach AI

CyberKavach AI is an India-focused cybersecurity prototype that helps users identify phishing websites, risky Android APKs, suspicious documents and media, and exposed passwords before harm occurs.

## What it includes

- **Titan Web Scanner**: URL, domain, redirect and live-page signal analysis with explainable risk evidence.
- **Chrome extension**: scans visited pages, warns on suspicious sites and blocks high-risk navigation.
- **APK Shield**: static APK inspection for risky permissions, suspicious APIs, bytecode strings and archive anomalies.
- **Satark Forensics**: image, PDF and audio forensic screening.
- **Shadow Scout**: privacy-preserving breached-password checks and heuristic UPI/email/phone risk checks.
- **Feedback loop**: users can report a scam or flag an incorrect result for analyst review and future model evaluation.
- **Optional ML URL classifier**: a reviewed local model can be trained from labelled data and combined with heuristic evidence; the scanner safely falls back when no validated model is configured.

## Important safety note

CyberKavach AI currently uses explainable heuristic and forensic risk analysis. A `SAFE` result means no known indicators were found in the available scan; it is **not** a guarantee that the target is harmless. Trained ML models and threat-intelligence integrations should be benchmarked on labelled data before production use.

For local setup, optional URL reputation, model training, and evaluation rules,
see [the professional setup guide](docs/PROFESSIONAL_SETUP.md).

## Project layout

```text
backend-api/          FastAPI application and detection engines
extension/            Chromium Manifest V3 browser extension
frontend-dashboard/   Dashboard and static web interface
```

## Run locally

```bash
cd backend-api
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Open `frontend-dashboard/app/index.html` with a local static server and set the API URL in `frontend-dashboard/app/config.js` if needed. Load `extension/` as an unpacked extension from Chromium's Extensions page.

## Test

```bash
cd backend-api
python -m unittest discover -s tests -v
```

## Planned upgrades

- ML phishing classifier using labelled URL, DNS and DOM features (model-ready URL pipeline included)
- NLP scam-message detection for English, Hindi and Hinglish
- Dynamic APK sandboxing and hash reputation checks
- Validated image/document and audio deepfake models
- Threat-intelligence integrations such as Google Safe Browsing, URLhaus and VirusTotal
- PostgreSQL, Redis, Docker and cloud deployment for scalable production use
