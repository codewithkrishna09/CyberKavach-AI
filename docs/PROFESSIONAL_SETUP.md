# CyberKavach AI: professional setup guide

This guide separates what works immediately from features that need a verified
provider account or a trained model. Do not claim a model is deployed until its
evaluation metrics have been recorded.

## Protection levels

| Level | What checks it | Internet needed | Extra cost / credit |
| --- | --- | --- | --- |
| Instant browser checks | IP URLs, `@` redirects, punycode, unsafe HTTP password forms, suspicious domain patterns | No | Free; no user scan credit |
| Cached result | Recently reviewed normalized URL | No new request | Free; short server cache |
| Deep page review | URL, domain age, redirect and visible form/iframe signals | Yes | Extension protection mode is free; manual dashboard scans use quota |
| Reputation check | Optional confirmed phishing/malware feed | Yes | Provider/API plan dependent |
| ML URL classifier | Local reviewed model artifact | No after training | Free to run locally |

## 1. Run safely in development

```bash
cd "/home/krishna/Desktop/phishguard ai"
backend-api/.venv/bin/uvicorn main:app --app-dir backend-api --reload
```

In another terminal:

```bash
cd "/home/krishna/Desktop/phishguard ai/frontend-dashboard/app"
python3 -m http.server 5501
```

Reload the unpacked extension from `chrome://extensions` after changing files in
the `extension/` folder.

## 2. Add URL reputation (known bad links)

The scanner can use an optional Google Safe Browsing key kept only in
`backend-api/.env`:

```env
CYBERKAVACH_GOOGLE_SAFE_BROWSING_API_KEY=your_backend_only_key
```

Never add this key to `extension/config.js`, GitHub, screenshots, or a frontend
file. The backend caches the reputation result for one hour by default, reducing
repeat provider requests.

For a public or paid product, first confirm that your selected reputation
provider's licence permits your use case. Google Safe Browsing is documented for
non-commercial use; commercial use needs a suitable licensed provider such as
Google Web Risk or another commercial threat-intelligence service.

## 3. Train the URL phishing model

Create a **reviewed** CSV file at `backend-api/data/url_labels.csv`:

```csv
url,label
https://www.example.com/,0
https://www.sbi.co.in/,0
https://fake-sbi-kyc.example/login,1
https://xn--paytm-9za.example/verify,1
```

- `0` means verified benign.
- `1` means verified phishing.
- Start with 200 rows only to check the pipeline. Use thousands of reviewed rows
  before relying on the output.
- Keep URLs from the same phishing campaign/domain family in a single split;
  otherwise the metrics will look falsely high.
- User reports are not labels until a human review verifies them.

Train:

```bash
cd "/home/krishna/Desktop/phishguard ai/backend-api"
.venv/bin/python train_url_model.py data/url_labels.csv
```

The model is written to `models/url_phishing_model.joblib`. Restart the backend.
The API will then return `ml_model_used: true` and the model contribution.

## 4. Minimum evaluation before claiming accuracy

Keep a final unseen test set and report:

- Precision — false alerts are low.
- Recall — phishing sites are caught.
- F1-score — balance between the two.
- False-positive rate — safe sites incorrectly warned/blocked.

Do not use a single “accuracy” percentage alone. A dataset with mostly safe URLs
can show high accuracy while still missing phishing links.

## 5. Recommended model order

1. URL phishing: current gradient-boosting baseline plus reputation and DOM
   evidence. This is the highest-impact first model.
2. Scam text: multilingual BERT/IndicBERT for English, Hindi and Hinglish SMS,
   email and web text.
3. APK malware: static permission/API/certificate features, then sandbox
   behaviour and a model trained on labelled APKs.
4. Image/document: a trained tamper detector evaluated on genuine and altered
   documents. Metadata and ELA alone are not proof.
5. Voice: a validated deepfake model evaluated on ASVspoof-like benchmarks.
   Audio metadata alone is not voice-authenticity detection.

## 6. What to say in a demo or summit

Safe wording:

> CyberKavach AI uses a hybrid browser-side and server-side risk assessment.
> It combines URL structure, live-page evidence, optional reputation checks and
> an optional locally trained classifier. All ML claims will be measured on a
> reviewed held-out test set before production deployment.

Avoid: “100% detection”, “all vulnerabilities detected”, or “fully accurate
deepfake detection”.
