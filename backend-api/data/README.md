# URL model dataset format

Keep source lists locally (they are intentionally ignored by Git) and create the
training CSV without opening a single candidate URL:

```bash
python prepare_url_dataset.py \
  --phishing /path/to/phishing_candidates.txt \
  --benign data/benign_domains.txt \
  --per-class 200 \
  --output data/url_labels.csv
```

The phishing list needs manual review. A trusted popular-domain list is only a
benign *candidate* source: sample and review it before deployment.

The generated CSV has these columns:

```csv
url,label
https://www.example.com/,0
https://brand-login.verify-account.example/,1
```

Use at least 200 **reviewed** examples, include both classes, and keep a representative benign sample. Do not use raw user reports as training labels until they have been verified.

Train with a hostname-grouped hold-out set. This keeps URLs from the same host
out of both train and test data, producing more honest preliminary metrics:

```bash
python train_url_model.py data/url_labels.csv --output models/preliminary_url_model.joblib
```

`preliminary_url_model.joblib` is deliberately not enabled automatically. Only
after reviewing the labels and metrics, train to
`models/url_phishing_model.joblib`; the scanner then uses it on restart. You can
also set `CYBERKAVACH_URL_MODEL_PATH` to a different trusted artifact.
