# URL model dataset format

Create `url_labels.csv` with these columns:

```csv
url,label
https://www.example.com/,0
https://brand-login.verify-account.example/,1
```

Use at least 200 **reviewed** examples, include both classes, and keep a representative benign sample. Do not use raw user reports as training labels until they have been verified.

Train and review its held-out metrics before deployment:

```bash
python train_url_model.py data/url_labels.csv --output models/url_phishing_model.joblib
```

The scanner will automatically use the resulting local model artifact. You can set `CYBERKAVACH_URL_MODEL_PATH` to use a different trusted artifact.
