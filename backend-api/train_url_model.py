"""Train a local phishing URL classifier from a reviewed CSV dataset.

CSV columns: url,label where label is 0 (benign) or 1 (phishing).
Do not train from unreviewed user feedback alone.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from joblib import dump
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from ml_url_model import FEATURE_NAMES, extract_url_features


def load_dataset(path: Path) -> tuple[list[list[float]], list[int]]:
    # Skip incomplete rows instead of guessing labels; wrong labels reduce
    # phishing-model accuracy more than a smaller clean dataset does.
    features, labels = [], []
    with path.open(newline="", encoding="utf-8") as source:
        for row in csv.DictReader(source):
            label = row.get("label", "").strip()
            url = row.get("url", "").strip()
            if url and label in {"0", "1"}:
                features.append(extract_url_features(url))
                labels.append(int(label))
    if len(features) < 200 or len(set(labels)) != 2:
        raise ValueError("Use at least 200 reviewed samples containing both benign (0) and phishing (1) labels.")
    return features, labels


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path, help="Reviewed CSV with url,label columns")
    parser.add_argument("--output", type=Path, default=Path("models/url_phishing_model.joblib"))
    args = parser.parse_args()
    features, labels = load_dataset(args.dataset)
    x_train, x_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42, stratify=labels)
    # Keep a held-out test split so reported metrics reflect unseen URLs.
    model = HistGradientBoostingClassifier(max_iter=250, learning_rate=0.08, random_state=42)
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    print(classification_report(y_test, predictions, digits=3))
    print(f"precision={precision_score(y_test, predictions):.3f}")
    print(f"recall={recall_score(y_test, predictions):.3f}")
    print(f"f1={f1_score(y_test, predictions):.3f}")
    if precision_score(y_test, predictions) < 0.85 or recall_score(y_test, predictions) < 0.85:
        print("WARNING: Metrics are below the recommended 0.85 threshold. Review data quality before deployment.")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    dump({"model": model, "feature_names": list(FEATURE_NAMES), "version": 1}, args.output)
    print(f"Saved trusted local model artifact to {args.output}")


if __name__ == "__main__":
    main()
