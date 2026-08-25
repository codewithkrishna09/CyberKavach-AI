"""Train a local phishing URL classifier from a reviewed CSV dataset.

CSV columns: url,label where label is 0 (benign) or 1 (phishing).
Do not train from unreviewed user feedback alone.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from urllib.parse import urlsplit

from joblib import dump
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from ml_url_model import FEATURE_NAMES, extract_url_features


def load_dataset(path: Path) -> tuple[list[str], list[list[float]], list[int]]:
    # Skip incomplete rows instead of guessing labels; wrong labels reduce
    # phishing-model accuracy more than a smaller clean dataset does.
    urls, features, labels = [], [], []
    with path.open(newline="", encoding="utf-8") as source:
        for row in csv.DictReader(source):
            label = row.get("label", "").strip()
            url = row.get("url", "").strip()
            if url and label in {"0", "1"}:
                urls.append(url)
                features.append(extract_url_features(url))
                labels.append(int(label))
    if len(features) < 200 or len(set(labels)) != 2:
        raise ValueError("Use at least 200 reviewed samples containing both benign (0) and phishing (1) labels.")
    return urls, features, labels


def host_group(url: str) -> str:
    """Keep the same hostname out of both training and test data."""
    return (urlsplit(url if "://" in url else f"https://{url}").hostname or url).lower()


def split_dataset(urls, features, labels, test_size: float, strategy: str):
    """Make a reproducible hold-out set without leaking duplicate hostnames."""
    if strategy == "random":
        return train_test_split(features, labels, test_size=test_size, random_state=42, stratify=labels)

    # A URL path from a domain already seen in training makes results look much
    # better than real-world performance. Grouping by hostname avoids that leak.
    groups = [host_group(url) for url in urls]
    for seed in range(42, 62):
        splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
        train_indices, test_indices = next(splitter.split(features, labels, groups))
        y_train = [labels[index] for index in train_indices]
        y_test = [labels[index] for index in test_indices]
        if len(set(y_train)) == 2 and len(set(y_test)) == 2:
            return (
                [features[index] for index in train_indices],
                [features[index] for index in test_indices],
                y_train,
                y_test,
            )
    raise ValueError("Could not create a host-grouped split with both labels. Add more distinct reviewed domains.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path, help="Reviewed CSV with url,label columns")
    parser.add_argument("--output", type=Path, default=Path("models/url_phishing_model.joblib"))
    parser.add_argument("--test-size", type=float, default=0.2, help="Held-out test share (default: 0.2)")
    parser.add_argument("--split", choices=("host-grouped", "random"), default="host-grouped")
    args = parser.parse_args()
    if not 0.05 <= args.test_size < 0.5:
        raise ValueError("--test-size must be between 0.05 and 0.49")
    urls, features, labels = load_dataset(args.dataset)
    x_train, x_test, y_train, y_test = split_dataset(urls, features, labels, args.test_size, args.split)
    print(f"samples={len(labels)} train={len(y_train)} test={len(y_test)} split={args.split}")
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
    dump({"model": model, "feature_names": list(FEATURE_NAMES), "version": 1, "split": args.split}, args.output)
    print(f"Saved local model artifact to {args.output}")


if __name__ == "__main__":
    main()
