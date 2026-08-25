"""Convert the public PhiUSIIL CSV into CyberKavach's URL-only training format.

The source dataset's labels are the reverse of this project: PhiUSIIL uses
0=phishing and 1=legitimate, while CyberKavach uses 1=phishing and 0=benign.
No URL is opened during conversion.
"""

from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path
from urllib.parse import urlsplit

from prepare_url_dataset import normalise_url


def cyberkavach_label(phiusiil_label: str) -> int | None:
    """Map documented PhiUSIIL labels to CyberKavach labels safely."""
    return {"0": 1, "1": 0}.get(str(phiusiil_label).strip())


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a balanced CyberKavach URL dataset from PhiUSIIL.")
    parser.add_argument("dataset", type=Path, help="Path to PhiUSIIL_Phishing_URL_Dataset.csv")
    parser.add_argument("--output", type=Path, default=Path("data/phiusiil_url_labels.csv"))
    parser.add_argument("--per-class", type=int, default=10_000, help="URLs to keep for each class")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if args.per_class < 100:
        raise ValueError("Use at least 100 URLs per class.")

    # Store one URL per hostname. This reduces near-duplicate training samples
    # and makes the hostname-grouped test split more meaningful.
    candidates: dict[int, list[str]] = {0: [], 1: []}
    seen_hosts: dict[int, set[str]] = {0: set(), 1: set()}
    skipped = 0
    with args.dataset.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames or "URL" not in reader.fieldnames or "label" not in reader.fieldnames:
            raise ValueError("PhiUSIIL CSV must contain URL and label columns.")
        for row in reader:
            label = cyberkavach_label(row.get("label", ""))
            url = normalise_url(row.get("URL", ""))
            host = urlsplit(url).hostname if url else None
            if label is None or not host or host in seen_hosts[label]:
                skipped += 1
                continue
            seen_hosts[label].add(host)
            candidates[label].append(url)

    if min(len(candidates[0]), len(candidates[1])) < args.per_class:
        raise ValueError(
            f"Not enough unique hosts: benign={len(candidates[0])}, phishing={len(candidates[1])}; "
            f"requested={args.per_class}."
        )
    random.Random(args.seed).shuffle(candidates[0])
    random.Random(args.seed + 1).shuffle(candidates[1])
    rows = [(url, 0) for url in candidates[0][:args.per_class]]
    rows += [(url, 1) for url in candidates[1][:args.per_class]]
    random.Random(args.seed + 2).shuffle(rows)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as target:
        writer = csv.writer(target)
        writer.writerow(("url", "label"))
        writer.writerows(rows)
    print(
        f"Created {args.output}: {args.per_class} benign + {args.per_class} phishing URLs. "
        f"Skipped {skipped} invalid/duplicate rows; no URLs were opened."
    )


if __name__ == "__main__":
    main()
