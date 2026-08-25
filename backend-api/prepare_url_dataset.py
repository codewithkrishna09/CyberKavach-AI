"""Build a balanced URL dataset without opening any supplied links.

Inputs are treated as plain text only. Candidate lists must still be reviewed
before a model is deployed, because a wrong label creates wrong alerts.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import random
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


def normalise_url(value: str) -> str | None:
    """Return a safe, canonical HTTP(S) URL without making a network request."""
    value = value.strip()
    if not value or value.startswith("#"):
        return None
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    host = parsed.hostname.rstrip(".").lower()
    try:
        address = ipaddress.ip_address(host)
        if not address.is_global:
            return None
    except ValueError:
        pass
    netloc = host if parsed.port is None else f"{host}:{parsed.port}"
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))


def read_unique_urls(path: Path) -> list[str]:
    """Read one candidate per hostname so variants cannot dominate the model."""
    urls, seen_hosts = [], set()
    with path.open(encoding="utf-8") as source:
        for line in source:
            url = normalise_url(line)
            if not url:
                continue
            host = urlsplit(url).hostname
            if host and host not in seen_hosts:
                seen_hosts.add(host)
                urls.append(url)
    return urls


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a balanced URL CSV without visiting the candidate URLs.")
    parser.add_argument("--phishing", type=Path, required=True, help="Reviewed phishing candidate list, one URL per line")
    parser.add_argument("--benign", type=Path, required=True, help="Reviewed benign domain/URL list, one per line")
    parser.add_argument("--output", type=Path, default=Path("data/url_labels.csv"))
    parser.add_argument("--per-class", type=int, default=200, help="Equal number of URLs per label")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if args.per_class < 100:
        raise ValueError("Use at least 100 samples per class.")
    phishing = read_unique_urls(args.phishing)
    benign = read_unique_urls(args.benign)
    if len(phishing) < args.per_class or len(benign) < args.per_class:
        raise ValueError(
            f"Need {args.per_class} unique URLs in each list; found phishing={len(phishing)}, benign={len(benign)}."
        )
    random.Random(args.seed).shuffle(phishing)
    random.Random(args.seed + 1).shuffle(benign)
    rows = [(url, 1) for url in phishing[:args.per_class]] + [(url, 0) for url in benign[:args.per_class]]
    random.Random(args.seed + 2).shuffle(rows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as target:
        writer = csv.writer(target)
        writer.writerow(("url", "label"))
        writer.writerows(rows)
    print(f"Created {args.output}: {args.per_class} phishing + {args.per_class} benign, no URLs were opened.")
    print("Review a sample of both classes before using this dataset to enable the live model.")


if __name__ == "__main__":
    main()
