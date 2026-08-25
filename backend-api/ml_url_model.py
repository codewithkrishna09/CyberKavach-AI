"""Optional, locally-trained phishing URL model support.

The production scanner stays usable when no validated model artifact is present.
Only load model artifacts produced and controlled by this project: joblib files are
Python serialization and must never be accepted from users or downloaded at runtime.
"""

from __future__ import annotations

import math
import os
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit


FEATURE_NAMES = (
    "url_length", "hostname_length", "dot_count", "digit_count", "hyphen_count",
    "has_ip_host", "has_at_symbol", "has_punycode", "has_https", "path_depth",
    "query_length", "suspicious_word_count",
)
SUSPICIOUS_WORDS = {"login", "verify", "update", "kyc", "secure", "account", "wallet", "refund", "support", "auth"}


def extract_url_features(url: str) -> list[float]:
    """Extract deterministic lexical features; no network requests are made."""
    parsed = urlsplit(url if "://" in url else f"https://{url}")
    host = (parsed.hostname or "").lower()
    lowered = url.lower()
    labels = [part for part in host.split(".") if part]
    has_ip_host = bool(host and all(part.isdigit() for part in host.split(".")) and len(labels) == 4)
    suspicious_word_count = sum(word in lowered for word in SUSPICIOUS_WORDS)
    return [
        float(len(url)), float(len(host)), float(host.count(".")), float(sum(char.isdigit() for char in url)),
        float(url.count("-")), float(has_ip_host), float("@" in parsed.netloc), float(host.startswith("xn--")),
        float(parsed.scheme.lower() == "https"), float(len([part for part in parsed.path.split("/") if part])),
        float(len(parsed.query)), float(suspicious_word_count),
    ]


def configured_model_path() -> Path:
    configured = os.getenv("CYBERKAVACH_URL_MODEL_PATH", "")
    return Path(configured) if configured else Path(__file__).with_name("models") / "url_phishing_model.joblib"


def model_enabled() -> bool:
    """Only use a reviewed model when an operator explicitly enables it.

    A local joblib file can be a preliminary experiment. Loading it by default
    would turn unreviewed labels into live browser warnings.
    """
    return os.getenv("CYBERKAVACH_ENABLE_URL_MODEL", "false").strip().lower() in {"1", "true", "yes"}


@lru_cache(maxsize=1)
def _load_model(path_value: str):
    # Joblib files can execute Python during loading. Load only a local artifact
    # created and controlled by this project, never a user-provided upload.
    path = Path(path_value)
    if not path.is_file():
        return None
    try:
        import joblib
        artifact = joblib.load(path)
        if artifact.get("feature_names") != list(FEATURE_NAMES) or "model" not in artifact:
            return None
        return artifact
    except (ImportError, OSError, ValueError, AttributeError):
        return None


def predict_phishing_probability(url: str) -> float | None:
    """Return a 0–100 probability only when a validated local artifact exists."""
    if not model_enabled():
        return None
    artifact = _load_model(str(configured_model_path()))
    if artifact is None:
        return None
    try:
        probability = float(artifact["model"].predict_proba([extract_url_features(url)])[0][1]) * 100
        return max(0.0, min(100.0, probability)) if math.isfinite(probability) else None
    except (AttributeError, IndexError, TypeError, ValueError):
        return None
