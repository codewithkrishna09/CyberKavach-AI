"""Optional URL reputation checks with short-lived, privacy-conscious caching.

Why this exists:
Heuristics can identify suspicious patterns but cannot recognise a URL already
confirmed as phishing or malware. A reputation provider adds that missing
evidence. The integration is optional, so local development never fails when
no provider key is configured.
"""

from __future__ import annotations

import hashlib
import time
from threading import Lock

import requests

from config import GOOGLE_SAFE_BROWSING_API_KEY, THREAT_INTEL_CACHE_SECONDS, THREAT_INTEL_TIMEOUT_SECONDS


_cache: dict[str, tuple[float, dict]] = {}
_cache_lock = Lock()


def _cache_key(url: str) -> str:
    """Keep only a hash in process memory; do not retain a user's raw URL here."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def lookup_url_reputation(url: str) -> dict:
    """Return a provider-confirmed malicious verdict or an unavailable result.

    The Google Safe Browsing endpoint is intentionally called server-side: API
    keys must never be bundled into the browser extension. Provider failures do
    not increase risk because an outage is not evidence that a URL is harmful.
    """
    # Local scanning still works when no reputation key is configured.
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return {"checked": False, "hit": False, "provider": None, "categories": []}

    key = _cache_key(url)
    now = time.monotonic()
    with _cache_lock:
        cached = _cache.get(key)
        if cached and cached[0] > now:
            return {**cached[1], "cache_hit": True}

    payload = {
        "client": {"clientId": "cyberkavach-ai", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    result = {"checked": True, "hit": False, "provider": "google_safe_browsing", "categories": []}
    try:
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}",
            json=payload,
            timeout=THREAT_INTEL_TIMEOUT_SECONDS,
        )
        if response.status_code == 200:
            matches = response.json().get("matches", [])
            result["hit"] = bool(matches)
            result["categories"] = sorted({match.get("threatType", "UNKNOWN") for match in matches})
        else:
            result["checked"] = False
    except requests.RequestException:
        # Never expose provider/network details to users or turn an outage into a threat score.
        result["checked"] = False

    with _cache_lock:
        if len(_cache) > 10_000:
            _cache.clear()
        _cache[key] = (now + THREAT_INTEL_CACHE_SECONDS, result)
    return result
