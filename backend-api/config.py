"""Environment-backed configuration for the CyberKavach API."""

import os
from pathlib import Path
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
# Load local development secrets from backend-api/.env. This file is ignored by
# git; .env.example remains only a copyable template.
load_dotenv(BASE_DIR / ".env")


def _csv_env(name: str, default: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


DB_FILE = os.getenv("CYBERKAVACH_DB_FILE", str(BASE_DIR / "cyberkavach_master.db"))
ALLOWED_ORIGINS = _csv_env(
    "CYBERKAVACH_ALLOWED_ORIGINS",
    "http://127.0.0.1:5501,http://localhost:5501,http://[::1]:5501,http://127.0.0.1:3000,http://localhost:3000,http://[::1]:3000",
)
# Development convenience: any port is allowed only for loopback hosts, along
# with locally loaded Chrome extensions. Public deployments must keep
# CYBERKAVACH_ALLOWED_ORIGIN_REGEX empty and use exact HTTPS/extension origins.
ALLOWED_ORIGIN_REGEX = os.getenv(
    "CYBERKAVACH_ALLOWED_ORIGIN_REGEX",
    r"^(?:http://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]):[0-9]{1,5}|chrome-extension://[a-p]{32})$",
)
ALLOWED_EXTENSION_ORIGINS = _csv_env("CYBERKAVACH_EXTENSION_ORIGINS", "")
ALLOWED_HOSTS = _csv_env("CYBERKAVACH_ALLOWED_HOSTS", "127.0.0.1,localhost,testserver")

# Optional, server-side only. Do not place this key in extension/config.js.
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("CYBERKAVACH_GOOGLE_SAFE_BROWSING_API_KEY", "")
THREAT_INTEL_TIMEOUT_SECONDS = float(os.getenv("CYBERKAVACH_THREAT_INTEL_TIMEOUT_SECONDS", "3"))
THREAT_INTEL_CACHE_SECONDS = int(os.getenv("CYBERKAVACH_THREAT_INTEL_CACHE_SECONDS", "3600"))
SCAN_RESULT_CACHE_SECONDS = int(os.getenv("CYBERKAVACH_SCAN_RESULT_CACHE_SECONDS", "1800"))

MAX_APK_BYTES = int(os.getenv("CYBERKAVACH_MAX_APK_BYTES", str(50 * 1024 * 1024)))
MAX_FORENSIC_BYTES = int(os.getenv("CYBERKAVACH_MAX_FORENSIC_BYTES", str(20 * 1024 * 1024)))
MAX_URL_LENGTH = int(os.getenv("CYBERKAVACH_MAX_URL_LENGTH", "2048"))
MAX_SHADOW_QUERY_LENGTH = int(os.getenv("CYBERKAVACH_MAX_SHADOW_QUERY_LENGTH", "320"))
MAX_REQUESTS_PER_MINUTE = int(os.getenv("CYBERKAVACH_RATE_LIMIT_PER_MINUTE", "120"))
