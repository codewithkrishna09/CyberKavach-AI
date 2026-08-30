"""FastAPI entry point for CyberKavach.

This file validates requests and privacy rules, then sends slow analysis work
to specialised engines without blocking the web server.
"""

import datetime
import asyncio
import hashlib
import json
import logging
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path

from fastapi import FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from apk_shield import analyze_apk
from config import (
    ALLOWED_EXTENSION_ORIGINS,
    ALLOWED_HOSTS,
    ALLOWED_ORIGIN_REGEX,
    ALLOWED_ORIGINS,
    DB_FILE,
    MAX_APK_BYTES,
    MAX_FORENSIC_BYTES,
    MAX_REQUESTS_PER_MINUTE,
    MAX_SHADOW_QUERY_LENGTH,
    MAX_URL_LENGTH,
)
from satark_engine import analyze_forensics
from scanner import scan_website_logic
from security import SlidingWindowRateLimiter, normalize_api_key, validate_upload
from shadow_scout import analyze_shadow_query


# Application setup: docs are disabled in this demo deployment so internal API
# details are not exposed publicly by default.
app = FastAPI(title="CyberKavach API", docs_url=None, redoc_url=None)
logger = logging.getLogger("cyberkavach")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)
# CORS allows only configured dashboard and extension origins to call the API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS + ALLOWED_EXTENSION_ORIGINS,
    allow_origin_regex=ALLOWED_ORIGIN_REGEX or None,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "X-Scan-Mode"],
    max_age=600,
)

# Shared services used by all endpoints.
rate_limiter = SlidingWindowRateLimiter(MAX_REQUESTS_PER_MINUTE)
scan_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="cyberkavach-scan")


async def run_engine(function, *args, timeout: float):
    # File and URL analysis can be slow. Run it outside FastAPI's event loop so
    # one scan does not freeze other users' requests.
    loop = asyncio.get_running_loop()
    future = loop.run_in_executor(scan_executor, partial(function, *args))
    return await asyncio.wait_for(future, timeout=timeout)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # Apply the same rate limit and browser safety headers to every API route.
    # Keep local CORS troubleshooting visible without logging request bodies,
    # API keys, URLs, passwords, or uploaded content.
    if request.method == "OPTIONS":
        logger.info("CORS preflight: origin=%s path=%s", request.headers.get("origin", "missing"), request.url.path)
    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.allow(client_ip):
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many requests. Try again shortly."},
            headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"},
        )
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def key_digest(api_key: str) -> str:
    # A hash lets us identify the same user without saving their raw secret.
    return "sha256$" + hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def get_current_date() -> str:
    return datetime.date.today().isoformat()


def get_db_connection() -> sqlite3.Connection:
    # Each request receives a short-lived SQLite connection. WAL mode and the
    # busy timeout reduce "database locked" errors during simultaneous scans.
    conn = sqlite3.connect(DB_FILE, timeout=15.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def init_db() -> None:
    # Create local tables on first startup. No user action is needed.
    Path(DB_FILE).parent.mkdir(parents=True, exist_ok=True)
    conn = get_db_connection()
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
            api_key TEXT PRIMARY KEY,
            email TEXT,
            plan TEXT NOT NULL DEFAULT 'FREE' CHECK(plan IN ('FREE', 'PRO')),
            url_used INTEGER NOT NULL DEFAULT 0 CHECK(url_used >= 0),
            ai_used INTEGER NOT NULL DEFAULT 0 CHECK(ai_used >= 0),
            last_reset DATE NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key TEXT NOT NULL,
            url TEXT NOT NULL,
            verdict TEXT NOT NULL,
            score INTEGER NOT NULL CHECK(score BETWEEN 0 AND 100),
            method TEXT NOT NULL,
            analysis_json TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS scan_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key TEXT NOT NULL,
            target TEXT NOT NULL,
            feedback_type TEXT NOT NULL CHECK(feedback_type IN ('false_positive', 'reported_scam')),
            comment TEXT NOT NULL DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )"""
    )

    # One-time migration: replace any legacy plaintext identifiers with hashes.
    legacy_users = conn.execute("SELECT api_key FROM users WHERE api_key NOT LIKE 'sha256$%'").fetchall()
    for row in legacy_users:
        raw_key = row["api_key"]
        hashed = key_digest(raw_key)
        conn.execute("UPDATE scan_logs SET api_key = ? WHERE api_key = ?", (hashed, raw_key))
        try:
            conn.execute("UPDATE users SET api_key = ? WHERE api_key = ?", (hashed, raw_key))
        except sqlite3.IntegrityError:
            conn.execute("DELETE FROM users WHERE api_key = ?", (raw_key,))
    orphaned_log_keys = conn.execute("SELECT DISTINCT api_key FROM scan_logs WHERE api_key NOT LIKE 'sha256$%'").fetchall()
    for row in orphaned_log_keys:
        if row["api_key"]:
            conn.execute("UPDATE scan_logs SET api_key=? WHERE api_key=?", (key_digest(row["api_key"]), row["api_key"]))
    conn.commit()
    conn.close()


init_db()


def verify_and_sync_user(raw_api_key: str | None) -> dict:
    # Store only a one-way hash of the local session identifier in SQLite.
    api_key = normalize_api_key(raw_api_key)
    owner_id = key_digest(api_key)
    today = get_current_date()
    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM users WHERE api_key = ?", (owner_id,)).fetchone()
        if row is None:
            # The existing column name is retained only for compatibility with
            # local databases created by earlier builds. It is not a user plan.
            plan = "FREE"
            conn.execute(
                "INSERT INTO users (api_key, email, plan, url_used, ai_used, last_reset) VALUES (?, ?, ?, 0, 0, ?)",
                (owner_id, "", plan, today),
            )
        elif row["last_reset"] != today:
            conn.execute(
                "UPDATE users SET url_used=0, ai_used=0, last_reset=? WHERE api_key=?",
                (today, owner_id),
            )
        conn.commit()
        user = conn.execute("SELECT * FROM users WHERE api_key = ?", (owner_id,)).fetchone()
        return dict(user)
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def log_scan(owner_id: str, target: str, verdict: str, score: int, method: str, analysis: list, details: list | None = None) -> None:
    # Keep dashboard history useful but bounded; never store unbounded engine output.
    safe_analysis = [str(item)[:1000] for item in analysis[:50]] if isinstance(analysis, list) else []
    safe_details = []
    for section in (details or [])[:8]:
        if not isinstance(section, dict):
            continue
        items = []
        for item in section.get("items", [])[:12]:
            if isinstance(item, dict):
                items.append({"label": str(item.get("label", "Field"))[:80], "value": str(item.get("value", ""))[:240]})
        if items:
            safe_details.append({"title": str(section.get("title", "Details"))[:80], "items": items})
    # Older logs contain a plain list. New URL scans use an object so the
    # dashboard can show both short indicators and full structured evidence.
    stored_analysis = {"indicators": safe_analysis, "details": safe_details} if safe_details else safe_analysis
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO scan_logs (api_key, url, verdict, score, method, analysis_json) VALUES (?, ?, ?, ?, ?, ?)",
        (owner_id, str(target)[:2048], str(verdict)[:80], max(0, min(int(score), 100)), method[:80], json.dumps(stored_analysis)),
    )
    conn.commit()
    conn.close()


class UrlRequest(BaseModel):
    # Pydantic rejects empty or oversized URL payloads before scanner work starts.
    url: str = Field(min_length=1, max_length=MAX_URL_LENGTH)


class ShadowRequest(BaseModel):
    # Limit both text size and supported lookup type at the API boundary.
    query: str = Field(min_length=1, max_length=MAX_SHADOW_QUERY_LENGTH)
    type: str = Field(pattern="^(password|upi|email|phone)$")


class ScanFeedback(BaseModel):
    # Feedback is intentionally limited to two review labels and a short comment.
    target: str = Field(min_length=1, max_length=MAX_URL_LENGTH)
    feedback_type: str = Field(pattern="^(false_positive|reported_scam)$")
    comment: str = Field(default="", max_length=500)


@app.get("/health")
async def health():
    # Lightweight endpoint for local deployment and uptime checks.
    return {"status": "ok"}


@app.post("/scan")
async def scan_url_endpoint(
    req: UrlRequest,
    x_api_key: str = Header("GUEST_SESSION"),
    x_scan_mode: str = Header("manual"),
):
    # 1. Identify the caller. API-wide rate limiting still protects the service.
    user = verify_and_sync_user(x_api_key)
    is_extension_background_scan = x_scan_mode.strip().lower() == "extension-background"
    # 2. Run the URL engine with a hard timeout so a slow remote website does
    # not keep a request open indefinitely.
    try:
        result = await run_engine(scan_website_logic, req.url, timeout=15)
    except TimeoutError:
        raise HTTPException(status_code=504, detail="URL scan timed out safely.")
    # 3. Store a bounded audit record for the user's dashboard.
    # Keep scan-history labels short and clear for people using the dashboard.
    method = "Browser scan" if is_extension_background_scan else "Website scan"
    log_scan(user["api_key"], req.url, result["status"], result["risk_score"], method, result.get("ai_analysis", []), result.get("details"))
    return result


@app.post("/scan-feedback")
async def submit_scan_feedback(feedback: ScanFeedback, x_api_key: str = Header("GUEST_SESSION")):
    """Store user corrections for analyst review and future model evaluation."""
    user = verify_and_sync_user(x_api_key)
    # Feedback is stored for later review. It is not used as automatic model
    # training data until it has been checked for spam and correct labels.
    target = feedback.target.strip()
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO scan_feedback (api_key, target, feedback_type, comment) VALUES (?, ?, ?, ?)",
            (user["api_key"], target, feedback.feedback_type, feedback.comment.strip()),
        )
        conn.commit()
    finally:
        conn.close()
    return {"message": "Thank you. Your report has been recorded for review."}


APK_EXTENSIONS = {".apk"}
# Upload allowlists are checked together with file signatures below. A filename
# or browser-provided content type alone is not trusted.
APK_TYPES = {"application/vnd.android.package-archive", "application/zip", "application/octet-stream"}
FORENSIC_EXTENSIONS = {".jpg", ".jpeg", ".png", ".pdf", ".mp3", ".wav", ".ogg", ".m4a"}
FORENSIC_TYPES = {
    "image/jpeg", "image/png", "application/pdf", "audio/mpeg", "audio/wav", "audio/x-wav",
    "audio/ogg", "audio/mp4", "application/octet-stream",
}


@app.post("/scan-apk")
async def scan_apk_endpoint(file: UploadFile = File(...), x_api_key: str = Header("GUEST_SESSION")):
    # Validate size/type before reading the archive.
    data = await validate_upload(file, max_bytes=MAX_APK_BYTES, allowed_extensions=APK_EXTENSIONS, allowed_content_types=APK_TYPES)
    if not data.startswith(b"PK\x03\x04"):
        raise HTTPException(status_code=415, detail="File is not a valid APK/ZIP container.")
    user = verify_and_sync_user(x_api_key)
    try:
        result = await run_engine(analyze_apk, file, timeout=20)
    except TimeoutError:
        raise HTTPException(status_code=504, detail="APK scan timed out safely.")
    log_scan(
        user["api_key"], Path(file.filename or "upload.apk").name,
        result["verdict"], result["risk_score"], "APK scan",
        result.get("triggers", []), result.get("details"),
    )
    return result


@app.post("/satark-scan")
async def satark_scan(file: UploadFile = File(...), scan_type: str = Form(...), x_api_key: str = Header("GUEST_SESSION")):
    # Match the selected scan mode with the actual file header. This prevents a
    # renamed executable from being accepted as an image, PDF or audio file.
    if scan_type not in {"image", "audio", "qr", "pdf"}:
        raise HTTPException(status_code=422, detail="Invalid forensic scan type.")
    data = await validate_upload(file, max_bytes=MAX_FORENSIC_BYTES, allowed_extensions=FORENSIC_EXTENSIONS, allowed_content_types=FORENSIC_TYPES)
    suffix = Path(file.filename or "").suffix.lower()
    is_image = data.startswith((b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n"))
    is_pdf = data.startswith(b"%PDF-")
    is_audio = data.startswith((b"ID3", b"RIFF", b"OggS", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2")) or suffix == ".m4a"
    expected = is_image if scan_type in {"image", "qr"} else is_audio if scan_type == "audio" else is_pdf
    if not expected:
        raise HTTPException(status_code=415, detail="File signature does not match the selected scan type.")
    user = verify_and_sync_user(x_api_key)
    try:
        result = await run_engine(analyze_forensics, file, scan_type, timeout=20)
    except TimeoutError:
        raise HTTPException(status_code=504, detail="Forensic scan timed out safely.")
    log_scan(user["api_key"], Path(file.filename or "upload").name, result["verdict"], result["risk_score"], f"File scan ({scan_type.upper()})", result.get("triggers", []))
    return result


@app.post("/shadow-scout")
async def shadow_scout_endpoint(req: ShadowRequest, x_api_key: str = Header("GUEST_SESSION")):
    # Shadow Scout receives only the validated query type and returns a masked
    # target in saved history to reduce exposure of sensitive input.
    user = verify_and_sync_user(x_api_key)
    try:
        result = await run_engine(analyze_shadow_query, req.query, req.type, timeout=10)
    except TimeoutError:
        raise HTTPException(status_code=504, detail="Intelligence lookup timed out safely.")
    log_scan(user["api_key"], f"[{req.type.upper()}] {result.get('masked_target', '***')}", result["status"], result.get("risk_score", 0), "Privacy check", result.get("logs", []))
    return result


@app.get("/user-status")
async def get_user_status(x_api_key: str = Header("GUEST_SESSION")):
    # Keep a lightweight compatibility endpoint for installed local clients.
    verify_and_sync_user(x_api_key)
    return {"service_status": "active"}


@app.get("/dashboard-data")
async def get_dashboard_data(x_api_key: str = Header("GUEST_SESSION")):
    # The dashboard is the URL-protection history, not a mixed list of every
    # upload/privacy tool. Satark, APK Kavach and Privacy Check keep their own
    # results on their feature pages so this view stays simple and useful.
    # "Titan Web Scanner" is included only for older URL entries created before
    # the labels were simplified to Website scan / Browser scan.
    user = verify_and_sync_user(x_api_key)
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT * FROM scan_logs WHERE api_key=? AND method IN (?, ?, ?) ORDER BY timestamp DESC LIMIT 100",
        (user["api_key"], "Website scan", "Browser scan", "Titan Web Scanner"),
    ).fetchall()
    conn.close()
    logs = []
    safe_count = 0
    for row in rows:
        item = dict(row)
        is_safe = item["verdict"] in {"SAFE", "CLEAN", "AUTHENTIC", "NO STRONG WARNING"}
        safe_count += int(is_safe)
        try:
            stored_analysis = json.loads(item["analysis_json"])
        except (TypeError, json.JSONDecodeError):
            stored_analysis = []
        if isinstance(stored_analysis, dict):
            analysis = stored_analysis.get("indicators", [])
            details = stored_analysis.get("details", [])
        else:
            analysis, details = stored_analysis if isinstance(stored_analysis, list) else [], []
        logs.append({"id": item["id"], "url": item["url"], "verdict": item["verdict"], "score": item["score"], "method": item["method"], "time": item["timestamp"], "analysis": analysis, "details": details})
    return {"stats": {"safe": safe_count, "phishing": len(logs) - safe_count, "total": len(logs)}, "logs": logs}


@app.delete("/clear-history")
async def clear_history(x_api_key: str = Header("GUEST_SESSION")):
    # Delete only this user's scan history and feedback.
    user = verify_and_sync_user(x_api_key)
    conn = get_db_connection()
    conn.execute("DELETE FROM scan_logs WHERE api_key=?", (user["api_key"],))
    conn.execute("DELETE FROM scan_feedback WHERE api_key=?", (user["api_key"],))
    conn.commit()
    conn.close()
    return {"message": "Logs purged successfully."}
