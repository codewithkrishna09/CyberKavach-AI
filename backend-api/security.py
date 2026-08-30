"""Input, upload, and outbound-request security helpers."""

import ipaddress
import re
import socket
import time
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from fastapi import HTTPException, UploadFile


LOCAL_KEY_RE = re.compile(r"^CK-LOCAL-[A-F0-9]{16,64}$")
ALLOWED_SCHEMES = {"http", "https"}
REDIRECT_CODES = {301, 302, 303, 307, 308}


def normalize_api_key(value: str | None) -> str:
    key = (value or "").strip()
    if key in {"", "null", "FREE"}:
        return "GUEST_SESSION"
    if key == "GUEST_SESSION" or LOCAL_KEY_RE.fullmatch(key):
        return key
    raise HTTPException(status_code=401, detail="Invalid API key format.")


def validate_public_url(raw_url: str, max_length: int = 2048) -> str:
    # This is SSRF protection: reject local/private networks before any backend
    # worker is allowed to fetch a URL supplied by a user.
    url = raw_url.strip()
    if not url or len(url) > max_length:
        raise ValueError("URL is empty or exceeds the maximum length.")
    if "://" not in url:
        url = "https://" + url

    parsed = urlsplit(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("URL host is invalid or contains credentials.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL port is invalid.") from exc
    if port not in {None, 80, 443}:
        raise ValueError("Only standard web ports 80 and 443 are allowed.")

    host = parsed.hostname.rstrip(".").lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise ValueError("Local network targets are not allowed.")

    try:
        literal_ip = ipaddress.ip_address(host.split("%", 1)[0])
        addresses = {str(literal_ip)}
    except ValueError:
        try:
            addresses = {item[4][0].split("%", 1)[0] for item in socket.getaddrinfo(host, port or 443)}
        except socket.gaierror as exc:
            raise ValueError("Domain could not be resolved.") from exc
    if not addresses:
        raise ValueError("Domain did not resolve to an address.")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError("Private, loopback, link-local, and reserved targets are blocked.")

    safe_netloc = host if port is None else f"{host}:{port}"
    return urlunsplit((parsed.scheme.lower(), safe_netloc, parsed.path or "/", parsed.query, ""))


def safe_get(url: str, *, headers: dict[str, str], timeout: float, max_bytes: int, max_redirects: int = 3) -> tuple[requests.Response, bytes]:
    """Fetch a public URL while revalidating every redirect and limiting the body."""
    current = validate_public_url(url)
    session = requests.Session()
    session.trust_env = False
    try:
        for redirect_count in range(max_redirects + 1):
            # Redirect targets are validated again because a public URL can
            # redirect a server-side scanner toward an internal address.
            response = session.get(current, headers=headers, timeout=timeout, allow_redirects=False, stream=True)
            connection = getattr(response.raw, "_connection", None) or getattr(response.raw, "connection", None)
            sock = getattr(connection, "sock", None)
            if sock is None:
                response.close()
                raise ValueError("Unable to verify the remote peer address.")
            peer_ip = ipaddress.ip_address(sock.getpeername()[0].split("%", 1)[0])
            if not peer_ip.is_global:
                response.close()
                raise ValueError("Connection resolved to a blocked network address.")
            if response.status_code in REDIRECT_CODES:
                location = response.headers.get("location")
                response.close()
                if not location:
                    raise ValueError("Redirect response did not include a destination.")
                current = validate_public_url(urljoin(current, location))
                continue

            content_length = response.headers.get("content-length")
            if content_length and int(content_length) > max_bytes:
                response.close()
                raise ValueError("Remote response is too large to scan safely.")
            chunks = []
            total = 0
            for chunk in response.iter_content(64 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    response.close()
                    raise ValueError("Remote response exceeded the scan size limit.")
                chunks.append(chunk)
            # The scanner needs the redirect count for an explainable report.
            # Store it only on this in-memory response object, never in headers.
            response._cyberkavach_redirect_count = redirect_count
            return response, b"".join(chunks)
        raise ValueError("Too many redirects.")
    finally:
        session.close()


async def validate_upload(
    upload: UploadFile,
    *,
    max_bytes: int,
    allowed_extensions: set[str],
    allowed_content_types: set[str],
) -> bytes:
    filename = Path(upload.filename or "").name
    extension = Path(filename).suffix.lower()
    if not filename or extension not in allowed_extensions:
        raise HTTPException(status_code=415, detail="Unsupported file extension.")
    content_type = (upload.content_type or "application/octet-stream").lower()
    if content_type not in allowed_content_types:
        raise HTTPException(status_code=415, detail="Unsupported file content type.")
    data = await upload.read(max_bytes + 1)
    if not data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(data) > max_bytes:
        raise HTTPException(status_code=413, detail="Uploaded file exceeds the size limit.")
    await upload.seek(0)
    return data


class SlidingWindowRateLimiter:
    def __init__(self, limit: int, window_seconds: int = 60):
        self.limit = limit
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, identity: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            events = self._events[identity]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(now)
            return True
