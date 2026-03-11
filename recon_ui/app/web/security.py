from __future__ import annotations

"""HTTP middleware and browser security header policy."""

import base64
import binascii
import hashlib
import hmac
import secrets
import time
from urllib.parse import parse_qs, urlsplit

from fastapi import HTTPException, Request

from ..config import (
    ALLOWED_HOSTS,
    APP_AUTH_PASSWORD,
    APP_MAX_REQUEST_BYTES,
    APP_AUTH_USERNAME,
    APP_REQUIRE_AUTH,
)

SAFE_HTTP_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
CSRF_TOKEN_TTL_SECONDS = 60 * 60 * 4
_CSRF_SIGNING_KEY = (APP_AUTH_PASSWORD.encode("utf-8") if APP_AUTH_PASSWORD else secrets.token_bytes(32))


def _normalize_host(host_header: str) -> str:
    """Normalize Host header into lower-case hostname without port."""
    host = host_header.strip().lower()
    if not host:
        return ""
    if host.startswith("["):
        # IPv6 literal form: [::1]:8000
        closing = host.find("]")
        if closing == -1:
            return ""
        return host[1:closing]
    return host.split(":", 1)[0]


def _is_allowed_host(host: str) -> bool:
    """Check host against configured allow-list to reduce host-header abuse."""
    return bool(host) and ("*" in ALLOWED_HOSTS or host in ALLOWED_HOSTS)


def _parse_basic_auth(auth_header: str) -> tuple[str, str] | None:
    """Parse HTTP Basic auth header into username/password tuple."""
    if not auth_header.startswith("Basic "):
        return None
    token = auth_header[6:].strip()
    if not token:
        return None
    try:
        decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError):
        return None
    if ":" not in decoded:
        return None
    username, password = decoded.split(":", 1)
    return username, password


def _is_same_origin(url: str, expected_host_header: str) -> bool:
    """Validate same-origin for CSRF origin/referer checks."""
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        return False
    return bool(parts.netloc) and parts.netloc.lower() == expected_host_header


async def _extract_submitted_csrf_token(request: Request) -> str:
    """Extract CSRF token from header first, then from form fields."""
    header_token = request.headers.get("x-csrf-token", "").strip()
    if header_token:
        return header_token

    content_type = request.headers.get("content-type", "").lower()
    if content_type.startswith("application/x-www-form-urlencoded"):
        # Read raw body bytes to avoid consuming multipart/form parser state used by endpoint dependencies.
        raw = (await request.body()).decode("utf-8", errors="replace")
        parsed = parse_qs(raw, keep_blank_values=True)
        values = parsed.get("csrf_token", [])
        if values:
            return str(values[0]).strip()
    return ""


def _generate_csrf_token(host: str) -> str:
    """Generate stateless signed CSRF token bound to request host."""
    now = str(int(time.time()))
    nonce = secrets.token_urlsafe(18)
    payload = f"{now}|{host}|{nonce}"
    sig = hmac.new(_CSRF_SIGNING_KEY, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}|{sig}"


def _validate_csrf_token(token: str, host: str) -> bool:
    """Validate signed CSRF token integrity, host binding, and freshness."""
    parts = token.split("|")
    if len(parts) != 4:
        return False
    issued_at_raw, bound_host, nonce, provided_sig = parts
    _ = nonce
    if bound_host != host:
        return False
    try:
        issued_at = int(issued_at_raw)
    except ValueError:
        return False
    age = int(time.time()) - issued_at
    if age < 0 or age > CSRF_TOKEN_TTL_SECONDS:
        return False
    payload = f"{issued_at_raw}|{bound_host}|{nonce}"
    expected_sig = hmac.new(_CSRF_SIGNING_KEY, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(provided_sig, expected_sig)


async def apply_security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
    """Set baseline browser hardening headers for every HTTP response."""
    is_static_asset = request.url.path.startswith("/static/")
    host_header = request.headers.get("host", "").strip().lower()
    normalized_host = _normalize_host(host_header)
    if not _is_allowed_host(normalized_host):
        raise HTTPException(status_code=400, detail="Invalid host header")

    content_length = request.headers.get("content-length", "").strip()
    if content_length:
        try:
            declared_length = int(content_length)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header") from exc
        # Reject oversized request bodies before they reach form/JSON parsers.
        if declared_length < 0 or declared_length > APP_MAX_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="Request body too large")

    if APP_REQUIRE_AUTH:
        parsed = _parse_basic_auth(request.headers.get("authorization", "").strip())
        if not parsed:
            raise HTTPException(
                status_code=401,
                detail="Authentication required",
                headers={"WWW-Authenticate": 'Basic realm="GhostReconRev", charset="UTF-8"'},
            )
        username, password = parsed
        # Constant-time comparisons reduce credential oracle side channels.
        if not (
            hmac.compare_digest(username, APP_AUTH_USERNAME) and hmac.compare_digest(password, APP_AUTH_PASSWORD)
        ):
            raise HTTPException(
                status_code=401,
                detail="Authentication required",
                headers={"WWW-Authenticate": 'Basic realm="GhostReconRev", charset="UTF-8"'},
            )

    request.state.csrf_token = _generate_csrf_token(normalized_host)

    if request.method not in SAFE_HTTP_METHODS:
        origin = request.headers.get("origin", "").strip()
        referer = request.headers.get("referer", "").strip()

        if origin and not _is_same_origin(origin, host_header):
            raise HTTPException(status_code=403, detail="Cross-site request blocked")
        if not origin and referer and not _is_same_origin(referer, host_header):
            raise HTTPException(status_code=403, detail="Cross-site request blocked")

        submitted_csrf = await _extract_submitted_csrf_token(request)
        if not submitted_csrf or not _validate_csrf_token(submitted_csrf, normalized_host):
            raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")

    response = await call_next(request)
    # Inline scripts are currently used in templates, so CSP keeps 'unsafe-inline' for scripts.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["Cache-Control"] = "public, max-age=604800, immutable" if is_static_asset else "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), microphone=()"
    response.headers["Cross-Origin-Resource-Policy"] = "cross-origin" if request.url.path == "/favicon.ico" else "same-origin"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response
