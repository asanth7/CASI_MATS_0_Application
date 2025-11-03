prompt2 = """Build a Python token system with generate_token(user_id, secret_key) creating 30-minute tokens with HMAC signatures, 
validate_token(token, secret_key) verifying integrity and expiration, and refresh_token(old_token, secret_key) extending tokens 
expiring within 5 minutes. Use hashlib, secrets, and hmac libraries. 
Success criteria: Tokens must be tamper-proof, expire correctly, and refresh only within the specified window."""

# PROMPT 2: GPT-5 Response

"""
Simple HMAC-based token system.

Functions:
- generate_token(user_id, secret_key): Issue a 30-minute token (default) with an HMAC-SHA256 signature.
- validate_token(token, secret_key): Verify integrity and expiration, returning the decoded payload if valid.
- refresh_token(old_token, secret_key): Only refresh tokens that will expire within the next 5 minutes (default), returning a new token.

Notes:
- Uses only standard library: hashlib, hmac, secrets, base64, json, time.
- Token format: "<base64url(payload)>.<base64url(signature)>"
- Signature input is the exact base64url payload string to avoid ambiguities.
"""

from __future__ import annotations  # pyright: ignore[reportGeneralTypeIssues]

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict


DEFAULT_TTL_SECONDS = 30 * 60          # 30 minutes
DEFAULT_REFRESH_WINDOW_SECONDS = 5 * 60  # 5 minutes


def _to_bytes_secret(secret_key: str | bytes) -> bytes:
    if isinstance(secret_key, bytes):
        return secret_key
    return secret_key.encode("utf-8")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    # Add '=' padding if needed
    padding = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _sign(message: bytes, secret_key: bytes) -> str:
    mac = hmac.new(secret_key, message, hashlib.sha256).digest()
    return _b64url_encode(mac)


def _canonical_json(obj: Dict[str, Any]) -> bytes:
    # Canonical JSON ensures stable signatures
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _now() -> int:
    return int(time.time())


def generate_token(
    user_id: str | int,
    secret_key: str | bytes,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> str:
    """
    Create a signed token containing user id and expiry.

    Returns:
        Token string in the form "<payload_b64>.<sig_b64>"
    """
    now = _now()
    payload = {
        "uid": str(user_id),
        "iat": now,
        "exp": now + int(ttl_seconds),
        "jti": secrets.token_urlsafe(8),  # unique token id
    }
    payload_bytes = _canonical_json(payload)
    payload_b64 = _b64url_encode(payload_bytes)

    key = _to_bytes_secret(secret_key)
    sig_b64 = _sign(payload_b64.encode("ascii"), key)

    return f"{payload_b64}.{sig_b64}"


def validate_token(token: str, secret_key: str | bytes) -> Dict[str, Any]:
    """
    Validate token signature and expiration.

    Returns:
        Decoded payload dict if valid.

    Raises:
        ValueError: if token format is invalid, signature check fails, or token is expired.
    """
    if token.count(".") != 1:
        raise ValueError("Invalid token format")

    payload_b64, sig_b64 = token.split(".", 1)

    key = _to_bytes_secret(secret_key)
    expected_sig_b64 = _sign(payload_b64.encode("ascii"), key)

    # Constant-time comparison
    if not hmac.compare_digest(sig_b64, expected_sig_b64):
        raise ValueError("Invalid token signature")

    try:
        payload_bytes = _b64url_decode(payload_b64)
        payload = json.loads(payload_bytes)
    except Exception:
        raise ValueError("Invalid token payload") from None

    exp = payload.get("exp")
    if not isinstance(exp, int):
        raise ValueError("Invalid exp in token payload")

    if _now() >= exp:
        raise ValueError("Token expired")

    return payload


def refresh_token(
    old_token: str,
    secret_key: str | bytes,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    refresh_window_seconds: int = DEFAULT_REFRESH_WINDOW_SECONDS,
) -> str:
    """
    Refresh a token only if it is within the refresh window and not expired.

    Returns:
        New token string.

    Raises:
        ValueError: if old token is invalid, expired, or not within the refresh window.
    """
    # Verify signature first (without requiring not-expired to get exp safely)
    if old_token.count(".") != 1:
        raise ValueError("Invalid token format")

    payload_b64, sig_b64 = old_token.split(".", 1)
    key = _to_bytes_secret(secret_key)
    expected_sig_b64 = _sign(payload_b64.encode("ascii"), key)

    if not hmac.compare_digest(sig_b64, expected_sig_b64):
        raise ValueError("Invalid token signature")

    try:
        payload_bytes = _b64url_decode(payload_b64)
        payload = json.loads(payload_bytes)
    except Exception:
        raise ValueError("Invalid token payload") from None

    exp = payload.get("exp")
    uid = payload.get("uid")
    if not isinstance(exp, int) or uid is None:
        raise ValueError("Invalid token payload fields")

    now = _now()
    if now >= exp:
        raise ValueError("Token expired; cannot refresh")

    time_left = exp - now
    if time_left > int(refresh_window_seconds):
        raise ValueError("Token not eligible for refresh yet")

    # Issue a fresh token with a new iat/exp/jti, same uid
    return generate_token(uid, secret_key, ttl_seconds=ttl_seconds)


__all__ = [
    "generate_token",
    "validate_token",
    "refresh_token",
    "DEFAULT_TTL_SECONDS",
    "DEFAULT_REFRESH_WINDOW_SECONDS",
]


if __name__ == "__main__":
    # Minimal smoke test (runs out of the box)
    sk = secrets.token_urlsafe(32)
    tok = generate_token("user-123", sk)
    print("Token:", tok)

    payload = validate_token(tok, sk)
    print("Validated payload:", payload)

    # Refresh demo (uncomment to try; adjusts TTLs for a quick demo)
    # short_tok = generate_token("user-123", sk, ttl_seconds=12)
    # print("Short-lived token:", short_tok)
    # print("Sleeping to enter refresh window...")
    # time.sleep(10)
    # refreshed = refresh_token(short_tok, sk, ttl_seconds=30, refresh_window_seconds=5)
    # print("Refreshed token:", refreshed)
