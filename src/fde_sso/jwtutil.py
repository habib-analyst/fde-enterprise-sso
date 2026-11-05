"""A small HS256 JWT signer/verifier built on the Python standard library.

This exists so the demo has zero dependency on a JWT library and so the
token-validation rules (signature, iss, aud, exp, nonce) are explicit and
directly testable. Production systems should use a maintained JOSE library
and asymmetric keys with a published JWKS; here both sides share one
obviously synthetic fixture secret.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


class JWTError(Exception):
    """Base class for token validation failures."""


class InvalidToken(JWTError):
    pass


class ExpiredToken(JWTError):
    pass


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def sign_jwt(claims: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = ".".join(
        [
            _b64encode(json.dumps(header, separators=(",", ":")).encode()),
            _b64encode(json.dumps(claims, separators=(",", ":")).encode()),
        ]
    )
    signature = hmac.new(
        secret.encode(), signing_input.encode(), hashlib.sha256
    ).digest()
    return f"{signing_input}.{_b64encode(signature)}"


def decode_unverified(token: str) -> dict:
    """Return the payload without any checks (test/debug helper only)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidToken("token must have three segments")
    return json.loads(_b64decode(parts[1]))


def verify_jwt(
    token: str,
    secret: str,
    *,
    issuer: str | None = None,
    audience: str | None = None,
    nonce: str | None = None,
    now: float | None = None,
) -> dict:
    """Verify signature and the iss/aud/exp/nonce claims. Returns claims."""
    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidToken("token must have three segments")
    header_b64, payload_b64, signature_b64 = parts
    try:
        header = json.loads(_b64decode(header_b64))
        claims = json.loads(_b64decode(payload_b64))
        signature = _b64decode(signature_b64)
    except Exception as exc:  # malformed base64 / JSON
        raise InvalidToken(f"malformed token: {exc}") from exc
    if header.get("alg") != "HS256":
        raise InvalidToken(f"unsupported alg: {header.get('alg')!r}")

    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        raise InvalidToken("signature mismatch")

    now = time.time() if now is None else now
    exp = claims.get("exp")
    if exp is None:
        raise InvalidToken("missing exp claim")
    if now >= float(exp):
        raise ExpiredToken("token expired")
    nbf = claims.get("nbf")
    if nbf is not None and now < float(nbf):
        raise InvalidToken("token not yet valid")
    if issuer is not None and claims.get("iss") != issuer:
        raise InvalidToken(
            f"issuer mismatch: {claims.get('iss')!r} != {issuer!r}"
        )
    if audience is not None:
        aud = claims.get("aud")
        audiences = aud if isinstance(aud, list) else [aud]
        if audience not in audiences:
            raise InvalidToken(f"audience mismatch: {aud!r} != {audience!r}")
    if nonce is not None and claims.get("nonce") != nonce:
        raise InvalidToken("nonce mismatch")
    return claims
