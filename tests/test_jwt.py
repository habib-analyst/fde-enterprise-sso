import time

import pytest

from fde_sso.jwtutil import ExpiredToken, InvalidToken, sign_jwt, verify_jwt

SECRET = "fixture-test-secret"


def _claims(**overrides):
    now = time.time()
    claims = {"iss": "issuer-x", "aud": "aud-y", "sub": "user-1",
              "iat": int(now), "exp": int(now + 600), "nonce": "n-1"}
    claims.update(overrides)
    return claims


def test_roundtrip():
    token = sign_jwt(_claims(), SECRET)
    out = verify_jwt(token, SECRET, issuer="issuer-x", audience="aud-y", nonce="n-1")
    assert out["sub"] == "user-1"


def test_wrong_secret_rejected():
    token = sign_jwt(_claims(), SECRET)
    with pytest.raises(InvalidToken):
        verify_jwt(token, "fixture-other-secret")


def test_expired_rejected():
    token = sign_jwt(_claims(exp=int(time.time()) - 10), SECRET)
    with pytest.raises(ExpiredToken):
        verify_jwt(token, SECRET)


def test_wrong_issuer_rejected():
    token = sign_jwt(_claims(), SECRET)
    with pytest.raises(InvalidToken):
        verify_jwt(token, SECRET, issuer="someone-else")


def test_wrong_audience_rejected():
    token = sign_jwt(_claims(), SECRET)
    with pytest.raises(InvalidToken):
        verify_jwt(token, SECRET, audience="other-aud")


def test_nonce_mismatch_rejected():
    token = sign_jwt(_claims(), SECRET)
    with pytest.raises(InvalidToken):
        verify_jwt(token, SECRET, nonce="different")


def test_tampered_payload_rejected():
    token = sign_jwt(_claims(), SECRET)
    head, _payload, sig = token.split(".")
    import base64, json

    forged = base64.urlsafe_b64encode(
        json.dumps(_claims(sub="attacker")).encode()
    ).rstrip(b"=").decode()
    with pytest.raises(InvalidToken):
        verify_jwt(f"{head}.{forged}.{sig}", SECRET)
