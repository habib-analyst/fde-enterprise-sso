import time
import urllib.parse

import pytest

from conftest import full_login, run_authorize
from fde_sso.config import (
    CLIENT_ID,
    CLIENT_SECRET,
    IDP_ISSUER,
    IDP_SIGNING_SECRET,
    REDIRECT_URI,
    TENANT_ACME,
    IdpConfig,
)
from fde_sso.jwtutil import decode_unverified, sign_jwt
from fde_sso.oidc import OidcClient, create_idp_app, s256_challenge
from fde_sso.app import create_service_app
from fastapi.testclient import TestClient


# --- Happy path ---------------------------------------------------------------


def test_full_oidc_pkce_happy_path(service, idp):
    response = full_login(service, idp, TENANT_ACME, "ada@acme.example")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["role"] == "owner"
    assert body["tenant_id"] == TENANT_ACME
    # The issued session actually works against the RBAC layer.
    headers = {"Authorization": f"Bearer {body['session_token']}"}
    settings = service.get(f"/tenants/{TENANT_ACME}/settings", headers=headers)
    assert settings.status_code == 200


def test_discovery_document(idp):
    doc = idp.get("/.well-known/openid-configuration").json()
    assert doc["issuer"] == IDP_ISSUER
    assert doc["code_challenge_methods_supported"] == ["S256"]
    assert doc["response_types_supported"] == ["code"]


def test_userinfo_with_access_token(service, idp, store):
    # Run a raw flow to capture the access token from the token endpoint.
    start = service.get("/auth/login", params={"tenant_id": TENANT_ACME}).json()
    callback = run_authorize(idp, start["authorization_url"], "alan@acme.example")
    client = service.app.state.oidc_client
    pending = client._pending[callback["state"]]
    token_response = idp.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": callback["code"],
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code_verifier": pending["verifier"],
        },
    )
    assert token_response.status_code == 200
    access_token = token_response.json()["access_token"]
    info = idp.get("/userinfo", headers={"Authorization": f"Bearer {access_token}"})
    assert info.status_code == 200
    assert info.json()["email"] == "alan@acme.example"


def test_userinfo_rejects_garbage_token(idp):
    response = idp.get("/userinfo", headers={"Authorization": "Bearer not-a-token"})
    assert response.status_code == 401


# --- PKCE failure modes ---------------------------------------------------------


def _authorize_params(**overrides):
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "state": "state-1",
        "nonce": "nonce-1",
        "code_challenge": s256_challenge("v" * 50),
        "code_challenge_method": "S256",
        "fixture_user": "ada@acme.example",
    }
    params.update(overrides)
    return params


def test_pkce_plain_method_rejected(idp):
    response = idp.get(
        "/authorize",
        params=_authorize_params(code_challenge_method="plain"),
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "S256" in response.json()["error_description"]


def test_pkce_missing_challenge_rejected(idp):
    params = _authorize_params()
    del params["code_challenge"]
    response = idp.get("/authorize", params=params, follow_redirects=False)
    assert response.status_code == 400


def test_pkce_wrong_verifier_rejected_at_token(idp):
    response = idp.get(
        "/authorize", params=_authorize_params(), follow_redirects=False
    )
    assert response.status_code == 302
    code = urllib.parse.parse_qs(
        urllib.parse.urlparse(response.headers["location"]).query
    )["code"][0]
    token_response = idp.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code_verifier": "w" * 50,  # well-formed but wrong
        },
    )
    assert token_response.status_code == 400
    assert token_response.json()["error"] == "invalid_grant"


def test_pkce_missing_verifier_rejected_at_token(idp):
    response = idp.get(
        "/authorize", params=_authorize_params(), follow_redirects=False
    )
    code = urllib.parse.parse_qs(
        urllib.parse.urlparse(response.headers["location"]).query
    )["code"][0]
    token_response = idp.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
    )
    assert token_response.status_code == 400


# --- Code lifecycle ---------------------------------------------------------------


def test_replayed_code_rejected(service, idp):
    start = service.get("/auth/login", params={"tenant_id": TENANT_ACME}).json()
    callback = run_authorize(idp, start["authorization_url"], "ada@acme.example")
    client = service.app.state.oidc_client
    pending = client._pending[callback["state"]]
    form = {
        "grant_type": "authorization_code",
        "code": callback["code"],
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code_verifier": pending["verifier"],
    }
    first = idp.post("/token", data=form)
    assert first.status_code == 200
    second = idp.post("/token", data=form)
    assert second.status_code == 400
    assert "already used" in second.json()["error_description"]


def test_expired_code_rejected(store):
    short_lived = TestClient(create_idp_app(store, IdpConfig(code_ttl_seconds=-10)))
    response = short_lived.get(
        "/authorize", params=_authorize_params(), follow_redirects=False
    )
    assert response.status_code == 302
    code = urllib.parse.parse_qs(
        urllib.parse.urlparse(response.headers["location"]).query
    )["code"][0]
    token_response = short_lived.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code_verifier": "v" * 50,
        },
    )
    assert token_response.status_code == 400
    assert "expired" in token_response.json()["error_description"]


def test_wrong_client_secret_rejected(idp):
    response = idp.get(
        "/authorize", params=_authorize_params(), follow_redirects=False
    )
    code = urllib.parse.parse_qs(
        urllib.parse.urlparse(response.headers["location"]).query
    )["code"][0]
    token_response = idp.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": "fixture-wrong-secret",
            "code_verifier": "v" * 50,
        },
    )
    assert token_response.status_code == 401


def test_unregistered_redirect_uri_rejected(idp):
    response = idp.get(
        "/authorize",
        params=_authorize_params(redirect_uri="https://evil.fixture.example/cb"),
        follow_redirects=False,
    )
    assert response.status_code == 400


def test_callback_state_mismatch_rejected(service):
    response = service.get(
        "/auth/callback", params={"code": "whatever", "state": "no-such-state"}
    )
    assert response.status_code == 400
    assert "state" in response.json()["detail"]


# --- ID token validation at the client --------------------------------------------


def _client_with_tampering_token_post(store, idp, tamper):
    def token_post(form):
        response = idp.post("/token", data=form)
        body = response.json()
        if response.status_code == 200:
            claims = decode_unverified(body["id_token"])
            tamper(claims)
            body = dict(body, id_token=sign_jwt(claims, IDP_SIGNING_SECRET))
        return response.status_code, body

    from fde_sso.config import ServiceConfig

    return OidcClient(store, ServiceConfig(), token_post)


def _begin_and_authorize(client, idp, fixture_user="ada@acme.example"):
    start = client.begin_login(TENANT_ACME)
    params = {
        k: v[0]
        for k, v in urllib.parse.parse_qs(
            urllib.parse.urlparse(start["authorization_url"]).query
        ).items()
    }
    params["fixture_user"] = fixture_user
    response = idp.get("/authorize", params=params, follow_redirects=False)
    assert response.status_code == 302
    return {
        k: v[0]
        for k, v in urllib.parse.parse_qs(
            urllib.parse.urlparse(response.headers["location"]).query
        ).items()
    }


def test_wrong_audience_id_token_rejected(store, idp):
    client = _client_with_tampering_token_post(
        store, idp, lambda c: c.update(aud="some-other-client")
    )
    callback = _begin_and_authorize(client, idp)
    with pytest.raises(Exception) as excinfo:
        client.handle_callback(callback["code"], callback["state"])
    assert excinfo.value.status == 401


def test_expired_id_token_rejected(store, idp):
    client = _client_with_tampering_token_post(
        store, idp, lambda c: c.update(exp=int(time.time()) - 60)
    )
    callback = _begin_and_authorize(client, idp)
    with pytest.raises(Exception) as excinfo:
        client.handle_callback(callback["code"], callback["state"])
    assert excinfo.value.status == 401


def test_wrong_nonce_id_token_rejected(store, idp):
    client = _client_with_tampering_token_post(
        store, idp, lambda c: c.update(nonce="attacker-nonce")
    )
    callback = _begin_and_authorize(client, idp)
    with pytest.raises(Exception) as excinfo:
        client.handle_callback(callback["code"], callback["state"])
    assert excinfo.value.status == 401


def test_wrong_issuer_id_token_rejected(store, idp):
    client = _client_with_tampering_token_post(
        store, idp, lambda c: c.update(iss="https://evil.fixture.example")
    )
    callback = _begin_and_authorize(client, idp)
    with pytest.raises(Exception) as excinfo:
        client.handle_callback(callback["code"], callback["state"])
    assert excinfo.value.status == 401


def test_login_for_other_tenants_user_rejected(service, idp):
    # Gina's home tenant is Globex; starting a login for Acme must fail.
    response = full_login(service, idp, TENANT_ACME, "gina@globex.example")
    assert response.status_code == 403
