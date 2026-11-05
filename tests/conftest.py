import time
import urllib.parse

import pytest
from fastapi.testclient import TestClient

from fde_sso.app import create_service_app
from fde_sso.config import (
    SERVICE_AUDIENCE,
    SERVICE_ISSUER,
    SERVICE_SIGNING_SECRET,
    TENANT_ACME,
)
from fde_sso.fixtures import seed_store
from fde_sso.jwtutil import sign_jwt
from fde_sso.oidc import create_idp_app
from fde_sso.store import Store

SCIM_ACME = {"Authorization": "Bearer fixture-scim-token-acme"}
SCIM_GLOBEX = {"Authorization": "Bearer fixture-scim-token-globex"}


@pytest.fixture()
def store():
    s = seed_store(Store())  # fresh in-memory DB per test
    yield s
    s.close()


@pytest.fixture()
def idp(store):
    return TestClient(create_idp_app(store))


@pytest.fixture()
def service(store, idp):
    def token_post(form):
        response = idp.post("/token", data=form)
        return response.status_code, response.json()

    return TestClient(create_service_app(store, token_post=token_post))


def _flatten(parsed_qs):
    return {k: v[0] for k, v in parsed_qs.items()}


def run_authorize(idp: TestClient, authorization_url: str, fixture_user: str):
    """Drive the fixture IdP authorize step; return the callback params."""
    params = _flatten(urllib.parse.parse_qs(urllib.parse.urlparse(authorization_url).query))
    params["fixture_user"] = fixture_user
    response = idp.get("/authorize", params=params, follow_redirects=False)
    assert response.status_code == 302, response.text
    location = response.headers["location"]
    return _flatten(urllib.parse.parse_qs(urllib.parse.urlparse(location).query))


def full_login(service: TestClient, idp: TestClient, tenant_id: str, fixture_user: str):
    """Complete OIDC login flow; return the service callback response."""
    start = service.get("/auth/login", params={"tenant_id": tenant_id})
    assert start.status_code == 200, start.text
    callback_params = run_authorize(idp, start.json()["authorization_url"], fixture_user)
    return service.get("/auth/callback", params=callback_params)


def mint_session(user_id: str, tenant_id: str, email: str = "") -> dict:
    """Mint a service session token directly (fixture session shortcut)."""
    now = time.time()
    token = sign_jwt(
        {
            "iss": SERVICE_ISSUER,
            "aud": SERVICE_AUDIENCE,
            "sub": user_id,
            "email": email,
            "tenant_id": tenant_id,
            "iat": int(now),
            "exp": int(now + 3600),
        },
        SERVICE_SIGNING_SECRET,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def acme_owner_headers():
    return mint_session("user-ada", TENANT_ACME, "ada@acme.example")
