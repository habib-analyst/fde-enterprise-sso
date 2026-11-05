"""OAuth2 / OIDC authorization-code flow with PKCE.

Two halves share this module:

- The **fixture IdP** (`authorize` / `token` core functions plus the
  FastAPI app from `create_idp_app`): an authorization endpoint and a
  token endpoint with strict rules — PKCE S256 only (plain or missing
  verifiers are rejected), authorization codes are single-use with a
  60-second expiry, `state` and `nonce` are required and echoed/checked.
- The **client** (`OidcClient`): builds the authorization URL with a
  fresh state/nonce/PKCE pair per login, handles the callback, exchanges
  the code, and fully validates the ID token (signature, `iss`, `aud`,
  `exp`, `nonce`) before a local session exists.

Fixture login: a real IdP would render a login form. This local demo
selects the fixture user with the `fixture_user` authorize parameter;
that substitution is the only difference from a real flow. The token
exchange is a callable (`token_post`) so the same client code runs
against the in-process core here or an HTTP POST in a real deployment.
"""

from __future__ import annotations

import hashlib
import secrets
import time
import urllib.parse

from fastapi import FastAPI, Form, Header, Request
from fastapi.responses import JSONResponse, RedirectResponse

from .config import IdpConfig, ServiceConfig
from .fixtures import IDP_USERS
from .jwtutil import JWTError, sign_jwt, verify_jwt
from .store import Store


class OidcError(Exception):
    def __init__(self, status: int, error: str, detail: str = ""):
        super().__init__(detail or error)
        self.status = status
        self.error = error
        self.detail = detail or error


class LoginError(Exception):
    """Raised by OidcClient when a login cannot be completed."""

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


# --- PKCE -------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def s256_challenge(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode()).digest())


def new_code_verifier() -> str:
    return secrets.token_urlsafe(48)  # 64 chars, within the 43-128 range


def _valid_verifier_shape(verifier: str) -> bool:
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    )
    return 43 <= len(verifier) <= 128 and all(c in allowed for c in verifier)


def verify_pkce(verifier: str, challenge: str) -> bool:
    if not _valid_verifier_shape(verifier):
        return False
    import hmac as _hmac

    return _hmac.compare_digest(s256_challenge(verifier), challenge)


# --- Fixture IdP core ---------------------------------------------------------


def authorize(store: Store, cfg: IdpConfig, params: dict, now: float | None = None):
    """Validate an authorization request; return the redirect Location."""
    now = time.time() if now is None else now
    if params.get("client_id") != cfg.client_id:
        raise OidcError(400, "invalid_client", "unknown client_id")
    redirect_uri = params.get("redirect_uri", "")
    if redirect_uri not in cfg.redirect_uris:
        raise OidcError(400, "invalid_request", "redirect_uri is not registered")
    if params.get("response_type") != "code":
        raise OidcError(400, "unsupported_response_type", "only response_type=code")
    if "openid" not in params.get("scope", "").split():
        raise OidcError(400, "invalid_scope", "scope must include openid")
    challenge = params.get("code_challenge")
    if not challenge:
        raise OidcError(400, "invalid_request", "code_challenge is required (PKCE)")
    if params.get("code_challenge_method") != "S256":
        raise OidcError(
            400,
            "invalid_request",
            "only code_challenge_method=S256 is accepted; plain is rejected",
        )
    state = params.get("state")
    if not state:
        raise OidcError(400, "invalid_request", "state is required")
    nonce = params.get("nonce")
    if not nonce:
        raise OidcError(400, "invalid_request", "nonce is required")
    fixture_user = params.get("fixture_user", "")
    user = IDP_USERS.get(fixture_user)
    if user is None:
        raise OidcError(400, "access_denied", "unknown fixture user")

    code = secrets.token_urlsafe(24)
    store.save_auth_code(
        {
            "code": code,
            "client_id": cfg.client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "nonce": nonce,
            "idp_user": fixture_user,
            "tenant_id": user["home_tenant"],
            "expires_at": now + cfg.code_ttl_seconds,
        }
    )
    query = urllib.parse.urlencode({"code": code, "state": state})
    return f"{redirect_uri}?{query}"


def token(store: Store, cfg: IdpConfig, form: dict, now: float | None = None):
    """Exchange an authorization code for tokens. Returns the token JSON."""
    now = time.time() if now is None else now
    if form.get("grant_type") != "authorization_code":
        raise OidcError(400, "unsupported_grant_type", "authorization_code only")
    if form.get("client_id") != cfg.client_id or form.get("client_secret") != cfg.client_secret:
        raise OidcError(401, "invalid_client", "client authentication failed")
    code_value = form.get("code", "")
    record = store.get_auth_code(code_value)
    if record is None:
        raise OidcError(400, "invalid_grant", "unknown authorization code")
    if record["used"]:
        raise OidcError(400, "invalid_grant", "authorization code already used")
    if now >= float(record["expires_at"]):
        raise OidcError(400, "invalid_grant", "authorization code expired")
    if form.get("redirect_uri") != record["redirect_uri"]:
        raise OidcError(400, "invalid_grant", "redirect_uri mismatch")
    verifier = form.get("code_verifier")
    if not verifier:
        raise OidcError(400, "invalid_grant", "code_verifier is required (PKCE)")
    if not verify_pkce(verifier, record["code_challenge"]):
        raise OidcError(400, "invalid_grant", "PKCE verification failed")

    # Single-use: burn the code before issuing anything.
    store.mark_auth_code_used(code_value)

    user = IDP_USERS[record["idp_user"]]
    id_claims = {
        "iss": cfg.issuer,
        "sub": record["idp_user"],
        "aud": cfg.client_id,
        "iat": int(now),
        "exp": int(now + cfg.id_token_ttl_seconds),
        "nonce": record["nonce"],
        "email": user["email"],
        "name": user["name"],
        "tenant_id": record["tenant_id"],
    }
    access_claims = {
        "iss": cfg.issuer,
        "sub": record["idp_user"],
        "aud": cfg.client_id,
        "iat": int(now),
        "exp": int(now + cfg.access_token_ttl_seconds),
        "scope": "openid profile email",
    }
    return {
        "access_token": sign_jwt(access_claims, cfg.signing_secret),
        "token_type": "Bearer",
        "expires_in": int(cfg.access_token_ttl_seconds),
        "id_token": sign_jwt(id_claims, cfg.signing_secret),
    }


def create_idp_app(store: Store, cfg: IdpConfig | None = None) -> FastAPI:
    cfg = cfg or IdpConfig()
    app = FastAPI(title="fde-enterprise-sso fixture IdP")

    @app.get("/.well-known/openid-configuration")
    def discovery():
        return {
            "issuer": cfg.issuer,
            "authorization_endpoint": f"{cfg.issuer}/authorize",
            "token_endpoint": f"{cfg.issuer}/token",
            "userinfo_endpoint": f"{cfg.issuer}/userinfo",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
            "id_token_signing_alg_values_supported": ["HS256"],
            "note": "Fixture IdP for local development; HS256 with a shared fixture secret stands in for published JWKS keys.",
        }

    @app.get("/authorize")
    def authorize_endpoint(request: Request):
        try:
            location = authorize(store, cfg, dict(request.query_params))
        except OidcError as exc:
            return JSONResponse(
                status_code=exc.status,
                content={"error": exc.error, "error_description": exc.detail},
            )
        return RedirectResponse(location, status_code=302)

    @app.post("/token")
    def token_endpoint(
        grant_type: str = Form(""),
        code: str = Form(""),
        redirect_uri: str = Form(""),
        client_id: str = Form(""),
        client_secret: str = Form(""),
        code_verifier: str = Form(""),
    ):
        form = {
            "grant_type": grant_type,
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
            "code_verifier": code_verifier,
        }
        try:
            return token(store, cfg, form)
        except OidcError as exc:
            return JSONResponse(
                status_code=exc.status,
                content={"error": exc.error, "error_description": exc.detail},
            )

    @app.get("/userinfo")
    def userinfo(authorization: str | None = Header(default=None)):
        if not authorization or not authorization.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"error": "invalid_token"})
        try:
            claims = verify_jwt(
                authorization.removeprefix("Bearer "),
                cfg.signing_secret,
                issuer=cfg.issuer,
                audience=cfg.client_id,
            )
        except JWTError as exc:
            return JSONResponse(
                status_code=401, content={"error": "invalid_token", "detail": str(exc)}
            )
        user = IDP_USERS[claims["sub"]]
        return {"sub": claims["sub"], "email": user["email"], "name": user["name"]}

    return app


# --- Client side --------------------------------------------------------------


def direct_token_post(store: Store, cfg: IdpConfig):
    """A token_post that calls the IdP core in-process (single-process demo).

    In a deployed system this callable is an HTTPS POST to the IdP's token
    endpoint; the client code below is identical either way.
    """

    def _post(form: dict):
        try:
            return 200, token(store, cfg, form)
        except OidcError as exc:
            return exc.status, {"error": exc.error, "error_description": exc.detail}

    return _post


class OidcClient:
    """The service-side OIDC client: login initiation + callback handling."""

    def __init__(self, store: Store, service_cfg: ServiceConfig, token_post):
        self.store = store
        self.cfg = service_cfg
        self.idp = service_cfg.idp
        self.token_post = token_post
        self._pending: dict[str, dict] = {}

    def begin_login(self, tenant_id: str) -> dict:
        state = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        verifier = new_code_verifier()
        self._pending[state] = {
            "nonce": nonce,
            "verifier": verifier,
            "tenant_id": tenant_id,
        }
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": self.idp.client_id,
                "redirect_uri": self.idp.redirect_uris[0],
                "scope": "openid profile email",
                "state": state,
                "nonce": nonce,
                "code_challenge": s256_challenge(verifier),
                "code_challenge_method": "S256",
            }
        )
        return {
            "authorization_url": f"{self.idp.issuer}/authorize?{query}",
            "state": state,
        }

    def handle_callback(self, code: str, state: str) -> dict:
        pending = self._pending.pop(state, None)
        if pending is None:
            raise LoginError(400, "state mismatch: no pending login for this state")
        status, body = self.token_post(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.idp.redirect_uris[0],
                "client_id": self.idp.client_id,
                "client_secret": self.idp.client_secret,
                "code_verifier": pending["verifier"],
            }
        )
        if status != 200:
            raise LoginError(
                status,
                f"token exchange failed: {body.get('error', 'unknown')} "
                f"({body.get('error_description', '')})",
            )
        try:
            claims = verify_jwt(
                body["id_token"],
                self.idp.signing_secret,
                issuer=self.idp.issuer,
                audience=self.idp.client_id,
                nonce=pending["nonce"],
            )
        except JWTError as exc:
            raise LoginError(401, f"id_token validation failed: {exc}") from exc

        tenant_id = pending["tenant_id"]
        if claims.get("tenant_id") != tenant_id:
            raise LoginError(403, "identity belongs to a different tenant")

        # Provisioning gate: the SCIM directory decides who may sign in.
        # A deactivated (or never provisioned) user is, for authentication
        # purposes, not found.
        directory = self.store.get_scim_user_by_username(tenant_id, claims["email"])
        if directory is None or not directory["active"]:
            raise LoginError(404, "user is not provisioned (or is deactivated) in this tenant")

        user = self.store.get_user_by_email(claims["email"])
        membership = (
            self.store.get_membership(tenant_id, user["id"]) if user else None
        )
        if membership is None:
            raise LoginError(403, "user has no membership in this tenant")

        now = time.time()
        session_claims = {
            "iss": self.cfg.issuer,
            "aud": self.cfg.audience,
            "sub": user["id"],
            "email": user["email"],
            "tenant_id": tenant_id,
            "iat": int(now),
            "exp": int(now + self.cfg.session_ttl_seconds),
        }
        return {
            "session_token": sign_jwt(session_claims, self.cfg.signing_secret),
            "user_id": user["id"],
            "email": user["email"],
            "tenant_id": tenant_id,
            "role": membership["role"],
            "id_token_claims": claims,
        }
