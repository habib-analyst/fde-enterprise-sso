"""Configuration and fixture constants.

Every value here is synthetic. Issuer URLs are identifiers only — nothing
in this project makes a network call. Secrets are obviously fake fixture
strings, never real credentials.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --- Fixture identity provider (OIDC) -------------------------------------
IDP_ISSUER = "https://idp.fixture.example"
IDP_SIGNING_SECRET = "fixture-idp-signing-secret"
IDP_BASE_URL = IDP_ISSUER  # identifier only; the IdP app is in-process

# --- Service (the SaaS application / OIDC client + SCIM + RBAC) -----------
SERVICE_ISSUER = "https://service.fixture.example"
SERVICE_AUDIENCE = "fde-sso-api"
SERVICE_SIGNING_SECRET = "fixture-service-signing-secret"

CLIENT_ID = "fixture-client-sso-demo"
CLIENT_SECRET = "fixture-client-secret"
REDIRECT_URI = "https://service.fixture.example/auth/callback"

# --- SAML fixture ----------------------------------------------------------
SP_ENTITY_ID = "https://service.fixture.example/saml"
SAML_IDP_ENTITY_ID = "https://idp.fixture.example/saml"
SAML_SIGNING_KEY = "fixture-saml-signing-key"

# --- Tenants ----------------------------------------------------------------
TENANT_ACME = "tenant-acme"
TENANT_GLOBEX = "tenant-globex"

# Per-tenant SCIM provisioning bearer tokens (fixtures).
SCIM_TOKENS = {
    "fixture-scim-token-acme": TENANT_ACME,
    "fixture-scim-token-globex": TENANT_GLOBEX,
}


@dataclass
class IdpConfig:
    """Tunables for the fixture IdP (tests override the TTLs)."""

    issuer: str = IDP_ISSUER
    signing_secret: str = IDP_SIGNING_SECRET
    client_id: str = CLIENT_ID
    client_secret: str = CLIENT_SECRET
    redirect_uris: tuple = (REDIRECT_URI,)
    code_ttl_seconds: float = 60.0
    id_token_ttl_seconds: float = 600.0
    access_token_ttl_seconds: float = 600.0


@dataclass
class ServiceConfig:
    issuer: str = SERVICE_ISSUER
    audience: str = SERVICE_AUDIENCE
    signing_secret: str = SERVICE_SIGNING_SECRET
    session_ttl_seconds: float = 3600.0
    idp: IdpConfig = field(default_factory=IdpConfig)
