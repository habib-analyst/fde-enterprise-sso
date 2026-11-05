"""The SaaS service application.

Wires the four subsystems together:

- `/auth/login` + `/auth/callback` — the OIDC client side (PKCE login
  against the fixture IdP, ID-token validation, provisioning gate,
  session issuance).
- `/scim/v2/...` — SCIM provisioning, per-tenant bearer tokens.
- `/saml/validate` — validate a fixture SAML response, return identity.
- `/tenants/{tenant_id}/...` — RBAC-protected tenant resources. The
  caller's role is resolved from the membership row for the requested
  tenant on every request; the session token's tenant must match the
  path tenant, so rights in one tenant never leak into another.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse

from .config import ServiceConfig
from .jwtutil import JWTError, verify_jwt
from .oidc import LoginError, OidcClient, direct_token_post
from .rbac import has_permission
from .saml import SamlError, validate_saml_response
from .scim import ScimError, create_scim_router, scim_error_response
from .store import Store


class AuthError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def create_service_app(
    store: Store,
    cfg: ServiceConfig | None = None,
    token_post=None,
) -> FastAPI:
    cfg = cfg or ServiceConfig()
    client = OidcClient(store, cfg, token_post or direct_token_post(store, cfg.idp))
    app = FastAPI(title="fde-enterprise-sso service")
    app.state.oidc_client = client

    @app.exception_handler(ScimError)
    async def _scim_error_handler(_request: Request, exc: ScimError):
        return scim_error_response(exc)

    @app.exception_handler(AuthError)
    async def _auth_error_handler(_request: Request, exc: AuthError):
        return JSONResponse(status_code=exc.status, content={"detail": exc.detail})

    @app.get("/health")
    def health():
        return {"status": "ok"}

    # -- OIDC client endpoints ---------------------------------------------
    @app.get("/auth/login")
    def login(tenant_id: str):
        # A deployed service would 302 to this URL; returning it as JSON
        # keeps the local demo (and its tests) inspectable.
        return client.begin_login(tenant_id)

    @app.get("/auth/callback")
    def callback(code: str, state: str):
        try:
            result = client.handle_callback(code, state)
        except LoginError as exc:
            return JSONResponse(status_code=exc.status, content={"detail": exc.detail})
        return {
            "session_token": result["session_token"],
            "user_id": result["user_id"],
            "email": result["email"],
            "tenant_id": result["tenant_id"],
            "role": result["role"],
        }

    # -- SAML endpoint -------------------------------------------------------
    @app.post("/saml/validate")
    async def saml_validate(request: Request):
        body = await request.json()
        xml_text = body.get("saml_response", "")
        try:
            identity = validate_saml_response(xml_text)
        except SamlError as exc:
            return JSONResponse(
                status_code=400,
                content={"detail": f"{type(exc).__name__}: {exc}"},
            )
        return {
            "name_id": identity.name_id,
            "issuer": identity.issuer,
            "audience": identity.audience,
            "attributes": identity.attributes,
        }

    # -- SCIM ------------------------------------------------------------------
    app.include_router(create_scim_router(store))

    # -- Session + RBAC enforcement ---------------------------------------------
    def get_session(authorization: str | None = Header(default=None)) -> dict:
        if not authorization or not authorization.startswith("Bearer "):
            raise AuthError(401, "missing session token")
        try:
            return verify_jwt(
                authorization.removeprefix("Bearer "),
                cfg.signing_secret,
                issuer=cfg.issuer,
                audience=cfg.audience,
            )
        except JWTError as exc:
            raise AuthError(401, f"invalid session token: {exc}") from exc

    def require_permission(permission: str):
        def dependency(tenant_id: str, session: dict = Depends(get_session)):
            if session.get("tenant_id") != tenant_id:
                raise AuthError(
                    403, "session is scoped to a different tenant"
                )
            membership = store.get_membership(tenant_id, session.get("sub", ""))
            if membership is None:
                raise AuthError(403, "no membership in this tenant")
            if not has_permission(membership["role"], permission):
                raise AuthError(
                    403,
                    f"role {membership['role']!r} lacks permission {permission!r}",
                )
            return {"session": session, "role": membership["role"]}

        return dependency

    # -- Tenant resources ------------------------------------------------------
    @app.get("/tenants/{tenant_id}/settings")
    def get_settings(tenant_id: str, _=Depends(require_permission("tenant.settings.read"))):
        return store.get_kv(tenant_id, "settings", {})

    @app.patch("/tenants/{tenant_id}/settings")
    async def patch_settings(
        tenant_id: str, request: Request, _=Depends(require_permission("tenant.settings.write"))
    ):
        updates = await request.json()
        settings = store.get_kv(tenant_id, "settings", {})
        settings.update(updates)
        store.set_kv(tenant_id, "settings", settings)
        return settings

    @app.get("/tenants/{tenant_id}/members")
    def list_members(tenant_id: str, _=Depends(require_permission("members.read"))):
        return [
            {
                "user_id": row["user_id"],
                "email": row["email"],
                "name": row["name"],
                "role": row["role"],
            }
            for row in store.list_memberships(tenant_id)
        ]

    @app.post("/tenants/{tenant_id}/members/invite", status_code=201)
    async def invite_member(
        tenant_id: str, request: Request, _=Depends(require_permission("members.invite"))
    ):
        body = await request.json()
        from .rbac import ROLES

        user = store.get_user(body.get("user_id", ""))
        if user is None:
            raise AuthError(404, "user not found")
        if body.get("role") not in ROLES:
            raise AuthError(400, f"role must be one of {ROLES}")
        store.set_membership(tenant_id, user["id"], body["role"])
        return {"user_id": user["id"], "role": body["role"], "tenant_id": tenant_id}

    @app.delete("/tenants/{tenant_id}/members/{user_id}")
    def remove_member(
        tenant_id: str, user_id: str, _=Depends(require_permission("members.remove"))
    ):
        if not store.delete_membership(tenant_id, user_id):
            raise AuthError(404, "membership not found")
        return JSONResponse(status_code=204, content=None)

    @app.get("/tenants/{tenant_id}/sso/config")
    def get_sso_config(tenant_id: str, _=Depends(require_permission("sso.read"))):
        return store.get_kv(tenant_id, "sso_config", {})

    @app.put("/tenants/{tenant_id}/sso/config")
    async def put_sso_config(
        tenant_id: str, request: Request, _=Depends(require_permission("sso.configure"))
    ):
        body = await request.json()
        store.set_kv(tenant_id, "sso_config", body)
        return body

    @app.get("/tenants/{tenant_id}/scim/status")
    def scim_status(tenant_id: str, _=Depends(require_permission("scim.read"))):
        users = store.list_scim_users(tenant_id)
        return {
            "users": len(users),
            "active_users": sum(1 for u in users if u["active"]),
            "groups": len(store.list_scim_groups(tenant_id)),
        }

    @app.get("/tenants/{tenant_id}/billing")
    def get_billing(tenant_id: str, _=Depends(require_permission("billing.read"))):
        return store.get_kv(tenant_id, "billing", {})

    @app.patch("/tenants/{tenant_id}/billing")
    async def patch_billing(
        tenant_id: str, request: Request, _=Depends(require_permission("billing.write"))
    ):
        updates = await request.json()
        billing = store.get_kv(tenant_id, "billing", {})
        billing.update(updates)
        store.set_kv(tenant_id, "billing", billing)
        return billing

    @app.get("/tenants/{tenant_id}/data")
    def list_data(tenant_id: str, _=Depends(require_permission("data.read"))):
        return [{"id": r["id"], "body": r["body"]} for r in store.list_data(tenant_id)]

    @app.post("/tenants/{tenant_id}/data", status_code=201)
    async def add_data(
        tenant_id: str, request: Request, _=Depends(require_permission("data.write"))
    ):
        body = await request.json()
        data_id = store.add_data(tenant_id, str(body.get("body", "")))
        return {"id": data_id}

    @app.delete("/tenants/{tenant_id}/data/{data_id}")
    def delete_data(
        tenant_id: str, data_id: str, _=Depends(require_permission("data.delete"))
    ):
        if not store.delete_data(tenant_id, data_id):
            raise AuthError(404, "data row not found")
        return JSONResponse(status_code=204, content=None)

    return app
