"""Deterministic fixture seed data: tenants, IdP users, memberships, and
the SCIM directory mirror of the IdP users.

The fixture IdP's users are also provisioned into each tenant's SCIM
directory (active) — that is what lets SCIM deactivation gate SSO sign-in:
provisioning controls who may authenticate, the IdP only proves identity.
"""

from __future__ import annotations

from .config import TENANT_ACME, TENANT_GLOBEX
from .store import Store

# Fixture IdP users. `username` is what the fixture IdP "authenticates"
# (selected via the `fixture_user` authorize parameter in this local demo —
# a real IdP would show a login form). Emails are on the reserved
# `.example` TLD and belong to nobody.
IDP_USERS = {
    "ada@acme.example": {
        "user_id": "user-ada",
        "email": "ada@acme.example",
        "name": "Ada Admin",
        "home_tenant": TENANT_ACME,
    },
    "alan@acme.example": {
        "user_id": "user-alan",
        "email": "alan@acme.example",
        "name": "Alan Member",
        "home_tenant": TENANT_ACME,
    },
    "vera@acme.example": {
        "user_id": "user-vera",
        "email": "vera@acme.example",
        "name": "Vera Viewer",
        "home_tenant": TENANT_ACME,
    },
    "gina@globex.example": {
        "user_id": "user-gina",
        "email": "gina@globex.example",
        "name": "Gina Globex",
        "home_tenant": TENANT_GLOBEX,
    },
}

# (tenant, user_id, role) — note the deliberate cross-tenant shape:
# Ada is owner of Acme but only a viewer in Globex; Gina administers
# Globex and has no Acme membership at all.
MEMBERSHIPS = [
    (TENANT_ACME, "user-ada", "owner"),
    (TENANT_ACME, "user-alan", "member"),
    (TENANT_ACME, "user-vera", "viewer"),
    (TENANT_GLOBEX, "user-gina", "admin"),
    (TENANT_GLOBEX, "user-ada", "viewer"),
]


def seed_store(store: Store) -> Store:
    store.add_tenant(TENANT_ACME, "Acme Fixture Corp")
    store.add_tenant(TENANT_GLOBEX, "Globex Fixture Ltd")
    for record in IDP_USERS.values():
        store.add_user(record["user_id"], record["email"], record["name"])
    for tenant_id, user_id, role in MEMBERSHIPS:
        store.set_membership(tenant_id, user_id, role)
    # SCIM directory mirror: every IdP user provisioned, active, in the
    # tenant(s) where they hold a membership.
    provisioned = set()
    for tenant_id, user_id, _role in MEMBERSHIPS:
        record = next(r for r in IDP_USERS.values() if r["user_id"] == user_id)
        key = (tenant_id, record["email"])
        if key in provisioned:
            continue
        provisioned.add(key)
        store.create_scim_user(
            tenant_id,
            {
                "user_name": record["email"],
                "display_name": record["name"],
                "email": record["email"],
                "external_id": f"fixture-ext-{user_id}",
                "active": True,
            },
        )
    store.set_kv(
        TENANT_ACME, "settings", {"display_name": "Acme Fixture Corp", "region": "fixture-eu"}
    )
    store.set_kv(
        TENANT_GLOBEX, "settings", {"display_name": "Globex Fixture Ltd", "region": "fixture-us"}
    )
    for tenant_id in (TENANT_ACME, TENANT_GLOBEX):
        store.set_kv(
            tenant_id,
            "sso_config",
            {"idp": "fixture-idp", "protocol": "oidc", "enforced": False},
        )
        store.set_kv(tenant_id, "billing", {"plan": "fixture-free", "seats": 5})
    return store
