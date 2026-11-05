import pytest

from conftest import mint_session
from fde_sso.config import TENANT_ACME, TENANT_GLOBEX
from fde_sso.rbac import PERMISSIONS, ROLE_PERMISSIONS, has_permission

OWNER = mint_session("user-ada", TENANT_ACME, "ada@acme.example")
MEMBER = mint_session("user-alan", TENANT_ACME, "alan@acme.example")
VIEWER = mint_session("user-vera", TENANT_ACME, "vera@acme.example")
GLOBEX_ADMIN_AS_ACME = mint_session("user-gina", TENANT_ACME, "gina@globex.example")
ADA_AS_GLOBEX = mint_session("user-ada", TENANT_GLOBEX, "ada@acme.example")


# --- The matrix itself, pinned ----------------------------------------------------


def test_permission_matrix_is_pinned():
    assert ROLE_PERMISSIONS["owner"] == frozenset(PERMISSIONS)
    assert ROLE_PERMISSIONS["admin"] == frozenset(PERMISSIONS) - {"billing.write"}
    assert ROLE_PERMISSIONS["viewer"] == frozenset(
        {"tenant.settings.read", "members.read", "sso.read", "scim.read", "data.read"}
    )
    assert ROLE_PERMISSIONS["member"] == ROLE_PERMISSIONS["viewer"] | {"data.write"}
    assert not has_permission(None, "data.read")
    assert not has_permission("nonexistent-role", "data.read")


# --- Per-role enforcement through the API -------------------------------------------


def test_viewer_is_read_only(service):
    assert service.get(f"/tenants/{TENANT_ACME}/settings", headers=VIEWER).status_code == 200
    assert service.get(f"/tenants/{TENANT_ACME}/data", headers=VIEWER).status_code == 200
    assert service.patch(
        f"/tenants/{TENANT_ACME}/settings", json={"region": "x"}, headers=VIEWER
    ).status_code == 403
    assert service.post(
        f"/tenants/{TENANT_ACME}/data", json={"body": "x"}, headers=VIEWER
    ).status_code == 403


def test_member_can_write_data_but_not_administer(service):
    assert service.post(
        f"/tenants/{TENANT_ACME}/data", json={"body": "hello"}, headers=MEMBER
    ).status_code == 201
    assert service.post(
        f"/tenants/{TENANT_ACME}/members/invite",
        json={"user_id": "user-gina", "role": "viewer"},
        headers=MEMBER,
    ).status_code == 403
    assert service.put(
        f"/tenants/{TENANT_ACME}/sso/config", json={"enforced": True}, headers=MEMBER
    ).status_code == 403
    assert service.get(f"/tenants/{TENANT_ACME}/billing", headers=MEMBER).status_code == 403
    assert service.delete(
        f"/tenants/{TENANT_ACME}/data/anything", headers=MEMBER
    ).status_code == 403


def test_admin_cannot_write_billing_but_owner_can(service, store):
    # Gina is admin of Globex: give her a Globex session via a second store role.
    store.set_membership(TENANT_GLOBEX, "user-gina", "admin")
    gina_globex = mint_session("user-gina", TENANT_GLOBEX, "gina@globex.example")
    assert service.get(f"/tenants/{TENANT_GLOBEX}/billing", headers=gina_globex).status_code == 200
    assert service.patch(
        f"/tenants/{TENANT_GLOBEX}/billing", json={"plan": "fixture-pro"}, headers=gina_globex
    ).status_code == 403
    assert service.put(
        f"/tenants/{TENANT_GLOBEX}/sso/config", json={"enforced": True}, headers=gina_globex
    ).status_code == 200

    assert service.patch(
        f"/tenants/{TENANT_ACME}/billing", json={"plan": "fixture-pro"}, headers=OWNER
    ).status_code == 200
    assert service.get(f"/tenants/{TENANT_ACME}/billing", headers=OWNER).json()["plan"] == "fixture-pro"


def test_owner_full_crud_and_member_admin(service):
    created = service.post(
        f"/tenants/{TENANT_ACME}/data", json={"body": "row"}, headers=OWNER
    )
    assert created.status_code == 201
    data_id = created.json()["id"]
    assert service.delete(
        f"/tenants/{TENANT_ACME}/data/{data_id}", headers=OWNER
    ).status_code == 204

    invited = service.post(
        f"/tenants/{TENANT_ACME}/members/invite",
        json={"user_id": "user-gina", "role": "viewer"},
        headers=OWNER,
    )
    assert invited.status_code == 201
    members = service.get(f"/tenants/{TENANT_ACME}/members", headers=OWNER).json()
    assert any(m["user_id"] == "user-gina" and m["role"] == "viewer" for m in members)
    assert service.delete(
        f"/tenants/{TENANT_ACME}/members/user-gina", headers=OWNER
    ).status_code == 204


def test_scim_status_respects_role(service):
    assert service.get(f"/tenants/{TENANT_ACME}/scim/status", headers=VIEWER).status_code == 200
    body = service.get(f"/tenants/{TENANT_ACME}/scim/status", headers=OWNER).json()
    assert body["users"] >= 3 and body["active_users"] >= 3


# --- Cross-tenant denial ---------------------------------------------------------------


def test_cross_tenant_session_rejected(service):
    # Ada's session is scoped to Acme; Globex routes refuse it outright,
    # even though Ada does hold a (viewer) membership in Globex.
    response = service.get(f"/tenants/{TENANT_GLOBEX}/settings", headers=OWNER)
    assert response.status_code == 403
    assert "different tenant" in response.json()["detail"]


def test_admin_of_other_tenant_has_no_rights_here(service):
    # Gina administers Globex but has no Acme membership: an Acme-scoped
    # token in her name gets nothing.
    assert service.get(f"/tenants/{TENANT_ACME}/settings", headers=GLOBEX_ADMIN_AS_ACME).status_code == 403
    assert service.get(f"/tenants/{TENANT_ACME}/members", headers=GLOBEX_ADMIN_AS_ACME).status_code == 403
    assert service.post(
        f"/tenants/{TENANT_ACME}/data", json={"body": "x"}, headers=GLOBEX_ADMIN_AS_ACME
    ).status_code == 403


def test_role_is_per_tenant_not_global(service):
    # The same person (Ada) is owner in Acme but only viewer in Globex:
    # with a Globex-scoped session she can read but not write.
    assert service.get(f"/tenants/{TENANT_GLOBEX}/settings", headers=ADA_AS_GLOBEX).status_code == 200
    assert service.patch(
        f"/tenants/{TENANT_GLOBEX}/settings", json={"region": "x"}, headers=ADA_AS_GLOBEX
    ).status_code == 403
    # ...while her Acme owner session writes fine.
    assert service.patch(
        f"/tenants/{TENANT_ACME}/settings", json={"region": "fixture-eu-2"}, headers=OWNER
    ).status_code == 200


def test_role_change_takes_effect_immediately(service, store):
    assert service.post(
        f"/tenants/{TENANT_ACME}/data", json={"body": "x"}, headers=MEMBER
    ).status_code == 201
    store.set_membership(TENANT_ACME, "user-alan", "viewer")
    assert service.post(
        f"/tenants/{TENANT_ACME}/data", json={"body": "x"}, headers=MEMBER
    ).status_code == 403


def test_unauthenticated_and_forged_tokens_rejected(service):
    assert service.get(f"/tenants/{TENANT_ACME}/settings").status_code == 401
    forged = {"Authorization": "Bearer aaa.bbb.ccc"}
    assert service.get(f"/tenants/{TENANT_ACME}/settings", headers=forged).status_code == 401
