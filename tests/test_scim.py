import pytest

from conftest import SCIM_ACME, SCIM_GLOBEX, full_login
from fde_sso.config import TENANT_ACME, TENANT_GLOBEX

NEW_USER = {
    "userName": "nina@acme.example",
    "displayName": "Nina New",
    "emails": [{"value": "nina@acme.example", "primary": True}],
    "active": True,
}


def _create_user(service, headers=SCIM_ACME, body=None):
    return service.post("/scim/v2/Users", json=body or NEW_USER, headers=headers)


# --- Lifecycle ------------------------------------------------------------------


def test_user_lifecycle_create_patch_deactivate_delete(service):
    created = _create_user(service)
    assert created.status_code == 201, created.text
    resource = created.json()
    assert resource["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:User"]
    assert resource["active"] is True
    user_id = resource["id"]

    fetched = service.get(f"/scim/v2/Users/{user_id}", headers=SCIM_ACME)
    assert fetched.status_code == 200
    assert fetched.json()["userName"] == "nina@acme.example"

    patched = service.patch(
        f"/scim/v2/Users/{user_id}",
        json={"Operations": [{"op": "replace", "path": "displayName", "value": "Nina Renamed"}]},
        headers=SCIM_ACME,
    )
    assert patched.status_code == 200
    assert patched.json()["displayName"] == "Nina Renamed"

    deactivated = service.patch(
        f"/scim/v2/Users/{user_id}",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        headers=SCIM_ACME,
    )
    assert deactivated.status_code == 200
    assert deactivated.json()["active"] is False

    deleted = service.delete(f"/scim/v2/Users/{user_id}", headers=SCIM_ACME)
    assert deleted.status_code == 204
    gone = service.get(f"/scim/v2/Users/{user_id}", headers=SCIM_ACME)
    assert gone.status_code == 404
    assert gone.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    assert gone.json()["status"] == "404"


def test_deactivation_blocks_sso_login_with_404(service, idp, store):
    # Ada is provisioned (active) in Acme; her login works.
    ok = full_login(service, idp, TENANT_ACME, "ada@acme.example")
    assert ok.status_code == 200

    ada = store.get_scim_user_by_username(TENANT_ACME, "ada@acme.example")
    deactivated = service.patch(
        f"/scim/v2/Users/{ada['id']}",
        json={"Operations": [{"op": "replace", "value": {"active": False}}]},
        headers=SCIM_ACME,
    )
    assert deactivated.status_code == 200
    assert deactivated.json()["active"] is False

    # After deactivation the same SSO login is refused: for authentication
    # the user is not found (404).
    refused = full_login(service, idp, TENANT_ACME, "ada@acme.example")
    assert refused.status_code == 404


def test_put_replaces_user(service):
    user_id = _create_user(service).json()["id"]
    replaced = service.put(
        f"/scim/v2/Users/{user_id}",
        json={
            "userName": "nina@acme.example",
            "displayName": "Nina Replaced",
            "emails": [{"value": "nina2@acme.example"}],
            "active": False,
        },
        headers=SCIM_ACME,
    )
    assert replaced.status_code == 200
    assert replaced.json()["displayName"] == "Nina Replaced"
    assert replaced.json()["emails"][0]["value"] == "nina2@acme.example"
    assert replaced.json()["active"] is False


def test_duplicate_username_conflict(service):
    assert _create_user(service).status_code == 201
    again = _create_user(service)
    assert again.status_code == 409
    assert again.json()["scimType"] == "uniqueness"


def test_missing_username_is_400(service):
    response = service.post("/scim/v2/Users", json={"displayName": "No Name"}, headers=SCIM_ACME)
    assert response.status_code == 400
    assert response.json()["scimType"] == "invalidValue"


def test_filter_by_username(service):
    _create_user(service)
    _create_user(service, body={**NEW_USER, "userName": "otto@acme.example"})
    response = service.get(
        "/scim/v2/Users", params={"filter": 'userName eq "otto@acme.example"'}, headers=SCIM_ACME
    )
    assert response.status_code == 200
    body = response.json()
    assert body["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
    assert body["totalResults"] == 1
    assert body["Resources"][0]["userName"] == "otto@acme.example"


def test_unsupported_filter_is_400(service):
    response = service.get(
        "/scim/v2/Users", params={"filter": 'userName co "a"'}, headers=SCIM_ACME
    )
    assert response.status_code == 400
    assert response.json()["scimType"] == "invalidFilter"


def test_list_users_scoped_and_seeded(service):
    response = service.get("/scim/v2/Users", headers=SCIM_ACME)
    names = {r["userName"] for r in response.json()["Resources"]}
    assert "ada@acme.example" in names
    assert "gina@globex.example" not in names


# --- Auth + tenant isolation -------------------------------------------------------


def test_scim_requires_valid_bearer_token(service):
    assert service.get("/scim/v2/Users").status_code == 401
    bad = service.get(
        "/scim/v2/Users", headers={"Authorization": "Bearer fixture-wrong-token"}
    )
    assert bad.status_code == 401
    assert bad.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]


def test_cross_tenant_user_is_invisible(service):
    user_id = _create_user(service, headers=SCIM_ACME).json()["id"]
    other = service.get(f"/scim/v2/Users/{user_id}", headers=SCIM_GLOBEX)
    assert other.status_code == 404
    patch = service.patch(
        f"/scim/v2/Users/{user_id}",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        headers=SCIM_GLOBEX,
    )
    assert patch.status_code == 404
    delete = service.delete(f"/scim/v2/Users/{user_id}", headers=SCIM_GLOBEX)
    assert delete.status_code == 404
    # Still intact in its own tenant.
    assert service.get(f"/scim/v2/Users/{user_id}", headers=SCIM_ACME).status_code == 200


def test_same_username_allowed_in_two_tenants(service):
    assert _create_user(service, headers=SCIM_ACME).status_code == 201
    assert _create_user(service, headers=SCIM_GLOBEX).status_code == 201


# --- Groups -------------------------------------------------------------------------


def test_group_lifecycle(service, store):
    ada = store.get_scim_user_by_username(TENANT_ACME, "ada@acme.example")
    alan = store.get_scim_user_by_username(TENANT_ACME, "alan@acme.example")
    vera = store.get_scim_user_by_username(TENANT_ACME, "vera@acme.example")

    created = service.post(
        "/scim/v2/Groups",
        json={"displayName": "Engineering", "members": [{"value": ada["id"]}]},
        headers=SCIM_ACME,
    )
    assert created.status_code == 201, created.text
    group = created.json()
    assert [m["value"] for m in group["members"]] == [ada["id"]]
    group_id = group["id"]

    added = service.patch(
        f"/scim/v2/Groups/{group_id}",
        json={"Operations": [{"op": "add", "path": "members", "value": [{"value": alan["id"]}]}]},
        headers=SCIM_ACME,
    )
    assert added.status_code == 200
    assert {m["value"] for m in added.json()["members"]} == {ada["id"], alan["id"]}

    removed = service.patch(
        f"/scim/v2/Groups/{group_id}",
        json={"Operations": [{"op": "remove", "path": f'members[value eq "{ada["id"]}"]'}]},
        headers=SCIM_ACME,
    )
    assert removed.status_code == 200
    assert [m["value"] for m in removed.json()["members"]] == [alan["id"]]

    filtered = service.get(
        "/scim/v2/Groups", params={"filter": 'displayName eq "Engineering"'}, headers=SCIM_ACME
    )
    assert filtered.json()["totalResults"] == 1

    deleted = service.delete(f"/scim/v2/Groups/{group_id}", headers=SCIM_ACME)
    assert deleted.status_code == 204
    assert service.get(f"/scim/v2/Groups/{group_id}", headers=SCIM_ACME).status_code == 404
    _ = vera  # referenced to keep the seeded trio explicit


def test_group_member_must_exist_in_tenant(service):
    response = service.post(
        "/scim/v2/Groups",
        json={"displayName": "Bad", "members": [{"value": "u-does-not-exist"}]},
        headers=SCIM_ACME,
    )
    assert response.status_code == 400


def test_group_cross_tenant_member_rejected(service, store):
    globex_user = store.get_scim_user_by_username(TENANT_GLOBEX, "gina@globex.example")
    response = service.post(
        "/scim/v2/Groups",
        json={"displayName": "Sneaky", "members": [{"value": globex_user["id"]}]},
        headers=SCIM_ACME,
    )
    assert response.status_code == 400
