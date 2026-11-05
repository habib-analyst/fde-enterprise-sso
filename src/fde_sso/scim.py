"""SCIM 2.0 provisioning endpoints (Users and Groups), scoped per tenant.

Authentication is a per-tenant bearer token (fixture tokens here; a real
deployment issues one credential per tenant connection). Every query is
constrained to the token's tenant, so one tenant's provisioning client
cannot read, modify or even confirm the existence of another tenant's
directory — cross-tenant ids return the SCIM 404 error, not data.

Supported: POST/GET(list+by id)/PATCH/PUT/DELETE for Users and Groups,
`filter=<attr> eq "<value>"` on userName/displayName, PATCH operations on
`active`, `displayName`, `userName`, `emails`, group `members`, and
deactivation via `active=false`. Errors use the SCIM error schema.
"""

from __future__ import annotations

import re
import sqlite3

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse, Response

from .config import SCIM_TOKENS
from .store import Store

ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"

_FILTER_RE = re.compile(r'^\s*([A-Za-z.]+)\s+eq\s+"([^"]*)"\s*$')
_MEMBER_PATH_RE = re.compile(r'^members\[value eq "([^"]+)"\]$')


class ScimError(Exception):
    def __init__(self, status: int, detail: str, scim_type: str | None = None):
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.scim_type = scim_type


def scim_error_response(exc: ScimError) -> JSONResponse:
    body = {"schemas": [ERROR_SCHEMA], "detail": exc.detail, "status": str(exc.status)}
    if exc.scim_type:
        body["scimType"] = exc.scim_type
    return JSONResponse(status_code=exc.status, content=body)


def _user_resource(store: Store, row) -> dict:
    return {
        "schemas": [USER_SCHEMA],
        "id": row["id"],
        "userName": row["user_name"],
        "displayName": row["display_name"],
        "emails": [{"value": row["email"], "primary": True}] if row["email"] else [],
        "active": bool(row["active"]),
        "externalId": row["external_id"],
        "meta": {"resourceType": "User", "location": f"/scim/v2/Users/{row['id']}"},
    }


def _group_resource(store: Store, row) -> dict:
    members = []
    for user_id in store.group_member_ids(row["id"]):
        user = store.get_scim_user(row["tenant_id"], user_id)
        members.append(
            {
                "value": user_id,
                "$ref": f"/scim/v2/Users/{user_id}",
                "display": user["display_name"] if user else "",
            }
        )
    return {
        "schemas": [GROUP_SCHEMA],
        "id": row["id"],
        "displayName": row["display_name"],
        "members": members,
        "meta": {"resourceType": "Group", "location": f"/scim/v2/Groups/{row['id']}"},
    }


def _list_response(resources: list) -> dict:
    return {
        "schemas": [LIST_SCHEMA],
        "totalResults": len(resources),
        "startIndex": 1,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


def _parse_filter(filter_value: str | None, allowed: set[str]):
    if not filter_value:
        return None
    match = _FILTER_RE.match(filter_value)
    if not match or match.group(1) not in allowed:
        raise ScimError(
            400,
            f"unsupported filter: {filter_value!r} (supported: <attr> eq \"<value>\")",
            scim_type="invalidFilter",
        )
    return match.group(1), match.group(2)


def _email_from(body: dict) -> str:
    emails = body.get("emails") or []
    for entry in emails:
        if isinstance(entry, dict) and entry.get("value"):
            return entry["value"]
    return body.get("email", "")


def _user_fields_from(body: dict, *, partial: bool) -> dict:
    fields = {}
    if "userName" in body:
        fields["user_name"] = body["userName"]
    if "displayName" in body:
        fields["display_name"] = body["displayName"]
    if "emails" in body or "email" in body:
        fields["email"] = _email_from(body)
    if "externalId" in body:
        fields["external_id"] = body["externalId"]
    if "active" in body:
        fields["active"] = bool(body["active"])
    if not partial:
        fields.setdefault("display_name", "")
        fields.setdefault("email", "")
        fields.setdefault("external_id", None)
        fields.setdefault("active", True)
    return fields


def create_scim_router(store: Store) -> APIRouter:
    router = APIRouter(prefix="/scim/v2")

    def tenant_from_token(authorization: str | None = Header(default=None)) -> str:
        if not authorization or not authorization.startswith("Bearer "):
            raise ScimError(401, "missing bearer token")
        tenant_id = SCIM_TOKENS.get(authorization.removeprefix("Bearer "))
        if tenant_id is None:
            raise ScimError(401, "invalid bearer token")
        return tenant_id

    # -- Users ------------------------------------------------------------
    @router.post("/Users", status_code=201)
    async def create_user(request: Request, tenant_id: str = Depends(tenant_from_token)):
        body = await request.json()
        user_name = body.get("userName")
        if not user_name:
            raise ScimError(400, "userName is required", scim_type="invalidValue")
        if store.get_scim_user_by_username(tenant_id, user_name):
            raise ScimError(409, f"userName {user_name!r} already exists", scim_type="uniqueness")
        fields = _user_fields_from(body, partial=False)
        fields["user_name"] = user_name
        row = store.create_scim_user(tenant_id, fields)
        return JSONResponse(status_code=201, content=_user_resource(store, row))

    @router.get("/Users")
    def list_users(filter: str | None = None, tenant_id: str = Depends(tenant_from_token)):
        parsed = _parse_filter(filter, {"userName", "displayName"})
        rows = store.list_scim_users(tenant_id)
        if parsed:
            attr, value = parsed
            column = "user_name" if attr == "userName" else "display_name"
            rows = [r for r in rows if r[column] == value]
        return _list_response([_user_resource(store, r) for r in rows])

    @router.get("/Users/{user_id}")
    def get_user(user_id: str, tenant_id: str = Depends(tenant_from_token)):
        row = store.get_scim_user(tenant_id, user_id)
        if row is None:
            raise ScimError(404, f"user {user_id} not found")
        return _user_resource(store, row)

    @router.patch("/Users/{user_id}")
    async def patch_user(user_id: str, request: Request, tenant_id: str = Depends(tenant_from_token)):
        row = store.get_scim_user(tenant_id, user_id)
        if row is None:
            raise ScimError(404, f"user {user_id} not found")
        body = await request.json()
        fields: dict = {}
        for op in body.get("Operations", []):
            operation = str(op.get("op", "")).lower()
            if operation not in {"add", "replace", "remove"}:
                raise ScimError(400, f"unsupported op: {op.get('op')!r}", scim_type="invalidValue")
            path = op.get("path")
            value = op.get("value")
            if path is None and isinstance(value, dict):
                fields.update(_user_fields_from(value, partial=True))
            elif path in {"active", "displayName", "userName", "externalId"}:
                key = {"active": "active", "displayName": "display_name",
                       "userName": "user_name", "externalId": "external_id"}[path]
                if operation == "remove":
                    fields[key] = "" if key != "active" else False
                else:
                    fields[key] = value
            elif path == "emails":
                values = value if isinstance(value, list) else [value]
                fields["email"] = values[0].get("value", "") if values and isinstance(values[0], dict) else ""
            else:
                raise ScimError(400, f"unsupported path: {path!r}", scim_type="noTarget")
        if "user_name" in fields and fields["user_name"] != row["user_name"]:
            clash = store.get_scim_user_by_username(tenant_id, fields["user_name"])
            if clash is not None:
                raise ScimError(409, "userName already exists", scim_type="uniqueness")
        try:
            row = store.update_scim_user(tenant_id, user_id, fields)
        except sqlite3.IntegrityError as exc:
            raise ScimError(409, f"uniqueness violation: {exc}", scim_type="uniqueness") from exc
        return _user_resource(store, row)

    @router.put("/Users/{user_id}")
    async def replace_user(user_id: str, request: Request, tenant_id: str = Depends(tenant_from_token)):
        row = store.get_scim_user(tenant_id, user_id)
        if row is None:
            raise ScimError(404, f"user {user_id} not found")
        body = await request.json()
        if not body.get("userName"):
            raise ScimError(400, "userName is required", scim_type="invalidValue")
        fields = _user_fields_from(body, partial=False)
        fields["user_name"] = body["userName"]
        try:
            row = store.update_scim_user(tenant_id, user_id, fields)
        except sqlite3.IntegrityError as exc:
            raise ScimError(409, f"uniqueness violation: {exc}", scim_type="uniqueness") from exc
        return _user_resource(store, row)

    @router.delete("/Users/{user_id}")
    def delete_user(user_id: str, tenant_id: str = Depends(tenant_from_token)):
        if not store.delete_scim_user(tenant_id, user_id):
            raise ScimError(404, f"user {user_id} not found")
        return Response(status_code=204)

    # -- Groups -------------------------------------------------------------
    def _validated_member_ids(tenant_id: str, members) -> list[str]:
        ids = []
        for entry in members or []:
            user_id = entry.get("value") if isinstance(entry, dict) else None
            if not user_id or store.get_scim_user(tenant_id, user_id) is None:
                raise ScimError(400, f"member {user_id!r} is not a user in this tenant", scim_type="invalidValue")
            ids.append(user_id)
        return ids

    @router.post("/Groups", status_code=201)
    async def create_group(request: Request, tenant_id: str = Depends(tenant_from_token)):
        body = await request.json()
        display_name = body.get("displayName")
        if not display_name:
            raise ScimError(400, "displayName is required", scim_type="invalidValue")
        if store.get_scim_group_by_name(tenant_id, display_name):
            raise ScimError(409, f"displayName {display_name!r} already exists", scim_type="uniqueness")
        member_ids = _validated_member_ids(tenant_id, body.get("members"))
        row = store.create_scim_group(tenant_id, display_name)
        store.set_group_members(row["id"], member_ids)
        return JSONResponse(status_code=201, content=_group_resource(store, row))

    @router.get("/Groups")
    def list_groups(filter: str | None = None, tenant_id: str = Depends(tenant_from_token)):
        parsed = _parse_filter(filter, {"displayName"})
        rows = store.list_scim_groups(tenant_id)
        if parsed:
            rows = [r for r in rows if r["display_name"] == parsed[1]]
        return _list_response([_group_resource(store, r) for r in rows])

    @router.get("/Groups/{group_id}")
    def get_group(group_id: str, tenant_id: str = Depends(tenant_from_token)):
        row = store.get_scim_group(tenant_id, group_id)
        if row is None:
            raise ScimError(404, f"group {group_id} not found")
        return _group_resource(store, row)

    @router.patch("/Groups/{group_id}")
    async def patch_group(group_id: str, request: Request, tenant_id: str = Depends(tenant_from_token)):
        row = store.get_scim_group(tenant_id, group_id)
        if row is None:
            raise ScimError(404, f"group {group_id} not found")
        body = await request.json()
        for op in body.get("Operations", []):
            operation = str(op.get("op", "")).lower()
            path = op.get("path")
            value = op.get("value")
            if path == "displayName" and operation in {"add", "replace"}:
                store.update_scim_group(tenant_id, group_id, str(value))
            elif path == "members" and operation == "add":
                store.add_group_members(group_id, _validated_member_ids(tenant_id, value))
            elif path == "members" and operation == "replace":
                store.set_group_members(group_id, _validated_member_ids(tenant_id, value))
            elif path == "members" and operation == "remove":
                ids = [e.get("value") for e in (value or []) if isinstance(e, dict)]
                store.remove_group_members(group_id, ids)
            elif path and _MEMBER_PATH_RE.match(path) and operation == "remove":
                store.remove_group_members(group_id, [_MEMBER_PATH_RE.match(path).group(1)])
            else:
                raise ScimError(400, f"unsupported group patch: op={operation!r} path={path!r}", scim_type="noTarget")
        return _group_resource(store, store.get_scim_group(tenant_id, group_id))

    @router.put("/Groups/{group_id}")
    async def replace_group(group_id: str, request: Request, tenant_id: str = Depends(tenant_from_token)):
        row = store.get_scim_group(tenant_id, group_id)
        if row is None:
            raise ScimError(404, f"group {group_id} not found")
        body = await request.json()
        if not body.get("displayName"):
            raise ScimError(400, "displayName is required", scim_type="invalidValue")
        member_ids = _validated_member_ids(tenant_id, body.get("members"))
        store.update_scim_group(tenant_id, group_id, body["displayName"])
        store.set_group_members(group_id, member_ids)
        return _group_resource(store, store.get_scim_group(tenant_id, group_id))

    @router.delete("/Groups/{group_id}")
    def delete_group(group_id: str, tenant_id: str = Depends(tenant_from_token)):
        if not store.delete_scim_group(tenant_id, group_id):
            raise ScimError(404, f"group {group_id} not found")
        return Response(status_code=204)

    return router
