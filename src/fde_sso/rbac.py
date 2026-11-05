"""Tenant-scoped role-based access control.

The permission matrix lives here, in code, as data. Roles are granted
per tenant through memberships: the same person can be owner of one
tenant and a read-only viewer in another, and a grant in one tenant
confers nothing in any other. Enforcement (see app.py) resolves the
caller's role from the membership row for the *requested* tenant on
every request, so role changes take effect immediately and a session
token scoped to tenant A is worthless against tenant B's routes.
"""

from __future__ import annotations

PERMISSIONS = (
    "tenant.settings.read",
    "tenant.settings.write",
    "members.read",
    "members.invite",
    "members.remove",
    "sso.read",
    "sso.configure",
    "scim.read",
    "scim.provision",
    "billing.read",
    "billing.write",
    "data.read",
    "data.write",
    "data.delete",
)

_READ_ONLY = frozenset(
    {
        "tenant.settings.read",
        "members.read",
        "sso.read",
        "scim.read",
        "data.read",
    }
)

ROLE_PERMISSIONS: dict[str, frozenset] = {
    # Owner: everything, including billing changes.
    "owner": frozenset(PERMISSIONS),
    # Admin: everything except changing billing.
    "admin": frozenset(PERMISSIONS) - {"billing.write"},
    # Member: works with data and can read configuration, but cannot
    # manage people, SSO, provisioning or billing.
    "member": _READ_ONLY | {"data.write"},
    # Viewer: read-only.
    "viewer": _READ_ONLY,
}

ROLES = tuple(ROLE_PERMISSIONS)


def has_permission(role: str | None, permission: str) -> bool:
    if role is None:
        return False
    return permission in ROLE_PERMISSIONS.get(role, frozenset())
