"""SQLite-backed state for the SSO service.

One store holds everything the demo needs: tenants, global users (the
RBAC principals), per-tenant memberships, single-use authorization codes,
SCIM-provisioned directory users and groups, and small per-tenant key/value
records (settings, SSO config, billing plan) plus tenant data rows.

SQLite keeps the whole system portable and testable with no server; the
access patterns here (lookup by tenant-scoped key) are the same ones a
Postgres deployment would use.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memberships (
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
);
CREATE TABLE IF NOT EXISTS auth_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    nonce TEXT NOT NULL,
    idp_user TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    expires_at REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS scim_users (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_name TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    external_id TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    UNIQUE (tenant_id, user_name)
);
CREATE TABLE IF NOT EXISTS scim_groups (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    UNIQUE (tenant_id, display_name)
);
CREATE TABLE IF NOT EXISTS scim_group_members (
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    PRIMARY KEY (group_id, user_id)
);
CREATE TABLE IF NOT EXISTS tenant_kv (
    tenant_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (tenant_id, key)
);
CREATE TABLE IF NOT EXISTS tenant_data (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    body TEXT NOT NULL
);
"""


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


class Store:
    def __init__(self, path: str = ":memory:"):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- low-level helpers --------------------------------------------------
    def _execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def _query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, params))

    def _query_one(self, sql: str, params: tuple = ()):
        rows = self._query(sql, params)
        return rows[0] if rows else None

    # -- tenants / users / memberships --------------------------------------
    def add_tenant(self, tenant_id: str, name: str) -> None:
        self._execute(
            "INSERT OR IGNORE INTO tenants (id, name) VALUES (?, ?)",
            (tenant_id, name),
        )

    def add_user(self, user_id: str, email: str, name: str) -> None:
        self._execute(
            "INSERT OR IGNORE INTO users (id, email, name) VALUES (?, ?, ?)",
            (user_id, email, name),
        )

    def get_user(self, user_id: str):
        return self._query_one("SELECT * FROM users WHERE id = ?", (user_id,))

    def get_user_by_email(self, email: str):
        return self._query_one("SELECT * FROM users WHERE email = ?", (email,))

    def set_membership(self, tenant_id: str, user_id: str, role: str) -> None:
        self._execute(
            "INSERT INTO memberships (tenant_id, user_id, role) VALUES (?, ?, ?) "
            "ON CONFLICT (tenant_id, user_id) DO UPDATE SET role = excluded.role",
            (tenant_id, user_id, role),
        )

    def get_membership(self, tenant_id: str, user_id: str):
        return self._query_one(
            "SELECT * FROM memberships WHERE tenant_id = ? AND user_id = ?",
            (tenant_id, user_id),
        )

    def list_memberships(self, tenant_id: str) -> list:
        return self._query(
            "SELECT m.user_id, m.role, u.email, u.name FROM memberships m "
            "JOIN users u ON u.id = m.user_id WHERE m.tenant_id = ? "
            "ORDER BY u.email",
            (tenant_id,),
        )

    def delete_membership(self, tenant_id: str, user_id: str) -> bool:
        cur = self._execute(
            "DELETE FROM memberships WHERE tenant_id = ? AND user_id = ?",
            (tenant_id, user_id),
        )
        return cur.rowcount > 0

    # -- authorization codes --------------------------------------------------
    def save_auth_code(self, record: dict) -> None:
        self._execute(
            "INSERT INTO auth_codes (code, client_id, redirect_uri, "
            "code_challenge, nonce, idp_user, tenant_id, expires_at, used) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
            (
                record["code"],
                record["client_id"],
                record["redirect_uri"],
                record["code_challenge"],
                record["nonce"],
                record["idp_user"],
                record["tenant_id"],
                record["expires_at"],
            ),
        )

    def get_auth_code(self, code: str):
        return self._query_one(
            "SELECT * FROM auth_codes WHERE code = ?", (code,)
        )

    def mark_auth_code_used(self, code: str) -> None:
        self._execute(
            "UPDATE auth_codes SET used = 1 WHERE code = ?", (code,)
        )

    # -- SCIM directory -------------------------------------------------------
    def create_scim_user(self, tenant_id: str, fields: dict) -> dict:
        user_id = new_id("u")
        self._execute(
            "INSERT INTO scim_users (id, tenant_id, user_name, display_name, "
            "email, external_id, active) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                user_id,
                tenant_id,
                fields["user_name"],
                fields.get("display_name", ""),
                fields.get("email", ""),
                fields.get("external_id"),
                1 if fields.get("active", True) else 0,
            ),
        )
        return self.get_scim_user(tenant_id, user_id)

    def get_scim_user(self, tenant_id: str, user_id: str):
        return self._query_one(
            "SELECT * FROM scim_users WHERE tenant_id = ? AND id = ?",
            (tenant_id, user_id),
        )

    def get_scim_user_by_username(self, tenant_id: str, user_name: str):
        return self._query_one(
            "SELECT * FROM scim_users WHERE tenant_id = ? AND user_name = ?",
            (tenant_id, user_name),
        )

    def list_scim_users(self, tenant_id: str) -> list:
        return self._query(
            "SELECT * FROM scim_users WHERE tenant_id = ? ORDER BY user_name",
            (tenant_id,),
        )

    def update_scim_user(self, tenant_id: str, user_id: str, fields: dict):
        allowed = {"user_name", "display_name", "email", "external_id", "active"}
        sets = {k: v for k, v in fields.items() if k in allowed}
        if not sets:
            return self.get_scim_user(tenant_id, user_id)
        if "active" in sets:
            sets["active"] = 1 if sets["active"] else 0
        clause = ", ".join(f"{k} = ?" for k in sets)
        self._execute(
            f"UPDATE scim_users SET {clause} WHERE tenant_id = ? AND id = ?",
            (*sets.values(), tenant_id, user_id),
        )
        return self.get_scim_user(tenant_id, user_id)

    def delete_scim_user(self, tenant_id: str, user_id: str) -> bool:
        self._execute(
            "DELETE FROM scim_group_members WHERE user_id = ?", (user_id,)
        )
        cur = self._execute(
            "DELETE FROM scim_users WHERE tenant_id = ? AND id = ?",
            (tenant_id, user_id),
        )
        return cur.rowcount > 0

    def create_scim_group(self, tenant_id: str, display_name: str) -> dict:
        group_id = new_id("g")
        self._execute(
            "INSERT INTO scim_groups (id, tenant_id, display_name) "
            "VALUES (?, ?, ?)",
            (group_id, tenant_id, display_name),
        )
        return self.get_scim_group(tenant_id, group_id)

    def get_scim_group(self, tenant_id: str, group_id: str):
        return self._query_one(
            "SELECT * FROM scim_groups WHERE tenant_id = ? AND id = ?",
            (tenant_id, group_id),
        )

    def get_scim_group_by_name(self, tenant_id: str, display_name: str):
        return self._query_one(
            "SELECT * FROM scim_groups WHERE tenant_id = ? AND display_name = ?",
            (tenant_id, display_name),
        )

    def list_scim_groups(self, tenant_id: str) -> list:
        return self._query(
            "SELECT * FROM scim_groups WHERE tenant_id = ? ORDER BY display_name",
            (tenant_id,),
        )

    def update_scim_group(self, tenant_id: str, group_id: str, display_name: str):
        self._execute(
            "UPDATE scim_groups SET display_name = ? "
            "WHERE tenant_id = ? AND id = ?",
            (display_name, tenant_id, group_id),
        )
        return self.get_scim_group(tenant_id, group_id)

    def delete_scim_group(self, tenant_id: str, group_id: str) -> bool:
        self._execute(
            "DELETE FROM scim_group_members WHERE group_id = ?", (group_id,)
        )
        cur = self._execute(
            "DELETE FROM scim_groups WHERE tenant_id = ? AND id = ?",
            (tenant_id, group_id),
        )
        return cur.rowcount > 0

    def group_member_ids(self, group_id: str) -> list[str]:
        rows = self._query(
            "SELECT user_id FROM scim_group_members WHERE group_id = ? "
            "ORDER BY user_id",
            (group_id,),
        )
        return [r["user_id"] for r in rows]

    def set_group_members(self, group_id: str, user_ids: list[str]) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM scim_group_members WHERE group_id = ?", (group_id,)
            )
            self._conn.executemany(
                "INSERT OR IGNORE INTO scim_group_members (group_id, user_id) "
                "VALUES (?, ?)",
                [(group_id, uid) for uid in user_ids],
            )
            self._conn.commit()

    def add_group_members(self, group_id: str, user_ids: list[str]) -> None:
        with self._lock:
            self._conn.executemany(
                "INSERT OR IGNORE INTO scim_group_members (group_id, user_id) "
                "VALUES (?, ?)",
                [(group_id, uid) for uid in user_ids],
            )
            self._conn.commit()

    def remove_group_members(self, group_id: str, user_ids: list[str]) -> None:
        with self._lock:
            self._conn.executemany(
                "DELETE FROM scim_group_members WHERE group_id = ? AND user_id = ?",
                [(group_id, uid) for uid in user_ids],
            )
            self._conn.commit()

    # -- per-tenant key/value (settings, sso config, billing) -----------------
    def get_kv(self, tenant_id: str, key: str, default=None):
        row = self._query_one(
            "SELECT value FROM tenant_kv WHERE tenant_id = ? AND key = ?",
            (tenant_id, key),
        )
        return json.loads(row["value"]) if row else default

    def set_kv(self, tenant_id: str, key: str, value) -> None:
        self._execute(
            "INSERT INTO tenant_kv (tenant_id, key, value) VALUES (?, ?, ?) "
            "ON CONFLICT (tenant_id, key) DO UPDATE SET value = excluded.value",
            (tenant_id, key, json.dumps(value)),
        )

    # -- tenant data rows (RBAC demo resource) --------------------------------
    def add_data(self, tenant_id: str, body: str) -> str:
        data_id = new_id("d")
        self._execute(
            "INSERT INTO tenant_data (id, tenant_id, body) VALUES (?, ?, ?)",
            (data_id, tenant_id, body),
        )
        return data_id

    def list_data(self, tenant_id: str) -> list:
        return self._query(
            "SELECT * FROM tenant_data WHERE tenant_id = ? ORDER BY id",
            (tenant_id,),
        )

    def delete_data(self, tenant_id: str, data_id: str) -> bool:
        cur = self._execute(
            "DELETE FROM tenant_data WHERE tenant_id = ? AND id = ?",
            (tenant_id, data_id),
        )
        return cur.rowcount > 0
