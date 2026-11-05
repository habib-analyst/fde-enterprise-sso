"""Run the local demo: the service app with the fixture IdP mounted at /idp,
both sharing one seeded SQLite store in a single process.

    python3 -m fde_sso.serve            # http://127.0.0.1:8000

Try: GET /auth/login?tenant_id=tenant-acme, then complete the flow with
curl against /idp/authorize (add &fixture_user=ada@acme.example), then
/auth/callback. Everything is local; no network calls leave the process.
"""

from __future__ import annotations

import os

import uvicorn

from .app import create_service_app
from .fixtures import seed_store
from .oidc import create_idp_app
from .store import Store


def build_demo_app(db_path: str = "fde_sso_demo.db"):
    store = seed_store(Store(db_path))
    app = create_service_app(store)
    app.mount("/idp", create_idp_app(store))
    return app


def main() -> None:
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(build_demo_app(), host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()
