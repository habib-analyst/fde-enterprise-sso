# fde-enterprise-sso

An enterprise SSO integration layer for a multi-tenant SaaS: the identity
plumbing a Forward Deployed Engineer wires up when an enterprise customer
says "our people sign in through our IdP, accounts are provisioned from
our directory, and your roles must match our org." Four subsystems, all
running locally against fixture identity providers — no external network
calls, no real IdP, no real credentials.

## The four subsystems

**1. OAuth2 / OIDC with PKCE** (`oidc.py`)
A fixture identity provider (discovery document, `/authorize`, `/token`,
`/userinfo`) and the service-side client that consumes it.

- Authorization-code flow only; PKCE **S256 enforced** — `plain` or
  missing challenges/verifiers are rejected.
- Authorization codes are **single-use** with a 60-second expiry;
  replayed, expired, or redirect-mismatched codes fail at the token
  endpoint.
- `state` and `nonce` are required and verified; the client validates
  the ID token's signature, `iss`, `aud`, `exp` and `nonce` before any
  local session exists.
- HS256 JWTs are signed/verified with a small standard-library
  implementation (`jwtutil.py`), so the validation rules are explicit.

**2. SAML 2.0 response validation** (`saml.py`)
A parser/validator for signed fixture SAML responses plus a fixture
response builder. Unsigned, badly signed, expired, not-yet-valid,
wrong-issuer and wrong-audience assertions are all rejected before any
attribute is trusted. See *Scope honesty* below for exactly what the
signature is in this demo.

**3. SCIM 2.0 provisioning** (`scim.py`)
`POST/GET/PATCH/PUT/DELETE` for `/scim/v2/Users` and `/scim/v2/Groups`
with the SCIM error schema, `filter=userName eq "..."` support, group
membership operations, and deactivation via `active=false`. Each tenant
provisions with its own bearer token, and every query is constrained to
that tenant — another tenant's resources return the SCIM 404 error, not
data. Provisioning gates authentication: a user deactivated in SCIM can
no longer complete SSO sign-in (the login is refused as not found), and
reactivation restores it.

**4. Tenant-scoped RBAC** (`rbac.py`, enforced in `app.py`)
A permission matrix in code — 14 permissions across settings, members,
SSO, SCIM, billing and data — with four roles:

| Role | Access |
| --- | --- |
| owner | All 14 permissions |
| admin | All except `billing.write` |
| member | Read-only set + `data.write` |
| viewer | Read-only set |

Roles are granted **per tenant** through memberships and resolved from
the membership row on every request. A session scoped to tenant A is
refused by tenant B's routes, an admin of tenant B has no rights in
tenant A, and the same person can be owner of one tenant and viewer in
another — the tests pin all three behaviors, plus immediate effect of
role changes.

## Architecture

```
        fixture IdP app (oidc.py)            service app (app.py)
        /authorize  /token  /userinfo        /auth/login → /auth/callback
              │            ▲                 /scim/v2/Users|Groups
              └──── code ──┘  PKCE exchange  /tenants/{id}/... (RBAC)
                                                   │
                                    SQLite store (store.py)
                          tenants · users · memberships · auth codes
                          SCIM directory · per-tenant settings/data
```

State is SQLite (in-memory for tests, a file for the demo server), so
the full system runs anywhere Python does.

## How to run

```bash
pip install -r requirements.txt
python3 -m pytest tests/ -q     # 60 tests, all local, no network
python3 -m fde_sso.serve        # demo on http://127.0.0.1:8000
```

The demo server mounts the fixture IdP at `/idp` in the same process.
Start a login with `GET /auth/login?tenant_id=tenant-acme`, follow the
returned authorization URL against `/idp/authorize` (add
`&fixture_user=ada@acme.example` — the fixture IdP's stand-in for a login
form), then pass the returned `code` and `state` to `/auth/callback`.

Seeded fixtures: tenants `tenant-acme` and `tenant-globex`; users Ada
(owner in Acme, viewer in Globex), Alan (Acme member), Vera (Acme
viewer), Gina (Globex admin, no Acme membership); SCIM bearer tokens
`fixture-scim-token-acme` / `fixture-scim-token-globex`.

## Measured results

Verified in this repository's test suite (`python3 -m pytest tests/ -q`):
**60 passed, 0 failed** — 18 OIDC tests, 14 SCIM tests, 11 RBAC tests,
10 SAML tests, 7 JWT tests. Covered end to end:

- Full OIDC code + PKCE happy path, from authorization URL to a working
  RBAC-checked session.
- PKCE failure modes: `plain` method, missing challenge, missing or
  wrong verifier.
- Replayed code rejected; expired code rejected; wrong client secret
  rejected; unregistered redirect URI rejected; callback `state`
  mismatch rejected.
- ID tokens rejected at the client for wrong `aud`, wrong `iss`, wrong
  `nonce`, and past `exp`.
- SAML: valid fixture accepted; unsigned, empty-signature, wrong-key,
  tampered, expired, wrong-audience and wrong-issuer fixtures rejected.
- SCIM lifecycle: create → patch → deactivate (SSO login then refused,
  404) → delete (404 after), plus group membership add/remove and
  cross-tenant invisibility.
- RBAC matrix pinned exactly, enforced per role through the API, with
  cross-tenant denial in both directions.

## Scope honesty

- **Fixture IdP only.** The IdP is a local stand-in with users seeded in
  code and a `fixture_user` authorize parameter where a real IdP would
  show a login form. There is no integration with any production IdP.
- **SAML signature is an HMAC stand-in.** Assertions are signed with
  HMAC-SHA256 over a canonical rendering of the signed fields, keyed by a
  fixture secret. Real SAML requires XML-DSig verification (enveloped
  signatures, canonicalization, certificate trust) with a dedicated
  library; this module validates the same decision points — signature
  presence and correctness, issuer, audience, validity window — without
  claiming to be that library.
- **HS256 fixture secrets everywhere.** JWT signing uses shared fixture
  secrets (`fixture-*`) so both sides run in one process; production
  OIDC uses asymmetric keys and a published JWKS.
- **Fixture auth on the service itself.** SCIM bearer tokens and session
  shortcuts in the tests are synthetic values on the reserved `.example`
  domain space. Nothing here is a production credential, and no data is
  real.
