# Launch note — fde-enterprise-sso (20-point pre-launch checklist)

1. **Tests green** — PASS: `python3 -m pytest tests/ -q` → 60 passed, 0 failed (18 OIDC, 14 SCIM, 11 RBAC, 10 SAML, 7 JWT).
2. **No real secrets** — PASS: every credential value is an obviously synthetic `fixture-*` constant in `config.py` (IdP/service signing secrets, client secret, SAML key, SCIM tokens); grep-verified.
3. **No private/personal data** — PASS: tenants, users and emails are invented fixtures on the reserved `.example` TLD.
4. **No payment integration** — PASS: billing is a per-tenant key/value record behind an RBAC permission; no payment provider code or calls exist.
5. **Free tier only / $0 cost** — PASS: Python stdlib plus already-installed open-source packages (FastAPI, pydantic, uvicorn); no paid service used or required.
6. **No network calls at runtime or in tests** — PASS: the IdP and service run in-process; tests use FastAPI TestClient; issuer URLs are identifiers only.
7. **Deterministic fixtures** — PASS: seeded tenants, users, memberships and directory rows are fixed constants in `fixtures.py`; random values (codes, state, ids) are never asserted literally.
8. **README verified against reality** — PASS: every number in the README (60 tests and the per-file split, 14 permissions, role table) was measured or read from the code in this build session.
9. **README free of internal process language** — PASS: public-facing wording only; no staging/pipeline references.
10. **No binary files** — PASS: source and Markdown only; `.gitignore` excludes caches and local DB files; whole tree is ~340 KB including caches.
11. **Cross-tenant isolation tested** — PASS: SCIM cross-tenant GET/PATCH/DELETE return 404; RBAC cross-tenant sessions and foreign-tenant admins are denied (403) in tests.
12. **Auth failure modes tested** — PASS: PKCE plain/missing/wrong verifier, replayed and expired codes, wrong client secret, bad redirect URI, state mismatch, tampered/expired/wrong-aud/wrong-iss/wrong-nonce ID tokens, forged session tokens — all rejected in tests.
13. **SAML validation failure modes tested** — PASS: unsigned, empty signature, wrong key, tampered NameID, expired, wrong audience, wrong issuer and malformed XML all rejected.
14. **Deactivation path tested end to end** — PASS: SCIM `active=false` on a seeded user makes the subsequent OIDC login return 404; covered in `test_scim.py`.
15. **Scope honesty documented** — PASS: README states plainly that the IdP is a fixture, the SAML signature is an HMAC stand-in for XML-DSig, and JWT signing uses shared fixture HS256 secrets — no production IdP integration is claimed.
16. **License/attribution** — N/A: no third-party code is vendored; dependencies are standard open-source packages declared in `pyproject.toml`.
17. **No external submissions made** — PASS: local build only; nothing pushed, published or sent anywhere.
18. **Error behavior is leak-safe** — PASS: cross-tenant SCIM ids return 404 (not 403), so resource existence never leaks between tenants; auth errors carry no directory details.
19. **Demo runs standalone** — PASS: `python3 -m fde_sso.serve` builds a seeded app with the fixture IdP mounted at `/idp`; health, discovery and SCIM auth behavior verified against the built app.
20. **Reproducible from a clean checkout** — PASS: `pip install -r requirements.txt` plus the documented pytest/uvicorn commands reproduce everything; the default test run needs no database server or network.

Verdict: all items PASS or N/A with reason. Cleared for the ship lane.
