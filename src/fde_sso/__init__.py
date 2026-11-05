"""fde-enterprise-sso: enterprise SSO integration layer for a multi-tenant SaaS.

Four subsystems, all running locally against fixture identity providers:

- OAuth2/OIDC authorization-code flow with PKCE (fixture IdP + client).
- SAML 2.0 response validation on signed fixture XML (HMAC stand-in for
  XML-DSig — see saml.py and the README scope notes).
- SCIM 2.0 provisioning endpoints, scoped per tenant.
- Tenant-scoped RBAC with a permission matrix enforced per tenant.

Every secret, token, user and tenant in here is an invented fixture.
"""

__version__ = "0.1.0"
