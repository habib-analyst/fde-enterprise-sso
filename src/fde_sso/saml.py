"""SAML 2.0 response parsing and validation (fixture scope).

Scope honesty: this module validates the parts of a SAML response that
carry the security decisions — presence and correctness of the assertion
signature, issuer, audience restriction, and the validity window — on
signed fixture XML produced by `build_saml_response`.

The signature here is an HMAC-SHA256 over a canonical rendering of the
assertion's signed fields, keyed with a fixture secret. That is a
**stand-in for XML-DSig**: production SAML validation must verify real
XML digital signatures (enveloped signature, canonicalization, certificate
trust) with a dedicated library. The validation *shape* — reject unsigned,
badly signed, expired, not-yet-valid, wrong-issuer and wrong-audience
assertions before trusting any attribute — is the same.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

from .config import SAML_IDP_ENTITY_ID, SAML_SIGNING_KEY, SP_ENTITY_ID

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}

_TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"


class SamlError(Exception):
    """Base class for SAML validation failures."""


class MissingSignature(SamlError):
    pass


class BadSignature(SamlError):
    pass


class ExpiredAssertion(SamlError):
    pass


class NotYetValid(SamlError):
    pass


class WrongAudience(SamlError):
    pass


class WrongIssuer(SamlError):
    pass


@dataclass
class SamlIdentity:
    name_id: str
    issuer: str
    audience: str
    attributes: dict = field(default_factory=dict)


def _canonical(assertion_id: str, issuer: str, name_id: str, audience: str, not_on_or_after: str) -> str:
    return "|".join([assertion_id, issuer, name_id, audience, not_on_or_after])


def _sign(canonical: str, key: str) -> str:
    digest = hmac.new(key.encode(), canonical.encode(), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def _fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(_TIME_FMT)


def build_saml_response(
    *,
    name_id: str = "ada@acme.example",
    issuer: str = SAML_IDP_ENTITY_ID,
    audience: str = SP_ENTITY_ID,
    attributes: dict | None = None,
    signing_key: str = SAML_SIGNING_KEY,
    now: datetime | None = None,
    lifetime_seconds: int = 300,
    sign: bool = True,
) -> str:
    """Build a signed fixture SAML response (the fixture IdP side)."""
    now = now or datetime.now(timezone.utc)
    assertion_id = "_fixture-" + secrets.token_hex(8)
    not_before = _fmt(now - timedelta(seconds=30))
    not_on_or_after = _fmt(now + timedelta(seconds=lifetime_seconds))
    attributes = attributes or {"email": name_id, "tenant_id": "tenant-acme"}
    attr_xml = "".join(
        f'<saml:Attribute Name="{escape(k)}">'
        f"<saml:AttributeValue>{escape(str(v))}</saml:AttributeValue>"
        f"</saml:Attribute>"
        for k, v in attributes.items()
    )
    signature_value = ""
    if sign:
        signature_value = _sign(
            _canonical(assertion_id, issuer, name_id, audience, not_on_or_after),
            signing_key,
        )
    signature_xml = (
        f"<ds:Signature><ds:SignatureValue>{signature_value}</ds:SignatureValue></ds:Signature>"
        if sign
        else ""
    )
    return (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
        f'ID="_resp-{assertion_id}" Version="2.0" IssueInstant="{_fmt(now)}">'
        f"<saml:Issuer>{escape(issuer)}</saml:Issuer>"
        f'<saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="{_fmt(now)}">'
        f"<saml:Issuer>{escape(issuer)}</saml:Issuer>"
        f"{signature_xml}"
        "<saml:Subject>"
        f"<saml:NameID>{escape(name_id)}</saml:NameID>"
        "</saml:Subject>"
        f'<saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">'
        "<saml:AudienceRestriction>"
        f"<saml:Audience>{escape(audience)}</saml:Audience>"
        "</saml:AudienceRestriction>"
        "</saml:Conditions>"
        f"<saml:AttributeStatement>{attr_xml}</saml:AttributeStatement>"
        "</saml:Assertion>"
        "</samlp:Response>"
    )


def _find(parent, path: str):
    el = parent.find(path, NS)
    if el is None:
        raise SamlError(f"missing element: {path}")
    return el


def validate_saml_response(
    xml_text: str,
    *,
    expected_audience: str = SP_ENTITY_ID,
    expected_issuer: str = SAML_IDP_ENTITY_ID,
    signing_key: str = SAML_SIGNING_KEY,
    now: datetime | None = None,
) -> SamlIdentity:
    """Validate a fixture SAML response; return the asserted identity.

    Raises a SamlError subclass on any failure — unsigned, badly signed,
    expired, not-yet-valid, wrong issuer or wrong audience.
    """
    now = now or datetime.now(timezone.utc)
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise SamlError(f"unparseable XML: {exc}") from exc
    assertion = _find(root, "saml:Assertion")

    signature_el = assertion.find("ds:Signature/ds:SignatureValue", NS)
    if signature_el is None or not (signature_el.text or "").strip():
        raise MissingSignature("assertion carries no signature")
    presented = signature_el.text.strip()

    issuer = _find(assertion, "saml:Issuer").text or ""
    name_id = _find(assertion, "saml:Subject/saml:NameID").text or ""
    conditions = _find(assertion, "saml:Conditions")
    not_before_raw = conditions.get("NotBefore", "")
    not_on_or_after_raw = conditions.get("NotOnOrAfter", "")
    audience = _find(
        assertion, "saml:Conditions/saml:AudienceRestriction/saml:Audience"
    ).text or ""

    expected_signature = _sign(
        _canonical(assertion.get("ID", ""), issuer, name_id, audience, not_on_or_after_raw),
        signing_key,
    )
    if not hmac.compare_digest(expected_signature, presented):
        raise BadSignature("assertion signature does not verify")

    if issuer != expected_issuer:
        raise WrongIssuer(f"issuer {issuer!r} != {expected_issuer!r}")
    if audience != expected_audience:
        raise WrongAudience(f"audience {audience!r} != {expected_audience!r}")

    not_on_or_after = datetime.strptime(not_on_or_after_raw, _TIME_FMT).replace(
        tzinfo=timezone.utc
    )
    if now >= not_on_or_after:
        raise ExpiredAssertion(f"assertion expired at {not_on_or_after_raw}")
    if not_before_raw:
        not_before = datetime.strptime(not_before_raw, _TIME_FMT).replace(
            tzinfo=timezone.utc
        )
        if now < not_before:
            raise NotYetValid(f"assertion not valid before {not_before_raw}")

    attributes = {}
    statement = assertion.find("saml:AttributeStatement", NS)
    if statement is not None:
        for attr in statement.findall("saml:Attribute", NS):
            value_el = attr.find("saml:AttributeValue", NS)
            attributes[attr.get("Name", "")] = (
                value_el.text if value_el is not None else ""
            )
    return SamlIdentity(
        name_id=name_id, issuer=issuer, audience=audience, attributes=attributes
    )
