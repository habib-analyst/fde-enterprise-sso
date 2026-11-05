from datetime import datetime, timedelta, timezone

import pytest

from fde_sso.saml import (
    BadSignature,
    ExpiredAssertion,
    MissingSignature,
    WrongAudience,
    WrongIssuer,
    build_saml_response,
    validate_saml_response,
)


def test_valid_response_accepted():
    xml = build_saml_response(attributes={"email": "ada@acme.example", "tenant_id": "tenant-acme"})
    identity = validate_saml_response(xml)
    assert identity.name_id == "ada@acme.example"
    assert identity.attributes["tenant_id"] == "tenant-acme"


def test_unsigned_response_rejected():
    xml = build_saml_response(sign=False)
    with pytest.raises(MissingSignature):
        validate_saml_response(xml)


def test_empty_signature_rejected():
    signed = build_saml_response()
    start = signed.index("<ds:SignatureValue>") + len("<ds:SignatureValue>")
    end = signed.index("</ds:SignatureValue>")
    blanked = signed[:start] + signed[end:]
    with pytest.raises(MissingSignature):
        validate_saml_response(blanked)


def test_wrong_signing_key_rejected():
    xml = build_saml_response(signing_key="fixture-wrong-key")
    with pytest.raises(BadSignature):
        validate_saml_response(xml)


def test_tampered_name_id_rejected():
    xml = build_saml_response(name_id="ada@acme.example")
    tampered = xml.replace("ada@acme.example", "mallory@acme.example", 1)
    # The NameID occurs in Subject and the default email attribute; replacing
    # only the first occurrence (Subject) breaks the signature either way.
    with pytest.raises(BadSignature):
        validate_saml_response(tampered)


def test_expired_assertion_rejected():
    past = datetime.now(timezone.utc) - timedelta(minutes=10)
    xml = build_saml_response(now=past, lifetime_seconds=60)
    with pytest.raises(ExpiredAssertion):
        validate_saml_response(xml)


def test_wrong_audience_rejected():
    xml = build_saml_response(audience="https://other-sp.fixture.example/saml")
    with pytest.raises(WrongAudience):
        validate_saml_response(xml)


def test_wrong_issuer_rejected():
    xml = build_saml_response(issuer="https://evil-idp.fixture.example/saml")
    with pytest.raises(WrongIssuer):
        validate_saml_response(xml)


def test_garbage_xml_rejected():
    with pytest.raises(Exception):
        validate_saml_response("<not-xml")


def test_service_saml_endpoint(service):
    xml = build_saml_response()
    ok = service.post("/saml/validate", json={"saml_response": xml})
    assert ok.status_code == 200
    assert ok.json()["name_id"] == "ada@acme.example"

    bad = service.post(
        "/saml/validate", json={"saml_response": build_saml_response(sign=False)}
    )
    assert bad.status_code == 400
    assert "MissingSignature" in bad.json()["detail"]
