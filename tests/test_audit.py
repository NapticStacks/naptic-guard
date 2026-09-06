"""Audit a deployed Bedrock guardrail config against the Naptic Standard."""
from naptic_guard.audit import audit_guardrail


def _guardrail(**overrides):
    """A minimal GetGuardrail-shaped response. Content filters only, no PII policy.

    This mirrors what 12 of the 14 guardrails in naptic-prod actually look like.
    """
    base = {
        "name": "example-content-filter",
        "contentPolicy": {
            "filters": [
                {"type": "PROMPT_ATTACK", "inputStrength": "HIGH", "outputStrength": "NONE"},
                {"type": "HATE", "inputStrength": "HIGH", "outputStrength": "HIGH"},
            ]
        },
    }
    base.update(overrides)
    return base


def test_flags_guardrail_with_no_pii_policy():
    findings = audit_guardrail(_guardrail())

    codes = [f.code for f in findings]
    assert "NG001" in codes

    pii = next(f for f in findings if f.code == "NG001")
    assert pii.severity == "HIGH"
    assert "sensitiveInformationPolicy" in pii.message


def test_flags_guardrail_missing_prompt_attack_filter():
    """aer-pilates-prod-outbound in naptic-prod has exactly this gap."""
    no_prompt_attack = _guardrail(
        contentPolicy={
            "filters": [
                {"type": "HATE", "inputStrength": "HIGH", "outputStrength": "HIGH"},
                {"type": "SEXUAL", "inputStrength": "HIGH", "outputStrength": "HIGH"},
            ]
        }
    )

    findings = audit_guardrail(no_prompt_attack)

    prompt = next(f for f in findings if f.code == "NG002")
    assert prompt.severity == "HIGH"
    assert "PROMPT_ATTACK" in prompt.message


def test_does_not_flag_prompt_attack_when_present():
    findings = audit_guardrail(_guardrail())

    assert "NG002" not in [f.code for f in findings]


def test_flags_pii_policy_missing_required_block_entities():
    """The Naptic Standard BLOCKs credentials and financial identifiers.

    ANONYMIZE is not sufficient for these: a stable token for a credential is a
    stable oracle for it.
    """
    anonymize_only = _guardrail(
        sensitiveInformationPolicy={
            "piiEntities": [
                {"type": "EMAIL", "action": "ANONYMIZE"},
                {"type": "PHONE", "action": "ANONYMIZE"},
            ]
        }
    )

    findings = audit_guardrail(anonymize_only)

    missing = next(f for f in findings if f.code == "NG003")
    assert missing.severity == "HIGH"
    for entity in ("US_SOCIAL_SECURITY_NUMBER", "AWS_SECRET_KEY", "PASSWORD"):
        assert entity in missing.message


def test_accepts_pii_policy_meeting_the_standard():
    compliant = _guardrail(
        sensitiveInformationPolicy={
            "piiEntities": [
                {"type": "EMAIL", "action": "ANONYMIZE"},
                {"type": "PHONE", "action": "ANONYMIZE"},
                {"type": "ADDRESS", "action": "ANONYMIZE"},
                {"type": "PASSWORD", "action": "BLOCK"},
                {"type": "US_SOCIAL_SECURITY_NUMBER", "action": "BLOCK"},
                {"type": "CREDIT_DEBIT_CARD_NUMBER", "action": "BLOCK"},
                {"type": "CREDIT_DEBIT_CARD_CVV", "action": "BLOCK"},
                {"type": "AWS_SECRET_KEY", "action": "BLOCK"},
                {"type": "AWS_ACCESS_KEY", "action": "BLOCK"},
            ]
        }
    )

    codes = [f.code for f in audit_guardrail(compliant)]
    assert "NG001" not in codes
    assert "NG003" not in codes
