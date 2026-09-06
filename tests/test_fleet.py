"""Aggregate audit results across every guardrail in an account."""
from naptic_guard.audit import audit_fleet


COMPLIANT_PII = [
    {"type": "PASSWORD", "action": "BLOCK"},
    {"type": "US_SOCIAL_SECURITY_NUMBER", "action": "BLOCK"},
    {"type": "CREDIT_DEBIT_CARD_NUMBER", "action": "BLOCK"},
    {"type": "CREDIT_DEBIT_CARD_CVV", "action": "BLOCK"},
    {"type": "AWS_SECRET_KEY", "action": "BLOCK"},
    {"type": "AWS_ACCESS_KEY", "action": "BLOCK"},
]
PROMPT_ATTACK = {"contentPolicy": {"filters": [{"type": "PROMPT_ATTACK"}]}}


def test_reports_which_guardrails_have_findings():
    configs = [
        {"name": "healthy", **PROMPT_ATTACK,
         "sensitiveInformationPolicy": {"piiEntities": COMPLIANT_PII}},
        {"name": "no-pii", **PROMPT_ATTACK},
    ]

    report = audit_fleet(configs)

    assert report.total == 2
    assert report.clean == 1
    assert [r.name for r in report.results if r.findings] == ["no-pii"]


def test_counts_guardrails_by_finding_code():
    configs = [
        {"name": "a", **PROMPT_ATTACK},
        {"name": "b", **PROMPT_ATTACK},
        {"name": "c", "contentPolicy": {"filters": []},
         "sensitiveInformationPolicy": {"piiEntities": COMPLIANT_PII}},
    ]

    report = audit_fleet(configs)

    assert report.counts["NG001"] == 2
    assert report.counts["NG002"] == 1
