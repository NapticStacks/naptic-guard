"""Audit Bedrock guardrail configurations against the Naptic Standard.

Pure functions over GetGuardrail-shaped dicts. No AWS calls, no I/O, so the
policy logic is testable offline and the same code paths run in CI.
"""
from __future__ import annotations

from dataclasses import dataclass

from naptic_guard.standard import REQUIRED_BLOCK_ENTITIES


@dataclass(frozen=True)
class Finding:
    """A single policy gap found in a guardrail configuration."""

    code: str
    severity: str
    message: str


def audit_guardrail(config: dict) -> list[Finding]:
    """Compare one guardrail config against the Naptic Standard."""
    findings: list[Finding] = []

    pii = config.get("sensitiveInformationPolicy", {}).get("piiEntities", [])
    if not pii:
        findings.append(
            Finding(
                code="NG001",
                severity="HIGH",
                message=(
                    "No sensitiveInformationPolicy configured. The guardrail cannot "
                    "anonymize or block PII in prompts or responses."
                ),
            )
        )

    else:
        blocked = {e.get("type") for e in pii if e.get("action") == "BLOCK"}
        absent = [e for e in REQUIRED_BLOCK_ENTITIES if e not in blocked]
        if absent:
            findings.append(
                Finding(
                    code="NG003",
                    severity="HIGH",
                    message=(
                        "PII policy does not BLOCK required entities: "
                        + ", ".join(absent)
                    ),
                )
            )

    filters = config.get("contentPolicy", {}).get("filters", [])
    if not any(f.get("type") == "PROMPT_ATTACK" for f in filters):
        findings.append(
            Finding(
                code="NG002",
                severity="HIGH",
                message=(
                    "No PROMPT_ATTACK content filter. The guardrail does not defend "
                    "against prompt injection or jailbreak attempts."
                ),
            )
        )

    return findings


@dataclass(frozen=True)
class GuardrailResult:
    """Findings for one guardrail."""

    name: str
    findings: list[Finding]


@dataclass(frozen=True)
class FleetReport:
    """Audit outcome across every guardrail in an account."""

    results: list[GuardrailResult]

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def clean(self) -> int:
        return sum(1 for r in self.results if not r.findings)

    @property
    def counts(self) -> dict[str, int]:
        tally: dict[str, int] = {}
        for result in self.results:
            for finding in result.findings:
                tally[finding.code] = tally.get(finding.code, 0) + 1
        return tally


def audit_fleet(configs: list[dict]) -> FleetReport:
    """Audit every guardrail config and summarize."""
    return FleetReport(
        results=[
            GuardrailResult(name=c.get("name", "<unnamed>"), findings=audit_guardrail(c))
            for c in configs
        ]
    )
