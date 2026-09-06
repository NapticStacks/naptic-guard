"""naptic-guard command line interface."""
from __future__ import annotations

import json
import sys

import click

from naptic_guard.audit import audit_fleet

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@click.group()
@click.version_option(package_name="naptic-guard")
def main() -> None:
    """Audit, provision and test Amazon Bedrock Guardrails."""


@main.command()
@click.option("--profile", default=None, help="AWS profile name.")
@click.option("--region", default=None, help="AWS region.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of a table.")
@click.option(
    "--fail-on-findings",
    is_flag=True,
    help="Exit non-zero when any guardrail has a finding. Use this in CI.",
)
def audit(profile: str | None, region: str | None, as_json: bool, fail_on_findings: bool) -> None:
    """Audit every Bedrock guardrail in an account against the Naptic Standard."""
    from naptic_guard.aws import fetch_guardrails

    configs = fetch_guardrails(profile=profile, region=region)
    report = audit_fleet(configs)

    if as_json:
        click.echo(
            json.dumps(
                {
                    "total": report.total,
                    "clean": report.clean,
                    "counts": report.counts,
                    "results": [
                        {
                            "name": r.name,
                            "findings": [
                                {"code": f.code, "severity": f.severity, "message": f.message}
                                for f in r.findings
                            ],
                        }
                        for r in report.results
                    ],
                },
                indent=2,
            )
        )
    else:
        for result in report.results:
            if not result.findings:
                click.echo(f"  OK   {result.name}")
                continue
            click.echo(f"  GAP  {result.name}")
            for finding in sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9)):
                click.echo(f"         [{finding.code} {finding.severity}] {finding.message}")
        click.echo("")
        click.echo(f"{report.clean} of {report.total} guardrails meet the Naptic Standard.")
        for code, n in sorted(report.counts.items()):
            click.echo(f"  {code}: {n} guardrail(s)")

    if fail_on_findings and report.clean < report.total:
        sys.exit(1)
