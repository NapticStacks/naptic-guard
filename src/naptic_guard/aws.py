"""Thin read-only boto3 layer.

Deliberately minimal: every policy decision lives in `audit.py` as pure
functions so it can be tested without AWS. This module only fetches.
All calls here are read-only.
"""
from __future__ import annotations

import boto3


def fetch_guardrails(profile: str | None = None, region: str | None = None) -> list[dict]:
    """Return the full DRAFT configuration of every guardrail in the account."""
    session = boto3.Session(profile_name=profile, region_name=region)
    client = session.client("bedrock")

    summaries: list[dict] = []
    token = None
    while True:
        page = client.list_guardrails(**({"nextToken": token} if token else {}))
        summaries.extend(page.get("guardrails", []))
        token = page.get("nextToken")
        if not token:
            break

    configs = []
    for summary in summaries:
        detail = client.get_guardrail(
            guardrailIdentifier=summary["id"], guardrailVersion="DRAFT"
        )
        detail.pop("ResponseMetadata", None)
        configs.append(detail)
    return configs
