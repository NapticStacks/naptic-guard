# naptic-guard

**Audit, provision and test Amazon Bedrock Guardrails.**

`naptic-guard` checks the guardrails protecting your Bedrock agents against a
production-derived standard and tells you exactly what is missing: PII policies
that were never configured, prompt-injection filters that were never enabled,
credentials that are anonymized when they should be blocked.

Guardrails are the enforcement point for AI data governance, privacy and
information security on Bedrock. They are also easy to deploy half-configured
and never look at again.

## Install

```
pip install naptic-guard
```

## Use

Audit every guardrail in an account:

```
naptic-guard audit --profile my-profile --region us-east-1
```

```
  GAP  acme-prod-content-filter
         [NG001 HIGH] No sensitiveInformationPolicy configured. The guardrail
                      cannot anonymize or block PII in prompts or responses.
  OK   acme-prod-slack-bot-guardrail

1 of 2 guardrails meet the Naptic Standard.
  NG001: 1 guardrail(s)
```

Machine-readable output, and a CI gate:

```
naptic-guard audit --json
naptic-guard audit --fail-on-findings
```

Every AWS call `naptic-guard` makes is read-only.

## Checks

| Code | Severity | Check |
|---|---|---|
| NG001 | HIGH | A `sensitiveInformationPolicy` exists |
| NG002 | HIGH | A `PROMPT_ATTACK` content filter is enabled |
| NG003 | HIGH | Credentials and financial identifiers are `BLOCK`, not `ANONYMIZE` |

## The standard

The checks come from a guardrail running in production on a customer-facing
assistant, not from a whitepaper.

**Blocked outright** — `PASSWORD`, `US_SOCIAL_SECURITY_NUMBER`,
`CREDIT_DEBIT_CARD_NUMBER`, `CREDIT_DEBIT_CARD_CVV`, `AWS_SECRET_KEY`,
`AWS_ACCESS_KEY`. These are blocked rather than anonymized deliberately: a
stable token for a credential is a stable oracle for it.

**Anonymized** — `EMAIL`, `PHONE`, `ADDRESS`. Replaced in both input and output
so the model keeps conversational coherence without seeing the identifier.

**Deliberately not anonymized** — `NAME`. Anonymizing it breaks agents that
legitimately address people, and participant names are not the PII the policy
exists to protect.

## Development

```
python -m venv .venv && ./.venv/bin/pip install -e ".[dev]"
./.venv/bin/pytest
```

The policy logic in `audit.py` is pure functions over `GetGuardrail`-shaped
dicts, so it runs in CI with no AWS account and no mocks.

## License

MIT
