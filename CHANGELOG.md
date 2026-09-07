# Changelog

All notable changes to `naptic-guard` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-06

First public release.

### Added
- `naptic-guard audit` — audits every Amazon Bedrock guardrail in an AWS account
  against the Naptic Standard. All AWS calls are read-only.
- **NG001** — flags a guardrail with no `sensitiveInformationPolicy`, meaning it
  cannot anonymize or block PII in prompts or responses.
- **NG002** — flags a missing `PROMPT_ATTACK` content filter, meaning no defense
  against prompt injection or jailbreak attempts.
- **NG003** — flags a PII policy that fails to `BLOCK` credentials and financial
  identifiers. `ANONYMIZE` is insufficient for these: a stable token for a
  credential is a stable oracle for it.
- `--json` for machine-readable output and `--fail-on-findings` for use as a CI gate.

### Notes
The standard is derived from a guardrail running in production on a
customer-facing assistant, not from a whitepaper. Policy logic is pure functions
over `GetGuardrail`-shaped dicts, so the test suite runs with no AWS account and
no mocks.
