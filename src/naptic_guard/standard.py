"""The Naptic Bedrock Guardrail Standard.

Derived from the production Standard tier deployed on
`naptic-prod-slack-bot-guardrail`. Each requirement below is in force on a
live, customer-facing guardrail, not aspirational.
"""
from __future__ import annotations

# Credentials and financial identifiers are BLOCKed rather than anonymized.
# A stable token for a credential is a stable oracle for it.
REQUIRED_BLOCK_ENTITIES: tuple[str, ...] = (
    "PASSWORD",
    "US_SOCIAL_SECURITY_NUMBER",
    "CREDIT_DEBIT_CARD_NUMBER",
    "CREDIT_DEBIT_CARD_CVV",
    "AWS_SECRET_KEY",
    "AWS_ACCESS_KEY",
)

# Contact details are anonymized in both input and output, so the model keeps
# conversational coherence without seeing the identifier.
RECOMMENDED_ANONYMIZE_ENTITIES: tuple[str, ...] = (
    "EMAIL",
    "PHONE",
    "ADDRESS",
)

# NAME is deliberately excluded. Anonymizing it breaks agent conversations that
# legitimately address participants, and participant names are not the PII the
# policy exists to protect.

REQUIRED_CONTENT_FILTERS: tuple[str, ...] = ("PROMPT_ATTACK",)

CONTEXTUAL_GROUNDING_THRESHOLD = 0.7
