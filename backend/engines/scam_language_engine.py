"""
CivicShield — Scam Language Engine
Detects general scam/phishing language patterns in message text.

Loads rules from rules/language_rules.yaml (scam_rules section).
Separate from the e-Challan Rule Engine so each can be maintained independently.
"""

from __future__ import annotations
import yaml
from pathlib import Path

from backend.models.schemas import EvidenceItem

_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "language_rules.yaml"

with open(_RULES_PATH, "r", encoding="utf-8") as _f:
    _LANG_RULES = yaml.safe_load(_f)

_SCAM_RULES: list[dict] = _LANG_RULES.get("scam_rules", [])


def analyze_scam_language(text: str) -> list[EvidenceItem]:
    """
    Scan text for general scam/social-engineering language patterns.

    Returns a list of EvidenceItems, one per matched rule.
    Rules are collapsed — if a rule fires on multiple patterns in the
    same text, it is still only reported once.
    """
    if not text:
        return []

    text_lower = text.lower()
    evidence: list[EvidenceItem] = []
    seen_rule_ids: set[str] = set()

    for rule in _SCAM_RULES:
        rule_id: str = rule["id"]
        if rule_id in seen_rule_ids:
            continue

        patterns: list[str] = rule.get("patterns", [])
        matched = [p for p in patterns if p.lower() in text_lower]

        if matched:
            seen_rule_ids.add(rule_id)
            sample = matched[:3]
            quoted = ", ".join(f'"{p}"' for p in sample)
            evidence.append(EvidenceItem(
                evidence_type="LANGUAGE_SIGNAL",
                finding=_build_finding(rule_id, sample),
                severity=rule["severity"],
                explanation=rule["explanation"].strip(),
                source="scam_language_engine",
                rule_id=rule_id,
            ))

    return evidence


def _build_finding(rule_id: str, matched: list[str]) -> str:
    labels = {
        "SECRECY_INSTRUCTION": "Message instructs recipient to keep information secret",
        "PRIZE_REWARD_CLAIM": "Message claims recipient has won a prize or reward",
        "ACCOUNT_SUSPENSION_THREAT": "Message threatens account/service suspension",
        "SUSPICIOUS_CALL_TO_ACTION": "Message uses credential-harvesting call-to-action",
        "URGENCY_LANGUAGE": "Message uses urgency-inducing language",
    }
    base = labels.get(rule_id, f"Scam pattern '{rule_id}' detected")
    quoted = ", ".join(f'"{p}"' for p in matched)
    return f"{base} — matched: {quoted}"
