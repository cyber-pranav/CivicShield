"""
CivicShield — e-Challan Rule Engine
Applies e-Challan and RTO-specific rule-based checks to extracted text.

Rules are loaded from rules/language_rules.yaml at startup.
Every match produces a structured EvidenceItem with a rule_id for traceability.

This engine is separate from the general Scam Language Engine so that
e-Challan-specific logic can be audited and updated independently.
"""

from __future__ import annotations
import yaml
from pathlib import Path

from backend.models.schemas import EvidenceItem

# ─────────────────────────────────────────────────────────────────────────────
# Load rules at module startup
# ─────────────────────────────────────────────────────────────────────────────

_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "language_rules.yaml"

with open(_RULES_PATH, "r", encoding="utf-8") as _f:
    _LANG_RULES = yaml.safe_load(_f)

_CHALLAN_RULES: list[dict] = _LANG_RULES.get("challan_rules", [])
_GENUINE_SIGNALS: list[dict] = _LANG_RULES.get("genuine_signals", [])


def analyze_challan_text(text: str) -> list[EvidenceItem]:
    """
    Scan text for e-Challan and RTO-specific suspicious patterns.

    Args:
        text: Extracted text from the submitted document or message.

    Returns:
        List of EvidenceItem — one per matched rule (not per match occurrence).
        Duplicate rule matches are collapsed into one item.
    """
    if not text:
        return []

    text_lower = text.lower()
    evidence: list[EvidenceItem] = []
    seen_rule_ids: set[str] = set()

    # ── Check suspicious challan rules ───────────────────────────────────────
    for rule in _CHALLAN_RULES:
        rule_id: str = rule["id"]
        if rule_id in seen_rule_ids:
            continue

        patterns: list[str] = rule.get("patterns", [])
        matched_patterns = [p for p in patterns if p.lower() in text_lower]

        if matched_patterns:
            seen_rule_ids.add(rule_id)
            # Show at most 3 matched patterns in the finding to keep it readable
            sample = matched_patterns[:3]
            evidence.append(EvidenceItem(
                evidence_type="RULE_MATCH",
                finding=_build_finding(rule_id, sample),
                severity=rule["severity"],
                explanation=rule["explanation"].strip(),
                source="challan_rule_engine",
                rule_id=rule_id,
            ))

    # ── Check genuine signals ─────────────────────────────────────────────────
    for rule in _GENUINE_SIGNALS:
        rule_id = rule["id"]
        if rule_id in seen_rule_ids:
            continue

        patterns = rule.get("patterns", [])
        matched_patterns = [p for p in patterns if p.lower() in text_lower]

        if matched_patterns:
            seen_rule_ids.add(rule_id)
            evidence.append(EvidenceItem(
                evidence_type="GENUINE_SIGNAL",
                finding=_build_genuine_finding(rule_id, matched_patterns[:2]),
                severity="INFO",
                explanation=rule["explanation"].strip(),
                source="challan_rule_engine",
                rule_id=rule_id,
            ))

    return evidence


def _build_finding(rule_id: str, matched: list[str]) -> str:
    """Construct a human-readable finding string from a matched rule."""
    labels = {
        "APK_DOWNLOAD_REQUEST": "Message requests APK / app download",
        "OTP_CREDENTIAL_REQUEST": "Message requests OTP or credentials",
        "UPI_PAYMENT_REQUEST": "Message contains a UPI payment request",
        "ARREST_THREAT": "Message contains arrest / legal-action threat",
        "LICENSE_SUSPENSION_THREAT": "Message threatens license/vehicle suspension",
        "URGENT_PAYMENT_DEADLINE": "Message creates urgent payment pressure",
        "INCREASED_PENALTY_THREAT": "Message threatens escalating financial penalties",
        "CHALLAN_IMPERSONATION": "Message uses e-Challan / RTO terminology",
    }
    base = labels.get(rule_id, f"Rule '{rule_id}' matched")
    quoted = ", ".join(f'"{p}"' for p in matched)
    return f"{base} — matched: {quoted}"


def _build_genuine_finding(rule_id: str, matched: list[str]) -> str:
    labels = {
        "OFFICIAL_PORTAL_REFERENCE": "Message references an official government portal",
        "CHALLAN_NUMBER_FORMAT": "Message includes a challan number / offence code reference",
    }
    base = labels.get(rule_id, f"Genuine signal '{rule_id}' found")
    quoted = ", ".join(f'"{p}"' for p in matched)
    return f"{base} — found: {quoted}"
