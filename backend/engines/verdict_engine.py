"""
CivicShield — Verdict Engine
Produces a final verdict from aggregated evidence.

Design principle:
  - Thresholds are loaded from rules/language_rules.yaml — configurable without code changes
  - Verdict is based on COUNTED evidence items, not fabricated probabilities
  - Reasoning is expressed in plain English for a non-technical citizen

Verdict options:
  "Likely Fraudulent"  — sufficient suspicious signals found
  "Likely Genuine"     — no significant suspicious signals + official domain confirmed
  "Unable to Verify"   — insufficient or conflicting evidence

IMPORTANT: The verdict is advisory, not certifying.
The mandatory disclaimer is always included in the response.
"""

from __future__ import annotations
import yaml
from pathlib import Path

from backend.models.schemas import EvidenceItem, AnalysisResult, UrlAnalysisResult

_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "language_rules.yaml"

with open(_RULES_PATH, "r", encoding="utf-8") as _f:
    _LANG_RULES = yaml.safe_load(_f)

_THRESHOLDS: dict = _LANG_RULES.get("verdict_thresholds", {})

# Configurable thresholds (sourced from YAML)
_FRAUD_HIGH_COUNT: int = _THRESHOLDS.get("fraudulent_high_count", 2)
_FRAUD_MED_COUNT: int = _THRESHOLDS.get("fraudulent_medium_count", 4)
_FRAUD_MIXED_MED: int = _THRESHOLDS.get("fraudulent_mixed_medium_with_high", 2)
_GENUINE_REQ_OFFICIAL: bool = _THRESHOLDS.get("genuine_requires_official_domain", True)
_GENUINE_REQ_ZERO_HIGH: bool = _THRESHOLDS.get("genuine_requires_zero_high", True)


def compute_verdict(
    evidence: list[EvidenceItem],
    url_analyses: list[UrlAnalysisResult],
    high_count: int,
    medium_count: int,
    low_count: int,
    input_type: str,
) -> tuple[str, str, str, list[str]]:
    """
    Compute the overall verdict.

    Returns:
        (verdict, risk_level, reasoning, recommended_actions)
    """

    # Collect per-URL risk signals
    url_high_risk = [u for u in url_analyses if u.risk_level == "HIGH"]
    url_medium_risk = [u for u in url_analyses if u.risk_level == "MEDIUM"]
    has_official_url = any(
        e.evidence_type == "DOMAIN_CHECK" and "official government whitelist" in e.explanation
        for e in evidence
    )
    has_official_url = has_official_url or any(
        u.features.get("is_official_domain", False) for u in url_analyses
    )

    # Aggregate URL risk into evidence counts
    effective_high = high_count + len(url_high_risk)
    effective_medium = medium_count + len(url_medium_risk)

    # ─── Verdict logic ───────────────────────────────────────────────────────

    verdict: str
    risk_level: str
    reasoning: str

    # Path 1: Clearly fraudulent
    if effective_high >= _FRAUD_HIGH_COUNT:
        verdict = "Likely Fraudulent"
        risk_level = "HIGH"
        reasoning = (
            f"Found {effective_high} HIGH-severity suspicious signal(s) "
            f"(threshold: {_FRAUD_HIGH_COUNT}). "
            "Multiple independent red flags strongly indicate this is a fraudulent communication."
        )

    elif effective_high == 1 and effective_medium >= _FRAUD_MIXED_MED:
        verdict = "Likely Fraudulent"
        risk_level = "HIGH"
        reasoning = (
            f"Found 1 HIGH-severity signal and {effective_medium} MEDIUM-severity signals. "
            "The combination of signals indicates a likely fraudulent communication."
        )

    elif effective_medium >= _FRAUD_MED_COUNT:
        verdict = "Likely Fraudulent"
        risk_level = "MEDIUM"
        reasoning = (
            f"Found {effective_medium} MEDIUM-severity suspicious signals "
            f"(threshold: {_FRAUD_MED_COUNT}). "
            "Multiple warning signs indicate this communication warrants serious caution."
        )

    # Path 2: Likely genuine
    elif (
        effective_high == 0
        and effective_medium <= 1
        and (has_official_url or not _GENUINE_REQ_OFFICIAL)
    ):
        verdict = "Likely Genuine"
        risk_level = "LOW"
        if has_official_url:
            reasoning = (
                "No high-severity suspicious signals were found and the URL points to "
                "an official Government of India domain. "
                "This is consistent with a genuine e-Challan communication. "
                "Always verify the challan number at echallan.parivahan.gov.in."
            )
        else:
            reasoning = (
                "No significant suspicious signals were found. "
                "However, no official government domain was confirmed. "
                "Please verify independently at echallan.parivahan.gov.in."
            )

    # Path 3: Unable to verify
    else:
        verdict = "Unable to Verify"
        risk_level = "MEDIUM" if (effective_high == 1 or effective_medium >= 2) else "LOW"
        reasoning = (
            f"Found {effective_high} HIGH and {effective_medium} MEDIUM-severity signals "
            "— insufficient to classify as clearly fraudulent or clearly genuine. "
            "Treat with caution and verify independently."
        )

    # ─── Recommended actions ─────────────────────────────────────────────────
    actions = _build_recommended_actions(verdict, evidence, url_analyses, has_official_url)

    return verdict, risk_level, reasoning, actions


def _build_recommended_actions(
    verdict: str,
    evidence: list[EvidenceItem],
    url_analyses: list[UrlAnalysisResult],
    has_official_url: bool,
) -> list[str]:
    """Build context-appropriate recommended actions for the citizen."""
    actions: list[str] = []

    # Always include official verification
    actions.append(
        "Verify any challan number at the official portal: https://echallan.parivahan.gov.in/ "
        "— you will need only the challan number or vehicle registration number."
    )

    if verdict == "Likely Fraudulent":
        actions += [
            "Do NOT click any links in this message.",
            "Do NOT download any files or APKs mentioned in this message.",
            "Do NOT share any OTP, password, or personal details.",
            "Do NOT make any payment through links in this message — use the official portal only.",
            "Report this fraudulent message to the National Cyber Crime Reporting Portal: https://cybercrime.gov.in/",
            "Forward suspicious messages to 1930 (National Cyber Crime Helpline).",
        ]
    elif verdict == "Likely Genuine":
        actions += [
            "Cross-verify the challan details at https://echallan.parivahan.gov.in/ before paying.",
            "Pay only through the official portal — do not pay via UPI IDs sent in messages.",
        ]
    else:  # Unable to Verify
        actions += [
            "Exercise caution — do not click links or pay until you have verified independently.",
            "Visit https://echallan.parivahan.gov.in/ to check if a challan exists for your vehicle.",
            "If uncertain, contact your nearest RTO office in person.",
        ]

    # Context-specific additions
    has_apk_risk = any(
        e.rule_id == "APK_DOWNLOAD_REQUEST" for e in evidence
    )
    if has_apk_risk:
        actions.append(
            "CRITICAL: Do not download or install any app/APK file from this message. "
            "Installing unknown APKs can compromise your device and financial accounts."
        )

    has_upi_risk = any(e.rule_id == "UPI_PAYMENT_REQUEST" for e in evidence)
    if has_upi_risk:
        actions.append(
            "Do NOT pay to the UPI ID in this message. "
            "Use only the official payment gateway at https://echallan.parivahan.gov.in/"
        )

    return actions
