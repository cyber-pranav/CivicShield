"""
CivicShield — Category Detector
Determines the most likely communication category from fired rules.

This is a pure function — deterministic, no side effects, easy to test.

Category priority:
  1. If any challan_rule_engine rule fired  →  "government_notice"
  2. If an official govt domain was detected →  "government_notice"
  3. If only scam_language_engine rules fired → "generic_phishing"
  4. Default                                 → "government_notice" (conservative)

Future categories (banking, delivery, etc.) will add priority checks
between steps 2 and 3 as new rule sections are introduced.
"""

from __future__ import annotations

from backend.models.schemas import EvidenceItem, UrlAnalysisResult


def detect_category(
    challan_evidence: list[EvidenceItem],
    scam_evidence: list[EvidenceItem],
    url_analyses: list[UrlAnalysisResult],
) -> str:
    """
    Determine the most likely communication category based on fired rules
    and URL analysis results.

    Returns one of:
      "government_notice"  — traffic/RTO/government notice indicators detected
      "generic_phishing"   — only general scam language indicators detected
    """

    # Priority 1: Challan/RTO-specific rules fired
    if challan_evidence:
        return "government_notice"

    # Priority 2: Official government domain confirmed in URL analysis
    has_official = any(
        u.features.get("is_official_domain", False) for u in url_analyses
    )
    if has_official:
        return "government_notice"

    # Priority 3: Only general scam signals
    if scam_evidence:
        return "generic_phishing"

    # Default: conservative — treat as government notice
    return "government_notice"
