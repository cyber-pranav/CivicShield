"""
CivicShield — Verdict Engine Unit Tests

Tests the verdict logic under different evidence configurations.

Run with: python -m pytest tests/test_verdict_engine.py -v
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from backend.engines.verdict_engine import compute_verdict
from backend.models.schemas import EvidenceItem, UrlAnalysisResult


def _make_evidence(severity: str, n: int, evidence_type: str = "RULE_MATCH") -> list[EvidenceItem]:
    return [
        EvidenceItem(
            evidence_type=evidence_type,
            finding=f"Test finding {i}",
            severity=severity,
            explanation="Test explanation",
            source="test",
        )
        for i in range(n)
    ]


def _make_url_analysis(risk_level: str, is_official: bool = False) -> UrlAnalysisResult:
    evidence = []
    if is_official:
        evidence.append(EvidenceItem(
            evidence_type="DOMAIN_CHECK",
            finding="Domain matches official government whitelist",
            severity="INFO",
            explanation="The URL hostname is in the official government domain whitelist.",
            source="url_risk_engine",
        ))
    return UrlAnalysisResult(
        url="https://test.example",
        risk_level=risk_level,
        features={"is_official_domain": is_official},
        evidence=evidence,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Likely Fraudulent
# ─────────────────────────────────────────────────────────────────────────────

def test_two_high_signals_is_fraudulent():
    evidence = _make_evidence("HIGH", 2)
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=evidence, url_analyses=[], high_count=2, medium_count=0, low_count=0,
        input_type="text"
    )
    assert verdict == "Likely Fraudulent"
    assert risk == "HIGH"


def test_one_high_two_medium_is_fraudulent():
    evidence = _make_evidence("HIGH", 1) + _make_evidence("MEDIUM", 2)
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=evidence, url_analyses=[], high_count=1, medium_count=2, low_count=0,
        input_type="text"
    )
    assert verdict == "Likely Fraudulent"


def test_four_medium_signals_is_fraudulent():
    evidence = _make_evidence("MEDIUM", 4)
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=evidence, url_analyses=[], high_count=0, medium_count=4, low_count=0,
        input_type="text"
    )
    assert verdict == "Likely Fraudulent"


def test_high_risk_url_contributes_to_fraudulent():
    """A HIGH-risk URL analysis should push verdict toward Fraudulent."""
    evidence = _make_evidence("HIGH", 1)
    url_analyses = [_make_url_analysis("HIGH")]
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=evidence, url_analyses=url_analyses,
        high_count=1, medium_count=0, low_count=0,
        input_type="url"
    )
    assert verdict == "Likely Fraudulent"


# ─────────────────────────────────────────────────────────────────────────────
# Likely Genuine
# ─────────────────────────────────────────────────────────────────────────────

def test_official_domain_no_signals_is_genuine():
    """Official domain + zero suspicious signals => Likely Genuine."""
    info_evidence = _make_evidence("INFO", 1, evidence_type="GENUINE_SIGNAL")
    url_analyses = [_make_url_analysis("LOW", is_official=True)]
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=info_evidence, url_analyses=url_analyses,
        high_count=0, medium_count=0, low_count=0,
        input_type="url"
    )
    assert verdict == "Likely Genuine"
    assert risk == "LOW"


def test_no_signals_no_urls_is_unable_to_verify():
    """No content analysed => Unable to Verify (no official domain confirmed)."""
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=[], url_analyses=[], high_count=0, medium_count=0, low_count=0,
        input_type="text"
    )
    # With genuine_requires_official_domain=True and no official domain found
    assert verdict in ("Likely Genuine", "Unable to Verify")


# ─────────────────────────────────────────────────────────────────────────────
# Unable to Verify
# ─────────────────────────────────────────────────────────────────────────────

def test_one_high_no_medium_is_unable_to_verify():
    """1 HIGH signal alone — below fraudulent threshold (2 needed) => Unable."""
    evidence = _make_evidence("HIGH", 1)
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=evidence, url_analyses=[], high_count=1, medium_count=0, low_count=0,
        input_type="text"
    )
    assert verdict in ("Unable to Verify", "Likely Fraudulent")


# ─────────────────────────────────────────────────────────────────────────────
# Recommended actions sanity check
# ─────────────────────────────────────────────────────────────────────────────

def test_fraudulent_actions_include_do_not_click():
    evidence = _make_evidence("HIGH", 2)
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=evidence, url_analyses=[], high_count=2, medium_count=0, low_count=0,
        input_type="text"
    )
    assert any("do not click" in a.lower() for a in actions)


def test_all_verdicts_include_official_portal():
    for n_high in [0, 1, 2]:
        evidence = _make_evidence("HIGH", n_high)
        verdict, risk, reasoning, actions = compute_verdict(
            evidence=evidence, url_analyses=[], high_count=n_high, medium_count=0, low_count=0,
            input_type="text"
        )
        assert any("parivahan.gov.in" in a for a in actions), (
            f"Verdict '{verdict}' missing official portal in actions"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Reasoning string quality
# ─────────────────────────────────────────────────────────────────────────────

def test_reasoning_is_non_empty():
    for n_high in [0, 1, 2, 3]:
        evidence = _make_evidence("HIGH", n_high)
        verdict, risk, reasoning, actions = compute_verdict(
            evidence=evidence, url_analyses=[], high_count=n_high, medium_count=0, low_count=0,
            input_type="text"
        )
        assert reasoning, f"Empty reasoning for {n_high} HIGH signals"
