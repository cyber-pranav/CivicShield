"""
CivicShield — Verdict Engine Unit Tests

Strict test suite for deterministic verdict precedence, exact risk levels,
and zero double-counting of URL risk.
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
# Precedence Tests: Exact assertions
# ─────────────────────────────────────────────────────────────────────────────

def test_two_high_signals_is_fraudulent():
    """CASE 7: Two HIGH signals -> Likely Fraudulent, HIGH."""
    evidence = _make_evidence("HIGH", 2)
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=evidence, url_analyses=[], high_count=2, medium_count=0, low_count=0,
        input_type="text"
    )
    assert verdict == "Likely Fraudulent"
    assert risk == "HIGH"


def test_one_high_two_medium_is_fraudulent():
    """CASE 8: One HIGH + mixed MEDIUM threshold (>= 2) -> Likely Fraudulent, HIGH."""
    evidence = _make_evidence("HIGH", 1) + _make_evidence("MEDIUM", 2)
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=evidence, url_analyses=[], high_count=1, medium_count=2, low_count=0,
        input_type="text"
    )
    assert verdict == "Likely Fraudulent"
    assert risk == "HIGH"


def test_four_medium_signals_is_fraudulent():
    """CASE 9: Four MEDIUM signals and zero HIGH -> Likely Fraudulent, MEDIUM."""
    evidence = _make_evidence("MEDIUM", 4)
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=evidence, url_analyses=[], high_count=0, medium_count=4, low_count=0,
        input_type="text"
    )
    assert verdict == "Likely Fraudulent"
    assert risk == "MEDIUM"


def test_url_risk_not_double_counted_regression():
    """
    P0 Regression Test:
    If one URL produces exactly one HIGH evidence item and its URL risk_level is HIGH,
    the verdict engine must see exactly ONE HIGH signal, not two.
    With one HIGH signal and zero MEDIUM, the verdict must be 'Unable to Verify',
    NEVER 'Likely Fraudulent'.
    """
    evidence = _make_evidence("HIGH", 1)
    url_analyses = [_make_url_analysis("HIGH")]
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=evidence, url_analyses=url_analyses,
        high_count=1, medium_count=0, low_count=0,
        input_type="url"
    )
    assert verdict == "Unable to Verify"
    assert risk == "MEDIUM"


def test_official_domain_no_signals_is_genuine():
    """CASE 1: Official domain + zero suspicious signals => Likely Genuine, LOW."""
    info_evidence = _make_evidence("INFO", 1, evidence_type="GENUINE_SIGNAL")
    url_analyses = [_make_url_analysis("LOW", is_official=True)]
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=info_evidence, url_analyses=url_analyses,
        high_count=0, medium_count=0, low_count=0,
        input_type="url"
    )
    assert verdict == "Likely Genuine"
    assert risk == "LOW"


def test_official_domain_one_medium_is_genuine():
    """Official domain + 1 MEDIUM signal => Likely Genuine with explanation."""
    evidence = _make_evidence("MEDIUM", 1)
    url_analyses = [_make_url_analysis("LOW", is_official=True)]
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=evidence, url_analyses=url_analyses,
        high_count=0, medium_count=1, low_count=0,
        input_type="url"
    )
    assert verdict == "Likely Genuine"
    assert risk == "LOW"
    assert "advisory indicator" in reasoning.lower()


def test_no_signals_no_urls_is_unable_to_verify():
    """CASE 10: No suspicious signals + no official domain => Unable to Verify, LOW."""
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=[], url_analyses=[], high_count=0, medium_count=0, low_count=0,
        input_type="text"
    )
    assert verdict == "Unable to Verify"
    assert risk == "LOW"


def test_one_high_no_medium_is_unable_to_verify():
    """CASE 6: 1 HIGH signal alone => Unable to Verify, MEDIUM."""
    evidence = _make_evidence("HIGH", 1)
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=evidence, url_analyses=[], high_count=1, medium_count=0, low_count=0,
        input_type="text"
    )
    assert verdict == "Unable to Verify"
    assert risk == "MEDIUM"


def test_official_domain_with_high_evidence_never_genuine():
    """CASE 11: Official domain + HIGH suspicious signal => NEVER Likely Genuine."""
    evidence = _make_evidence("HIGH", 2)
    url_analyses = [_make_url_analysis("LOW", is_official=True)]
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=evidence, url_analyses=url_analyses,
        high_count=2, medium_count=0, low_count=0,
        input_type="text"
    )
    assert verdict == "Likely Fraudulent"
    assert risk == "HIGH"


def test_official_domain_with_one_high_unable_to_verify():
    """Official domain + 1 HIGH signal => Unable to Verify, never Likely Genuine."""
    evidence = _make_evidence("HIGH", 1)
    url_analyses = [_make_url_analysis("LOW", is_official=True)]
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=evidence, url_analyses=url_analyses,
        high_count=1, medium_count=0, low_count=0,
        input_type="text"
    )
    assert verdict == "Unable to Verify"
    assert risk == "MEDIUM"


# ─────────────────────────────────────────────────────────────────────────────
# Recommended Actions & Reasoning Quality
# ─────────────────────────────────────────────────────────────────────────────

def test_fraudulent_actions_include_do_not_click():
    evidence = _make_evidence("HIGH", 2)
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=evidence, url_analyses=[], high_count=2, medium_count=0, low_count=0,
        input_type="text"
    )
    assert any("do not click" in a.lower() for a in actions)


def test_all_verdicts_include_official_portal():
    for n_high, n_med in [(0, 0), (1, 0), (2, 0), (0, 4)]:
        evidence = _make_evidence("HIGH", n_high) + _make_evidence("MEDIUM", n_med)
        verdict, risk, reasoning, actions = compute_verdict(
            evidence=evidence, url_analyses=[], high_count=n_high, medium_count=n_med, low_count=0,
            input_type="text"
        )
        assert any("parivahan.gov.in" in a for a in actions), (
            f"Verdict '{verdict}' missing official portal in actions"
        )


def test_reasoning_is_non_empty():
    for n_high in [0, 1, 2, 3]:
        evidence = _make_evidence("HIGH", n_high)
        verdict, risk, reasoning, actions = compute_verdict(
            evidence=evidence, url_analyses=[], high_count=n_high, medium_count=0, low_count=0,
            input_type="text"
        )
        assert reasoning, f"Empty reasoning for {n_high} HIGH signals"
