"""
CivicShield — Category Detector Tests
Unit tests for backend/engines/category_detector.py
"""

import pytest
from backend.engines.category_detector import detect_category
from backend.models.schemas import EvidenceItem, UrlAnalysisResult


def _make_evidence(source: str, rule_id: str = "TEST_RULE") -> EvidenceItem:
    """Helper to build a minimal EvidenceItem."""
    return EvidenceItem(
        evidence_type="RULE_MATCH",
        finding="test finding",
        severity="HIGH",
        explanation="test explanation",
        source=source,
        rule_id=rule_id,
    )


def _make_url_analysis(is_official: bool) -> UrlAnalysisResult:
    """Helper to build a minimal UrlAnalysisResult."""
    return UrlAnalysisResult(
        url="https://example.com",
        risk_level="LOW" if is_official else "UNKNOWN",
        features={"is_official_domain": is_official},
        evidence=[],
    )


# ─── Priority 1: Challan evidence → government_notice ────────────────────────

def test_challan_evidence_yields_government_notice():
    """When challan rules fire, category is always government_notice."""
    challan_ev = [_make_evidence("challan_rule_engine")]
    result = detect_category(challan_ev, [], [])
    assert result == "government_notice"


def test_challan_evidence_overrides_scam_evidence():
    """When both challan and scam evidence fire, challan takes priority."""
    challan_ev = [_make_evidence("challan_rule_engine")]
    scam_ev = [_make_evidence("scam_language_engine")]
    result = detect_category(challan_ev, scam_ev, [])
    assert result == "government_notice"


# ─── Priority 2: Official domain → government_notice ─────────────────────────

def test_official_domain_yields_government_notice():
    """When an official government domain is detected, category is government_notice."""
    url_analyses = [_make_url_analysis(is_official=True)]
    result = detect_category([], [], url_analyses)
    assert result == "government_notice"


def test_official_domain_overrides_scam_evidence():
    """Official domain + scam evidence still yields government_notice."""
    scam_ev = [_make_evidence("scam_language_engine")]
    url_analyses = [_make_url_analysis(is_official=True)]
    result = detect_category([], scam_ev, url_analyses)
    assert result == "government_notice"


# ─── Priority 3: Scam-only evidence → generic_phishing ───────────────────────

def test_scam_only_evidence_yields_generic_phishing():
    """When only scam language rules fire, category is generic_phishing."""
    scam_ev = [_make_evidence("scam_language_engine")]
    result = detect_category([], scam_ev, [])
    assert result == "generic_phishing"


def test_scam_evidence_with_non_official_url_yields_generic_phishing():
    """Scam evidence + non-official URL = generic_phishing."""
    scam_ev = [_make_evidence("scam_language_engine")]
    url_analyses = [_make_url_analysis(is_official=False)]
    result = detect_category([], scam_ev, url_analyses)
    assert result == "generic_phishing"


# ─── Default: no evidence → government_notice (conservative) ─────────────────

def test_no_evidence_defaults_to_government_notice():
    """When no evidence fires at all, conservative default is government_notice."""
    result = detect_category([], [], [])
    assert result == "government_notice"


def test_non_official_url_no_rules_defaults_to_government_notice():
    """Non-official URL without any rule matches defaults to government_notice."""
    url_analyses = [_make_url_analysis(is_official=False)]
    result = detect_category([], [], url_analyses)
    assert result == "government_notice"


# ─── Schema: new fields have correct defaults ────────────────────────────────

def test_analysis_result_has_detected_category_default():
    """AnalysisResult.detected_category defaults to 'government_notice'."""
    from backend.models.schemas import AnalysisResult
    result = AnalysisResult(
        verdict="Unable to Verify",
        risk_level="LOW",
        evidence=[],
        verdict_reasoning="test",
    )
    assert result.detected_category == "government_notice"


def test_analysis_result_has_official_verification_urls_default():
    """AnalysisResult.official_verification_urls defaults to Parivahan portal."""
    from backend.models.schemas import AnalysisResult
    result = AnalysisResult(
        verdict="Unable to Verify",
        risk_level="LOW",
        evidence=[],
        verdict_reasoning="test",
    )
    assert isinstance(result.official_verification_urls, list)
    assert "https://echallan.parivahan.gov.in/" in result.official_verification_urls


def test_analysis_result_backward_compat_singular_url():
    """AnalysisResult.official_verification_url (singular) still exists."""
    from backend.models.schemas import AnalysisResult
    result = AnalysisResult(
        verdict="Unable to Verify",
        risk_level="LOW",
        evidence=[],
        verdict_reasoning="test",
    )
    assert result.official_verification_url == "https://echallan.parivahan.gov.in/"


# ─── Verdict engine: category-aware reasoning ────────────────────────────────

def test_verdict_engine_accepts_category_param():
    """compute_verdict should accept category and official_urls without error."""
    from backend.engines.verdict_engine import compute_verdict
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=[],
        url_analyses=[],
        high_count=0,
        medium_count=0,
        low_count=0,
        input_type="text",
        category="generic_phishing",
        official_urls=["https://cybercrime.gov.in/"],
    )
    assert verdict in ("Likely Genuine", "Likely Fraudulent", "Unable to Verify")
    assert "cybercrime.gov.in" in reasoning or "cybercrime.gov.in" in " ".join(actions)


def test_verdict_default_category_includes_parivahan():
    """Default category (government_notice) should reference Parivahan in actions."""
    from backend.engines.verdict_engine import compute_verdict
    verdict, risk, reasoning, actions = compute_verdict(
        evidence=[],
        url_analyses=[],
        high_count=0,
        medium_count=0,
        low_count=0,
        input_type="text",
    )
    actions_text = " ".join(actions)
    assert "echallan.parivahan.gov.in" in actions_text


# ─── URL rules: expanded official domains ─────────────────────────────────────

def test_new_official_domains_recognised():
    """Expanded official domain list should recognise new government portals."""
    from backend.engines.url_features import is_official_gov_domain
    assert is_official_gov_domain("india.gov.in")
    assert is_official_gov_domain("cybercrime.gov.in")
    assert is_official_gov_domain("digilocker.gov.in")
    assert is_official_gov_domain("uidai.gov.in")
    assert is_official_gov_domain("indiapost.gov.in")
    # Existing domains still work
    assert is_official_gov_domain("echallan.parivahan.gov.in")
    assert is_official_gov_domain("parivahan.gov.in")


def test_new_official_domains_subdomains():
    """Subdomains of new official domains should also be recognised."""
    from backend.engines.url_features import is_official_gov_domain
    assert is_official_gov_domain("resident.uidai.gov.in")
    assert is_official_gov_domain("track.indiapost.gov.in")


def test_fake_new_domains_not_recognised():
    """Impersonation of new official domains should NOT be recognised."""
    from backend.engines.url_features import is_official_gov_domain
    assert not is_official_gov_domain("india.gov.in.evil.com")
    assert not is_official_gov_domain("fakecybercrime.gov.in")
