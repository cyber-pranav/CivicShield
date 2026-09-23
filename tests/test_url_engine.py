"""
CivicShield — URL Engine Unit Tests

Tests cover:
  - IP address detection
  - URL shortener detection
  - Suspicious TLD detection
  - Official domain recognition (PASS and FAIL cases)
  - Brand keyword impersonation
  - APK in URL detection
  - @ symbol detection
  - ML feature order consistency
  - URL extractor robustness

Run with: python -m pytest tests/test_url_engine.py -v
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from backend.engines.url_risk_engine import analyze_url
from backend.engines.url_extractor import extract_urls
from backend.engines.url_features import (
    URL_FEATURE_COLUMNS,
    is_official_gov_domain,
    extract_url_features,
)
from ml.url_model_loader import URL_FEATURE_COLUMNS as LOADER_FEATURE_COLUMNS
from backend.models.schemas import UrlAnalysisResult


def _severities(result: UrlAnalysisResult) -> list[str]:
    return [e.severity for e in result.evidence]


# ─────────────────────────────────────────────────────────────────────────────
# IP address as hostname
# ─────────────────────────────────────────────────────────────────────────────

def test_ip_address_url_is_high_risk():
    """CASE 2: Raw IP address -> Likely Fraudulent URL, HIGH."""
    result = analyze_url("http://192.168.1.1/echallan/pay")
    assert result.features["has_ip_host"] == 1
    assert "HIGH" in _severities(result)
    assert result.risk_level == "HIGH"


def test_normal_domain_not_flagged_as_ip():
    result = analyze_url("https://echallan.parivahan.gov.in/")
    assert result.features["has_ip_host"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# Official domain recognition (Section 4 Test Matrix)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "https://echallan.parivahan.gov.in/",
    "https://parivahan.gov.in/",
    "https://vahan.parivahan.gov.in/",
    "https://echallan.parivahan.gov.in:443/",
    "https://sarathi.parivahan.gov.in/sarathiservice/",
])
def test_official_domain_pass_cases(url):
    """PASS cases: Official portals must be confirmed as official."""
    result = analyze_url(url)
    assert result.features["is_official_domain"] is True
    assert result.risk_level == "LOW"


@pytest.mark.parametrize("url", [
    "https://echallan.parivahan.gov.in.evil.com/",
    "https://parivahan.gov.in.attacker.com/",
    "https://fakeparivahan.gov.in/",
    "https://echallan-parivahan.xyz/",
    "http://evil-parivahan.gov.in.example.com/",
])
def test_official_domain_fail_cases(url):
    """FAIL cases: Lookalikes and attacker suffixes must NOT be official."""
    result = analyze_url(url)
    assert result.features["is_official_domain"] is False
    assert result.risk_level != "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# URL shorteners
# ─────────────────────────────────────────────────────────────────────────────

def test_bitly_is_flagged():
    result = analyze_url("https://bit.ly/3XfakeLink")
    assert result.features["is_url_shortener"] == 1
    assert "HIGH" in _severities(result)


def test_tinyurl_is_flagged():
    result = analyze_url("https://tinyurl.com/fakechallan")
    assert result.features["is_url_shortener"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# Suspicious TLD
# ─────────────────────────────────────────────────────────────────────────────

def test_suspicious_tld_xyz():
    """CASE 4: Lookalike domain with .xyz TLD -> Likely Fraudulent, HIGH."""
    result = analyze_url("https://echallan-parivahan.xyz/pay")
    assert result.features["suspicious_tld"] == 1
    assert "HIGH" in _severities(result)
    assert result.risk_level == "HIGH"


def test_gov_in_not_suspicious_tld():
    result = analyze_url("https://parivahan.gov.in/")
    assert result.features["suspicious_tld"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# Brand keyword impersonation
# ─────────────────────────────────────────────────────────────────────────────

def test_brand_keyword_in_fake_domain():
    result = analyze_url("http://echallan-india.tk/payment")
    assert result.features["brand_keyword_in_domain"] == 1
    assert "HIGH" in _severities(result)


def test_brand_keyword_in_official_domain_not_flagged():
    result = analyze_url("https://echallan.parivahan.gov.in/")
    assert result.features["is_official_domain"] is True
    assert result.features["brand_keyword_in_domain"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# @ symbol in URL
# ─────────────────────────────────────────────────────────────────────────────

def test_at_symbol_in_url_flagged():
    result = analyze_url("http://google.com@192.168.1.1/phish")
    assert result.features["has_at_symbol"] == 1
    assert "HIGH" in _severities(result)


# ─────────────────────────────────────────────────────────────────────────────
# APK in URL
# ─────────────────────────────────────────────────────────────────────────────

def test_apk_url_flagged():
    """CASE 3: APK in URL -> Likely Fraudulent, HIGH."""
    result = analyze_url("http://192.168.1.1/echallan.apk")
    assert result.features["apk_in_url"] == 1
    assert "HIGH" in _severities(result)
    assert result.risk_level == "HIGH"


# ─────────────────────────────────────────────────────────────────────────────
# HTTP vs HTTPS
# ─────────────────────────────────────────────────────────────────────────────

def test_http_scheme_flagged():
    result = analyze_url("http://parivahan.gov.in/pay")
    assert result.features["scheme_is_http"] == 1


def test_https_not_flagged_for_scheme():
    result = analyze_url("https://parivahan.gov.in/")
    assert result.features["scheme_is_http"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# ML Feature Consistency (Section 13)
# ─────────────────────────────────────────────────────────────────────────────

def test_ml_feature_consistency():
    """Features in url_features must match loader and training expectations."""
    expected_12 = [
        "url_length",
        "has_ip_host",
        "scheme_is_http",
        "is_url_shortener",
        "suspicious_tld",
        "num_dots_in_domain",
        "num_hyphens_in_domain",
        "has_at_symbol",
        "has_double_slash_path",
        "path_depth",
        "brand_keyword_in_domain",
        "apk_in_url",
    ]
    assert URL_FEATURE_COLUMNS == expected_12
    assert LOADER_FEATURE_COLUMNS == expected_12

    extracted = extract_url_features("https://echallan.parivahan.gov.in/pay")
    assert list(extracted.keys()) == expected_12


# ─────────────────────────────────────────────────────────────────────────────
# URL Extractor Hardening (Section 12)
# ─────────────────────────────────────────────────────────────────────────────

def test_extract_one_url():
    text = "Visit https://echallan.parivahan.gov.in/ to pay."
    urls = extract_urls(text)
    assert urls == ["https://echallan.parivahan.gov.in/"]


def test_extract_multiple_urls():
    text = "Check https://echallan.parivahan.gov.in/ or https://parivahan.gov.in/ now."
    urls = extract_urls(text)
    assert urls == ["https://echallan.parivahan.gov.in/", "https://parivahan.gov.in/"]


def test_extract_repeated_url_deduplicated():
    text = "Go to https://echallan.parivahan.gov.in/ and again https://echallan.parivahan.gov.in/"
    urls = extract_urls(text)
    assert urls == ["https://echallan.parivahan.gov.in/"]


def test_extract_url_followed_by_punctuation():
    text = "Pay at (https://echallan.parivahan.gov.in/index/pay), immediately!"
    urls = extract_urls(text)
    assert urls == ["https://echallan.parivahan.gov.in/index/pay"]


def test_extract_bare_official_domain():
    text = "Visit echallan.parivahan.gov.in for your challan."
    urls = extract_urls(text)
    assert urls == ["https://echallan.parivahan.gov.in"]


def test_extract_lookalike_domain():
    text = "Payment link: http://echallan-parivahan.xyz/pay"
    urls = extract_urls(text)
    assert urls == ["http://echallan-parivahan.xyz/pay"]


def test_extract_shortened_url():
    text = "Click bit.ly/fakechallan now"
    # Bare shortener without scheme or http
    urls = extract_urls("Click https://bit.ly/fakechallan now")
    assert urls == ["https://bit.ly/fakechallan"]


def test_ordinary_text_containing_parivahan_not_extracted():
    text = "Please check your parivahan status at the office."
    urls = extract_urls(text)
    assert urls == []
