"""
CivicShield — URL Engine Unit Tests

Tests cover:
  - IP address detection
  - URL shortener detection
  - Suspicious TLD detection
  - Official domain recognition
  - Brand keyword impersonation
  - APK in URL detection
  - @ symbol detection

Run with: python -m pytest tests/test_url_engine.py -v
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from backend.engines.url_risk_engine import analyze_url
from backend.models.schemas import UrlAnalysisResult


def _severities(result: UrlAnalysisResult) -> list[str]:
    return [e.severity for e in result.evidence]


def _finding_contains(result: UrlAnalysisResult, keyword: str) -> bool:
    return any(keyword.lower() in e.finding.lower() for e in result.evidence)


# ─────────────────────────────────────────────────────────────────────────────
# IP address as hostname
# ─────────────────────────────────────────────────────────────────────────────

def test_ip_address_url_is_high_risk():
    result = analyze_url("http://192.168.1.1/echallan/pay")
    assert result.features["has_ip_host"] is True
    assert "HIGH" in _severities(result)


def test_normal_domain_not_flagged_as_ip():
    result = analyze_url("https://echallan.parivahan.gov.in/")
    assert result.features["has_ip_host"] is False


# ─────────────────────────────────────────────────────────────────────────────
# Official domain recognition
# ─────────────────────────────────────────────────────────────────────────────

def test_official_domain_recognized():
    result = analyze_url("https://echallan.parivahan.gov.in/index/accused-challan")
    assert result.features["is_official_domain"] is True
    assert result.risk_level in ("LOW", "UNKNOWN")


def test_fake_gov_domain_not_official():
    result = analyze_url("https://echallan-parivahan.xyz/pay")
    assert result.features["is_official_domain"] is False


# ─────────────────────────────────────────────────────────────────────────────
# URL shorteners
# ─────────────────────────────────────────────────────────────────────────────

def test_bitly_is_flagged():
    result = analyze_url("https://bit.ly/3XfakeLink")
    assert result.features["is_url_shortener"] is True
    assert "HIGH" in _severities(result)


def test_tinyurl_is_flagged():
    result = analyze_url("https://tinyurl.com/fakechallan")
    assert result.features["is_url_shortener"] is True


# ─────────────────────────────────────────────────────────────────────────────
# Suspicious TLD
# ─────────────────────────────────────────────────────────────────────────────

def test_suspicious_tld_xyz():
    result = analyze_url("https://parivahan-echallan.xyz/pay-now")
    assert result.features["suspicious_tld"] is True
    assert "HIGH" in _severities(result)


def test_gov_in_not_suspicious_tld():
    result = analyze_url("https://parivahan.gov.in/")
    # .in is not in suspicious TLD list
    assert result.features["suspicious_tld"] is False


# ─────────────────────────────────────────────────────────────────────────────
# Brand keyword impersonation
# ─────────────────────────────────────────────────────────────────────────────

def test_brand_keyword_in_fake_domain():
    result = analyze_url("http://echallan-india.tk/payment")
    assert result.features["brand_keyword_in_domain"] is True
    assert "HIGH" in _severities(result)


def test_brand_keyword_in_official_domain_not_flagged():
    result = analyze_url("https://echallan.parivahan.gov.in/")
    # Official domain should not flag brand keyword as suspicious
    assert result.features["is_official_domain"] is True


# ─────────────────────────────────────────────────────────────────────────────
# @ symbol in URL
# ─────────────────────────────────────────────────────────────────────────────

def test_at_symbol_in_url_flagged():
    result = analyze_url("http://google.com@192.168.1.1/phish")
    assert result.features["has_at_symbol"] is True
    assert "HIGH" in _severities(result)


# ─────────────────────────────────────────────────────────────────────────────
# APK in URL
# ─────────────────────────────────────────────────────────────────────────────

def test_apk_url_flagged():
    result = analyze_url("http://rto-challan-pay.ml/challan.apk")
    assert result.features["apk_in_url"] is True
    assert "HIGH" in _severities(result)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP vs HTTPS
# ─────────────────────────────────────────────────────────────────────────────

def test_http_scheme_flagged():
    result = analyze_url("http://parivahan.gov.in/pay")
    assert result.features["scheme_is_http"] is True


def test_https_not_flagged_for_scheme():
    result = analyze_url("https://parivahan.gov.in/")
    assert result.features["scheme_is_http"] is False


# ─────────────────────────────────────────────────────────────────────────────
# URL risk level derivation
# ─────────────────────────────────────────────────────────────────────────────

def test_clearly_fake_url_is_high_risk():
    """Multiple HIGH signals should yield HIGH risk level."""
    result = analyze_url("http://192.168.1.1/echallan.apk")
    assert result.risk_level == "HIGH"


def test_official_url_is_low_risk():
    result = analyze_url("https://echallan.parivahan.gov.in/")
    assert result.risk_level == "LOW"
