"""
CivicShield — Intelligence Layer Unit Tests

Tests the ThreatIntelProvider interface, IntelAggregator wiring,
and graceful degradation when providers are unavailable.

These tests use mock providers — no real network calls are made.
"""

from __future__ import annotations
import pytest
from unittest.mock import patch, MagicMock

from backend.intelligence.base import ThreatIntelProvider, ThreatIntelResult
from backend.intelligence.intel_aggregator import IntelAggregator
from backend.intelligence.urlhaus_provider import URLhausProvider
from backend.intelligence.gsb_provider import GoogleSafeBrowsingProvider


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

class _AlwaysHitProvider(ThreatIntelProvider):
    """Fake provider that always reports a phishing hit."""
    @property
    def name(self) -> str: return "FakeHit"
    @property
    def requires_api_key(self) -> bool: return False
    def is_available(self) -> bool: return True
    def lookup_url(self, url: str) -> ThreatIntelResult:
        return ThreatIntelResult(
            provider=self.name,
            url=url,
            found=True,
            threat_type="phishing",
            url_status="online",
            provider_available=True,
        )


class _AlwaysCleanProvider(ThreatIntelProvider):
    """Fake provider that always reports clean."""
    @property
    def name(self) -> str: return "FakeClean"
    @property
    def requires_api_key(self) -> bool: return False
    def is_available(self) -> bool: return True
    def lookup_url(self, url: str) -> ThreatIntelResult:
        return ThreatIntelResult(
            provider=self.name,
            url=url,
            found=False,
            provider_available=True,
        )


class _UnavailableProvider(ThreatIntelProvider):
    """Fake provider that is not configured."""
    @property
    def name(self) -> str: return "FakeUnavailable"
    @property
    def requires_api_key(self) -> bool: return True
    def is_available(self) -> bool: return False
    def lookup_url(self, url: str) -> ThreatIntelResult:
        raise RuntimeError("Should never be called when unavailable")


class _ErrorProvider(ThreatIntelProvider):
    """Fake provider that always errors."""
    @property
    def name(self) -> str: return "FakeError"
    @property
    def requires_api_key(self) -> bool: return False
    def is_available(self) -> bool: return True
    def lookup_url(self, url: str) -> ThreatIntelResult:
        return ThreatIntelResult(
            provider=self.name,
            url=url,
            found=False,
            error="Connection refused",
            provider_available=True,
        )


# ─────────────────────────────────────────────────────────────────────────────
# ThreatIntelProvider base behaviour
# ─────────────────────────────────────────────────────────────────────────────

def test_hit_provider_returns_found_true():
    p = _AlwaysHitProvider()
    r = p.lookup_url("http://evil.example.com/pay")
    assert r.found is True
    assert r.threat_type == "phishing"
    assert r.provider == "FakeHit"


def test_clean_provider_returns_found_false():
    p = _AlwaysCleanProvider()
    r = p.lookup_url("https://echallan.parivahan.gov.in/")
    assert r.found is False
    assert r.error is None


def test_unavailable_provider_is_skipped_by_aggregator():
    agg = IntelAggregator(providers=[_UnavailableProvider()])
    results, evidence, notes = agg.run(["http://evil.example.com/"])
    # No results (provider was skipped)
    assert len(results) == 0
    # The aggregator emits a note when no providers are active
    assert len(notes) >= 1
    combined = " ".join(notes).lower()
    assert "no threat-intelligence providers" in combined or "not configured" in combined


# ─────────────────────────────────────────────────────────────────────────────
# IntelAggregator behaviour
# ─────────────────────────────────────────────────────────────────────────────

def test_aggregator_hit_produces_evidence_item():
    agg = IntelAggregator(providers=[_AlwaysHitProvider()])
    results, evidence, notes = agg.run(["http://phishing-site.example.com/pay"])
    assert len(results) == 1
    assert results[0].found is True
    assert len(evidence) == 1
    ev = evidence[0]
    assert ev.evidence_type == "THREAT_INTEL"
    assert ev.severity == "HIGH"
    assert "FakeHit" in ev.finding
    assert "phishing" in ev.finding.lower()


def test_aggregator_clean_produces_no_evidence():
    agg = IntelAggregator(providers=[_AlwaysCleanProvider()])
    results, evidence, notes = agg.run(["https://echallan.parivahan.gov.in/"])
    assert len(results) == 1
    assert results[0].found is False
    assert len(evidence) == 0


def test_aggregator_error_produces_note_not_evidence():
    agg = IntelAggregator(providers=[_ErrorProvider()])
    results, evidence, notes = agg.run(["http://example.com/"])
    assert len(results) == 1
    assert len(evidence) == 0  # Error results don't become evidence
    assert any("FakeError" in n or "failed" in n.lower() for n in notes)


def test_aggregator_multiple_providers():
    agg = IntelAggregator(providers=[_AlwaysHitProvider(), _AlwaysCleanProvider()])
    results, evidence, notes = agg.run(["http://evil.com/"])
    # Both providers ran
    assert len(results) == 2
    # Only the hit produces evidence
    assert len(evidence) == 1
    assert evidence[0].severity == "HIGH"


def test_aggregator_empty_urls():
    agg = IntelAggregator(providers=[_AlwaysHitProvider()])
    results, evidence, notes = agg.run([])
    assert results == []
    assert evidence == []


def test_aggregator_deduplicates_urls():
    """Same URL submitted twice should only be looked up once."""
    agg = IntelAggregator(providers=[_AlwaysHitProvider()])
    results, evidence, notes = agg.run([
        "http://evil.com/",
        "http://evil.com/",  # duplicate
    ])
    assert len(results) == 1  # deduplicated


def test_aggregator_caps_at_max_urls():
    """Should not query more than _MAX_URLS_TO_CHECK URLs."""
    from backend.intelligence.intel_aggregator import _MAX_URLS_TO_CHECK
    urls = [f"http://url{i}.example.com/" for i in range(_MAX_URLS_TO_CHECK + 10)]
    agg = IntelAggregator(providers=[_AlwaysCleanProvider()])
    results, evidence, notes = agg.run(urls)
    assert len(results) <= _MAX_URLS_TO_CHECK


# ─────────────────────────────────────────────────────────────────────────────
# URLhaus provider — unit test with mocked HTTP
# ─────────────────────────────────────────────────────────────────────────────

def test_urlhaus_provider_is_always_available():
    p = URLhausProvider()
    assert p.is_available() is True
    assert p.requires_api_key is False


def test_urlhaus_rejects_non_http_scheme():
    p = URLhausProvider()
    r = p.lookup_url("ftp://evil.example.com/")
    assert r.found is False
    assert r.error is not None


def test_urlhaus_known_phishing(monkeypatch):
    """Test URLhaus correctly parses a 'is_reporting_a_phishing_site' response."""
    fake_response = {
        "query_status": "is_reporting_a_phishing_site",
        "urls": [
            {
                "url_status": "online",
                "date_added": "2024-01-15 12:00:00",
                "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/",
                "tags": ["phishing", "challan"],
            }
        ],
    }
    mock_resp = MagicMock()
    mock_resp.json.return_value = fake_response
    mock_resp.raise_for_status = MagicMock()

    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.post.return_value = mock_resp

    with patch("backend.intelligence.urlhaus_provider.httpx.Client", return_value=mock_client):
        p = URLhausProvider()
        r = p.lookup_url("http://phishing.example.com/echallan")

    assert r.found is True
    assert r.threat_type == "phishing"
    assert r.url_status == "online"
    assert "challan" in r.tags
    assert r.threat_url == "https://urlhaus.abuse.ch/url/123/"


def test_urlhaus_no_results(monkeypatch):
    fake_response = {"query_status": "no_results"}
    mock_resp = MagicMock()
    mock_resp.json.return_value = fake_response
    mock_resp.raise_for_status = MagicMock()

    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.post.return_value = mock_resp

    with patch("backend.intelligence.urlhaus_provider.httpx.Client", return_value=mock_client):
        p = URLhausProvider()
        r = p.lookup_url("https://echallan.parivahan.gov.in/")

    assert r.found is False
    assert r.error is None


def test_urlhaus_timeout_returns_error():
    import httpx as _httpx
    with patch(
        "backend.intelligence.urlhaus_provider.httpx.Client",
        side_effect=_httpx.TimeoutException("timeout"),
    ):
        p = URLhausProvider()
        r = p.lookup_url("http://example.com/")
    assert r.found is False
    assert r.error is not None
    assert "timed out" in r.error.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Google Safe Browsing provider
# ─────────────────────────────────────────────────────────────────────────────

def test_gsb_unavailable_when_no_key(monkeypatch):
    monkeypatch.delenv("CIVICSHIELD_GSB_API_KEY", raising=False)
    p = GoogleSafeBrowsingProvider()
    assert p.is_available() is False


def test_gsb_available_when_key_set(monkeypatch):
    monkeypatch.setenv("CIVICSHIELD_GSB_API_KEY", "fake_key_for_test")
    p = GoogleSafeBrowsingProvider()
    assert p.is_available() is True


def test_gsb_returns_unavailable_result_when_no_key(monkeypatch):
    monkeypatch.delenv("CIVICSHIELD_GSB_API_KEY", raising=False)
    p = GoogleSafeBrowsingProvider()
    r = p.lookup_url("http://evil.com/")
    assert r.found is False
    assert r.provider_available is False
    assert "not configured" in (r.error or "").lower()


def test_gsb_known_phishing(monkeypatch):
    monkeypatch.setenv("CIVICSHIELD_GSB_API_KEY", "fake_key_for_test")
    fake_response = {
        "matches": [
            {
                "threatType": "SOCIAL_ENGINEERING",
                "platformType": "ANY_PLATFORM",
                "threatEntryType": "URL",
                "threat": {"url": "http://evil.com/"},
            }
        ]
    }
    mock_resp = MagicMock()
    mock_resp.json.return_value = fake_response
    mock_resp.raise_for_status = MagicMock()

    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.post.return_value = mock_resp

    with patch("backend.intelligence.gsb_provider.httpx.Client", return_value=mock_client):
        p = GoogleSafeBrowsingProvider()
        r = p.lookup_url("http://evil.com/")

    assert r.found is True
    assert "phishing" in r.threat_type or "social" in r.threat_type


def test_gsb_clean_url(monkeypatch):
    monkeypatch.setenv("CIVICSHIELD_GSB_API_KEY", "fake_key_for_test")
    fake_response = {}  # Empty response = clean
    mock_resp = MagicMock()
    mock_resp.json.return_value = fake_response
    mock_resp.raise_for_status = MagicMock()

    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.post.return_value = mock_resp

    with patch("backend.intelligence.gsb_provider.httpx.Client", return_value=mock_client):
        p = GoogleSafeBrowsingProvider()
        r = p.lookup_url("https://echallan.parivahan.gov.in/")

    assert r.found is False
    assert r.error is None
