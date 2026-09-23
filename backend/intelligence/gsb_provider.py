"""
CivicShield — Google Safe Browsing v4 Threat Intelligence Provider

Queries Google's Safe Browsing API to check if a URL is known as a
phishing, malware, or social-engineering site.

API key is required. Configure via environment variable:
  CIVICSHIELD_GSB_API_KEY=<your_api_key>

Get a free API key at: https://developers.google.com/safe-browsing/v4/get-started

If the key is not set, this provider reports itself as unavailable and
is skipped during ENRICHED mode analysis.

IMPORTANT SECURITY NOTE:
  We send the URL *string* as a JSON payload to Google's API endpoint.
  We do NOT fetch/visit the user-submitted URL from this server.
  No SSRF risk from this provider.

Privacy note:
  Google receives the URL string if this provider is enabled.
  Disclosed in the ENRICHED mode disclaimer.
"""

from __future__ import annotations

import os
from typing import Optional

import httpx

from backend.intelligence.base import ThreatIntelProvider, ThreatIntelResult

# ── Constants ─────────────────────────────────────────────────────────────────
_GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_TIMEOUT_S = 8.0
_ENV_KEY = "CIVICSHIELD_GSB_API_KEY"

# GSB threat type → human-readable category
_THREAT_LABELS: dict[str, str] = {
    "MALWARE":             "malware",
    "SOCIAL_ENGINEERING":  "phishing / social engineering",
    "UNWANTED_SOFTWARE":   "unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "potentially harmful app",
}

_CLIENT_ID = "CivicShield"
_CLIENT_VERSION = "1.0.0"


class GoogleSafeBrowsingProvider(ThreatIntelProvider):
    """
    Queries Google Safe Browsing API v4.
    Requires CIVICSHIELD_GSB_API_KEY environment variable.
    """

    @property
    def name(self) -> str:
        return "Google Safe Browsing"

    @property
    def requires_api_key(self) -> bool:
        return True

    def _get_key(self) -> Optional[str]:
        return os.environ.get(_ENV_KEY, "").strip() or None

    def is_available(self) -> bool:
        return self._get_key() is not None

    def lookup_url(self, url: str) -> ThreatIntelResult:
        api_key = self._get_key()
        if not api_key:
            return ThreatIntelResult(
                provider=self.name,
                url=url,
                found=False,
                error="CIVICSHIELD_GSB_API_KEY not configured",
                provider_available=False,
            )

        if not url or not url.startswith(("http://", "https://")):
            return self._error_result(url, "GSB only supports http/https URLs")

        payload = {
            "client": {
                "clientId":      _CLIENT_ID,
                "clientVersion": _CLIENT_VERSION,
            },
            "threatInfo": {
                "threatTypes": list(_THREAT_LABELS.keys()),
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            with httpx.Client(timeout=_TIMEOUT_S) as client:
                resp = client.post(
                    f"{_GSB_API_URL}?key={api_key}",
                    json=payload,
                )
            resp.raise_for_status()
            data: dict = resp.json()
        except httpx.TimeoutException:
            return self._error_result(url, "Google Safe Browsing lookup timed out")
        except httpx.HTTPStatusError as exc:
            return self._error_result(url, f"GSB HTTP {exc.response.status_code}")
        except Exception as exc:
            return self._error_result(url, f"GSB error: {type(exc).__name__}: {exc}")

        matches: list[dict] = data.get("matches", [])
        if not matches:
            # Empty response = URL is not in any threat list
            return ThreatIntelResult(
                provider=self.name,
                url=url,
                found=False,
                provider_available=True,
            )

        # Build threat_type from first match
        first_match = matches[0]
        raw_type = first_match.get("threatType", "UNKNOWN")
        threat_type = _THREAT_LABELS.get(raw_type, raw_type.lower())

        # Collect all distinct threat types from all matches
        tags = list({
            _THREAT_LABELS.get(m.get("threatType", ""), m.get("threatType", "").lower())
            for m in matches
        })

        return ThreatIntelResult(
            provider=self.name,
            url=url,
            found=True,
            threat_type=threat_type,
            tags=tags,
            provider_available=True,
        )
