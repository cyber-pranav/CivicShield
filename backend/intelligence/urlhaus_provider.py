"""
CivicShield — URLhaus Threat Intelligence Provider

URLhaus (https://urlhaus.abuse.ch/) is a free, open abuse-reporting service
maintained by abuse.ch. No API key required for lookups.

API reference: https://urlhaus-api.abuse.ch/#urlinfo

IMPORTANT SECURITY NOTE:
  We POST the URL *string* to URLhaus's API server as form data.
  We do NOT fetch/visit the user-submitted URL from this server.
  URLhaus stores known malicious URLs and responds with metadata.
  There is no SSRF risk from this provider.

Privacy note:
  URLhaus receives the URL string submitted by the user.
  This is disclosed in the UI ("analysis_mode = ENRICHED shares URL
  strings with external threat intelligence services").
"""

from __future__ import annotations

import os
from typing import Optional

import httpx

from backend.intelligence.base import ThreatIntelProvider, ThreatIntelResult

# ── Constants ─────────────────────────────────────────────────────────────────
_URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
_TIMEOUT_S = 6.0  # seconds — tight timeout to avoid blocking analysis

# URLhaus query_status → threat_type mapping
_STATUS_TO_THREAT: dict[str, str] = {
    "is_reporting_a_phishing_site": "phishing",
    "is_reporting_a_malware_url":   "malware",
}
_CLEAN_STATUSES = {"no_results", "invalid_url"}


class URLhausProvider(ThreatIntelProvider):
    """
    Queries the abuse.ch URLhaus database.
    Free, no API key needed. Rate limit: ~20 req/min per IP (unenforced but courteous).
    """

    @property
    def name(self) -> str:
        return "URLhaus"

    @property
    def requires_api_key(self) -> bool:
        return False

    def is_available(self) -> bool:
        # URLhaus is always "available" — no key gate.
        # Actual reachability is only discovered at lookup time.
        return True

    def lookup_url(self, url: str) -> ThreatIntelResult:
        """
        POST the URL string to URLhaus and return a structured result.
        Returns an error result (found=False, error set) on any failure.
        """
        if not url or not url.startswith(("http://", "https://")):
            return self._error_result(url, "URLhaus only accepts http/https URLs")

        try:
            with httpx.Client(timeout=_TIMEOUT_S) as client:
                resp = client.post(
                    _URLHAUS_API,
                    data={"url": url},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            resp.raise_for_status()
            data: dict = resp.json()
        except httpx.TimeoutException:
            return self._error_result(url, "URLhaus lookup timed out")
        except httpx.HTTPStatusError as exc:
            return self._error_result(url, f"URLhaus HTTP {exc.response.status_code}")
        except Exception as exc:
            return self._error_result(url, f"URLhaus error: {type(exc).__name__}: {exc}")

        query_status: str = data.get("query_status", "")

        # Not in database → clean (unknown)
        if query_status in _CLEAN_STATUSES:
            return ThreatIntelResult(
                provider=self.name,
                url=url,
                found=False,
                provider_available=True,
            )

        # Known threat
        if query_status in _STATUS_TO_THREAT:
            threat_type = _STATUS_TO_THREAT[query_status]

            # Extract metadata from the first matching record (if present)
            urls_list: list[dict] = data.get("urls", [])
            first = urls_list[0] if urls_list else {}

            url_status = first.get("url_status", "unknown")
            date_added = first.get("date_added")
            urlhaus_ref = first.get("urlhaus_reference")
            tags: list[str] = []
            for entry in urls_list:
                for tag in (entry.get("tags") or []):
                    if tag and tag not in tags:
                        tags.append(tag)

            return ThreatIntelResult(
                provider=self.name,
                url=url,
                found=True,
                threat_type=threat_type,
                threat_url=urlhaus_ref,
                tags=tags[:10],  # cap at 10 tags
                date_added=date_added,
                url_status=url_status,
                provider_available=True,
            )

        # Unexpected status — treat as unknown
        return ThreatIntelResult(
            provider=self.name,
            url=url,
            found=False,
            error=f"Unexpected URLhaus query_status: {query_status!r}",
            provider_available=True,
        )
