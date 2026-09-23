"""
CivicShield — Threat Intelligence Provider Interface

Defines the abstract base class that all threat-intel providers implement.
Every provider must:
  - Report whether it is available (key configured, service reachable)
  - Look up a URL and return a structured result or None
  - Never raise unhandled exceptions — use ThreatIntelError

Design constraints:
  - Providers query EXTERNAL databases about a URL string.
  - Providers NEVER fetch/visit the user-submitted URL themselves.
  - No SSRF risk: we send the URL text to a trusted third-party API,
    not to the URL itself.
  - All network calls are wrapped with strict timeouts.
  - All results are advisory signals, not verdicts.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Shared data types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ThreatIntelResult:
    """
    Result of a single provider's lookup for one URL.

    Attributes:
        provider:    Human-readable provider name (e.g., "URLhaus", "GSB")
        url:         The URL that was looked up (as-submitted)
        found:       True if the provider has a record for this URL
        threat_type: Category of threat (e.g., "phishing", "malware", "botnet_cc")
                     None if not found or provider does not categorize
        threat_url:  Link to the threat report on the provider's site (for audit)
        tags:        Provider-supplied classification tags
        date_added:  ISO-8601 date the URL was first reported (if available)
        url_status:  "online" | "offline" | "unknown" — provider's last check
        error:       Non-empty if the lookup failed; result should be ignored
        provider_available: False if provider was not configured / unreachable
    """
    provider: str
    url: str
    found: bool = False
    threat_type: Optional[str] = None
    threat_url: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    date_added: Optional[str] = None
    url_status: str = "unknown"
    error: Optional[str] = None
    provider_available: bool = True


class ThreatIntelError(Exception):
    """Raised by a provider when it cannot complete a lookup."""


# ─────────────────────────────────────────────────────────────────────────────
# Abstract base class
# ─────────────────────────────────────────────────────────────────────────────

class ThreatIntelProvider(ABC):
    """
    Abstract base for all threat intelligence providers.

    Subclasses MUST override: name, requires_api_key, is_available, lookup_url.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider name."""

    @property
    @abstractmethod
    def requires_api_key(self) -> bool:
        """True if this provider needs an API key to function."""

    @abstractmethod
    def is_available(self) -> bool:
        """
        Return True if this provider is configured and can handle requests.
        For key-based providers: checks that the key env-var is set.
        For free providers: always True (may still fail at lookup time).
        """

    @abstractmethod
    def lookup_url(self, url: str) -> ThreatIntelResult:
        """
        Look up a URL in this provider's threat database.

        Returns:
            ThreatIntelResult with found=True if the URL is known malicious,
            found=False if clean/unknown, error set if the lookup failed.

        Must never raise — catch all exceptions and return an error result.
        """

    def _error_result(self, url: str, error: str) -> ThreatIntelResult:
        """Helper: build a safe error result without raising."""
        return ThreatIntelResult(
            provider=self.name,
            url=url,
            found=False,
            error=error,
            provider_available=self.is_available(),
        )
