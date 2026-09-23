"""
CivicShield — Threat Intelligence Aggregator

Runs all configured providers against a list of URLs and produces:
  - Per-URL ThreatIntelResult list (one per provider that ran)
  - Evidence items for any confirmed hits (HIGH severity)
  - Processing notes for skipped / failed providers

Usage:
    aggregator = IntelAggregator()
    intel_results, evidence, notes = aggregator.run(urls)

ENRICHED mode only — not called in STATIC mode.

Provider availability:
    URLhaus:   Always available (no key needed)
    GSB:       Only if CIVICSHIELD_GSB_API_KEY env var is set
"""

from __future__ import annotations

import concurrent.futures
from typing import Optional

from backend.intelligence.base import ThreatIntelProvider, ThreatIntelResult
from backend.intelligence.urlhaus_provider import URLhausProvider
from backend.intelligence.gsb_provider import GoogleSafeBrowsingProvider
from backend.models.schemas import EvidenceItem

# Maximum seconds to wait for ALL providers across ALL URLs
_AGGREGATE_TIMEOUT_S = 12.0

# Maximum URLs to query (cost/time guard)
_MAX_URLS_TO_CHECK = 5


class IntelAggregator:
    """
    Runs all available threat-intel providers against a set of URLs.
    Uses a thread pool so multiple providers can run concurrently.
    """

    def __init__(self, providers: Optional[list[ThreatIntelProvider]] = None):
        if providers is None:
            providers = [
                URLhausProvider(),
                GoogleSafeBrowsingProvider(),
            ]
        self._providers = providers

    @property
    def available_providers(self) -> list[str]:
        return [p.name for p in self._providers if p.is_available()]

    def run(
        self,
        urls: list[str],
    ) -> tuple[list[ThreatIntelResult], list[EvidenceItem], list[str]]:
        """
        Look up each URL in all available providers.

        Returns:
            (all_results, evidence_items, processing_notes)
        """
        all_results: list[ThreatIntelResult] = []
        evidence: list[EvidenceItem] = []
        notes: list[str] = []

        # Deduplicate and cap URLs
        unique_urls = list(dict.fromkeys(u for u in urls if u))[:_MAX_URLS_TO_CHECK]
        if not unique_urls:
            return all_results, evidence, notes

        # Filter to available providers
        active = [p for p in self._providers if p.is_available()]
        if not active:
            notes.append(
                "ENRICHED mode: No threat-intelligence providers are currently configured. "
                "Set CIVICSHIELD_GSB_API_KEY to enable Google Safe Browsing."
            )
            return all_results, evidence, notes

        skipped = [p.name for p in self._providers if not p.is_available()]
        if skipped:
            notes.append(
                f"Threat-intelligence provider(s) skipped (not configured): "
                f"{', '.join(skipped)}."
            )

        # Build task list: (provider, url)
        tasks = [(p, u) for p in active for u in unique_urls]

        def _lookup(args: tuple) -> ThreatIntelResult:
            provider, url = args
            return provider.lookup_url(url)

        # Run concurrently with a wall-clock timeout
        try:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(len(tasks), 8)
            ) as executor:
                futures = {executor.submit(_lookup, t): t for t in tasks}
                done, not_done = concurrent.futures.wait(
                    futures, timeout=_AGGREGATE_TIMEOUT_S
                )

                for fut in done:
                    try:
                        result = fut.result()
                        all_results.append(result)
                    except Exception as exc:
                        task = futures[fut]
                        notes.append(
                            f"Intel lookup error ({task[0].name} / {task[1]}): {exc}"
                        )

                for fut in not_done:
                    task = futures[fut]
                    fut.cancel()
                    notes.append(
                        f"Intel lookup timed out: {task[0].name} / {task[1][:60]}"
                    )

        except Exception as exc:
            notes.append(f"Threat intelligence aggregation error: {exc}")
            return all_results, evidence, notes

        # Convert confirmed hits to EvidenceItems
        for result in all_results:
            if result.found and not result.error:
                severity = "HIGH"
                tag_str = f" (tags: {', '.join(result.tags)})" if result.tags else ""
                status_str = (
                    f" URL is currently {result.url_status}."
                    if result.url_status not in ("unknown", "")
                    else ""
                )
                report_str = (
                    f" Report: {result.threat_url}"
                    if result.threat_url
                    else ""
                )
                finding = (
                    f"{result.provider} confirms URL as {result.threat_type or 'malicious'}"
                    f"{tag_str}"
                )
                explanation = (
                    f"The URL was found in the {result.provider} threat database "
                    f"as a known {result.threat_type or 'malicious'} site.{status_str}"
                    f"{report_str} "
                    "This is an external confirmation of threat intelligence "
                    "and does not depend on rule-based analysis."
                )
                evidence.append(EvidenceItem(
                    evidence_type="THREAT_INTEL",
                    finding=finding,
                    severity=severity,
                    explanation=explanation,
                    source=result.provider.lower().replace(" ", "_"),
                    rule_id=f"INTEL_{result.provider.upper().replace(' ', '_')}_HIT",
                ))
            elif result.error and result.provider_available:
                notes.append(
                    f"Threat intel lookup failed ({result.provider}): {result.error}"
                )

        return all_results, evidence, notes
