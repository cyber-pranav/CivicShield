"""
CivicShield — Evidence Engine
Aggregates evidence from all sub-engines into a unified, deduplicated list.

Responsibility:
  - Accept evidence from multiple sources
  - Deduplicate by (rule_id, source) pairs
  - Count severities for downstream verdict logic
  - Provide a clean interface for the verdict engine

This is intentionally thin — it does not itself produce judgements,
only organises the evidence trail.
"""

from __future__ import annotations
from backend.models.schemas import EvidenceItem


def aggregate_evidence(
    *evidence_lists: list[EvidenceItem],
) -> tuple[list[EvidenceItem], int, int, int]:
    """
    Merge evidence from multiple engines, deduplicate by (rule_id, source).

    Returns:
        (aggregated_evidence, high_count, medium_count, low_count)

    Note: INFO-severity items are included in the output but not counted
    in the severity totals (they represent reassurance signals, not risks).
    """
    seen: set[tuple] = set()
    aggregated: list[EvidenceItem] = []

    for evidence_list in evidence_lists:
        for item in evidence_list:
            # Deduplication key: rule_id + source + finding (truncated)
            dedup_key = (item.rule_id, item.source, item.finding[:60])
            if dedup_key not in seen:
                seen.add(dedup_key)
                aggregated.append(item)

    high_count = sum(1 for e in aggregated if e.severity == "HIGH")
    medium_count = sum(1 for e in aggregated if e.severity == "MEDIUM")
    low_count = sum(1 for e in aggregated if e.severity == "LOW")

    return aggregated, high_count, medium_count, low_count
