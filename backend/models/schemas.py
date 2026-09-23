"""
CivicShield Backend — Pydantic Schemas
Defines all request/response shapes for the /api/analyze endpoint.

Design principle: every response field is either measured or explicitly
flagged as an assumption. No fabricated confidence percentages.
"""

from __future__ import annotations
from typing import Literal, Optional
from pydantic import BaseModel, Field

# Analysis modes:
#   STATIC   — local rule-based and ML analysis only (no external network calls)
#   ENRICHED — STATIC + external threat-intelligence lookups (URLs shared with 3rd parties)
AnalysisMode = Literal["STATIC", "ENRICHED"]


# ─────────────────────────────────────────────────────────────────────────────
# Inbound request
# ─────────────────────────────────────────────────────────────────────────────

class AnalyzeTextRequest(BaseModel):
    input_type: Literal["url", "text"]
    content: str = Field(..., min_length=1, max_length=50_000)


# ─────────────────────────────────────────────────────────────────────────────
# Evidence items — the core audit trail
# ─────────────────────────────────────────────────────────────────────────────

class EvidenceItem(BaseModel):
    evidence_type: Literal[
        "URL_RISK",
        "DOMAIN_CHECK",
        "RULE_MATCH",
        "LANGUAGE_SIGNAL",
        "GENUINE_SIGNAL",
        "PROCESSING_NOTE",
        "THREAT_INTEL",    # External threat-intelligence hit (ENRICHED mode)
    ]
    finding: str          # Human-readable one-liner
    severity: Literal["HIGH", "MEDIUM", "LOW", "INFO"]
    explanation: str      # Why this is flagged, for a non-technical reader
    source: str           # Which engine produced this
    rule_id: Optional[str] = None  # Rule ID from YAML (for audit trail)


# ─────────────────────────────────────────────────────────────────────────────
# Per-URL analysis result
# ─────────────────────────────────────────────────────────────────────────────

class UrlAnalysisResult(BaseModel):
    url: str
    risk_level: Literal["HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    features: dict           # Computed URL features (fully transparent)
    evidence: list[EvidenceItem]
    ml_prediction: Optional[str] = None   # "phishing" | "legitimate" | None
    ml_available: bool = False
    note: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# Threat intelligence result (per provider, per URL) — ENRICHED mode only
# ─────────────────────────────────────────────────────────────────────────────

class ThreatIntelResultSchema(BaseModel):
    """Serializable form of backend.intelligence.base.ThreatIntelResult."""
    provider: str
    url: str
    found: bool = False
    threat_type: Optional[str] = None
    threat_url: Optional[str] = None
    tags: list[str] = []
    date_added: Optional[str] = None
    url_status: str = "unknown"
    error: Optional[str] = None
    provider_available: bool = True


# ─────────────────────────────────────────────────────────────────────────────
# Overall analysis result
# ─────────────────────────────────────────────────────────────────────────────

class AnalysisResult(BaseModel):
    # Top-level verdict
    verdict: Literal["Likely Genuine", "Likely Fraudulent", "Unable to Verify"]
    risk_level: Literal["HIGH", "MEDIUM", "LOW", "UNKNOWN"]

    # Analysis mode used (STATIC | ENRICHED)
    analysis_mode: AnalysisMode = "STATIC"

    # Evidence audit trail
    evidence: list[EvidenceItem]

    # Extracted content
    extracted_text: Optional[str] = None
    extracted_urls: list[str] = []

    # Per-URL analysis
    url_analyses: list[UrlAnalysisResult] = []

    # Threat intelligence results (ENRICHED mode only)
    intel_results: list[ThreatIntelResultSchema] = []

    # Verdict reasoning (plain English)
    verdict_reasoning: str

    # Recommended next steps for the citizen
    recommended_actions: list[str] = []

    # Official verification route
    official_verification_url: str = "https://echallan.parivahan.gov.in/"

    # Mandatory disclaimer
    disclaimer: str = (
        "CivicShield provides an evidence-based assessment and does not certify "
        "the authenticity of a government communication."
    )

    # Processing metadata
    processing_notes: list[str] = []
    input_type_processed: str = ""

    # Signal counts (for transparency)
    high_severity_count: int = 0
    medium_severity_count: int = 0
    low_severity_count: int = 0
