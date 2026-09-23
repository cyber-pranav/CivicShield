"""
CivicShield — Analysis Router
POST /api/analyze

Accepts URL, text, image, or PDF input.
Orchestrates all sub-engines and returns a structured AnalysisResult.

Analysis modes:
  STATIC   — local rule-based + ML analysis only. No external network calls.
  ENRICHED — STATIC + external threat-intelligence lookups.
             In ENRICHED mode, URL strings are submitted to configured
             third-party threat databases (URLhaus, Google Safe Browsing).
             Users must be informed before choosing ENRICHED mode.

Input validation happens at two layers:
  1. FastAPI route parameters (file size header check)
  2. input_processor.py (content validation)
"""

from __future__ import annotations
from typing import Optional, Annotated
import traceback

from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse

from backend.models.schemas import (
    AnalysisResult,
    EvidenceItem,
    ThreatIntelResultSchema,
    AnalysisMode,
)
from backend.processors.input_processor import process_input
from backend.engines.url_risk_engine import analyze_url
from backend.engines.challan_rule_engine import analyze_challan_text
from backend.engines.scam_language_engine import analyze_scam_language
from backend.engines.evidence_engine import aggregate_evidence
from backend.engines.verdict_engine import compute_verdict
from backend.db.database import log_analysis
from ml.url_model_loader import load_model

router = APIRouter()

# Load ML model at startup (returns None if model file doesn't exist)
_ml_model = load_model()


def _to_schema(intel_result) -> ThreatIntelResultSchema:
    """Convert a ThreatIntelResult dataclass to a Pydantic schema."""
    return ThreatIntelResultSchema(
        provider=intel_result.provider,
        url=intel_result.url,
        found=intel_result.found,
        threat_type=intel_result.threat_type,
        threat_url=intel_result.threat_url,
        tags=intel_result.tags or [],
        date_added=intel_result.date_added,
        url_status=intel_result.url_status,
        error=intel_result.error,
        provider_available=intel_result.provider_available,
    )


@router.post("/analyze", response_model=AnalysisResult)
async def analyze(
    input_type: Annotated[str, Form()],
    content: Annotated[Optional[str], Form()] = None,
    file: Annotated[Optional[UploadFile], File()] = None,
    analysis_mode: Annotated[str, Form()] = "STATIC",
) -> AnalysisResult:
    """
    Analyse a submitted URL, text message, image, or PDF for fraud indicators.

    input_type:    "url" | "text" | "image" | "pdf"
    content:       For url/text inputs — the raw string
    file:          For image/pdf inputs — the uploaded file
    analysis_mode: "STATIC" (default) | "ENRICHED" (adds threat-intel lookups)
    """

    # ── Validate input_type ───────────────────────────────────────────────────
    valid_types = {"url", "text", "image", "pdf"}
    if input_type not in valid_types:
        raise HTTPException(
            status_code=422,
            detail=f"input_type must be one of: {', '.join(valid_types)}",
        )

    # ── Validate analysis_mode ────────────────────────────────────────────────
    valid_modes: set[str] = {"STATIC", "ENRICHED"}
    if analysis_mode not in valid_modes:
        analysis_mode = "STATIC"
    effective_mode: AnalysisMode = analysis_mode  # type: ignore[assignment]

    # ── Read file bytes if provided ───────────────────────────────────────────
    file_bytes: Optional[bytes] = None
    filename: Optional[str] = None
    if file is not None:
        file_bytes = await file.read()
        filename = file.filename

    # ── Process input ─────────────────────────────────────────────────────────
    try:
        extracted_text, extracted_urls, processing_notes = process_input(
            input_type=input_type,
            content=content,
            file_bytes=file_bytes,
            filename=filename,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Internal error during input processing.")

    # ── URL analysis ──────────────────────────────────────────────────────────
    url_analyses = [analyze_url(url, ml_model=_ml_model) for url in extracted_urls]
    url_evidence = [ev for ua in url_analyses for ev in ua.evidence]

    # ── Text rule analysis ────────────────────────────────────────────────────
    text_to_analyze = extracted_text or ""
    # For URL-only input, also run rules on the URL string itself
    if input_type == "url" and not text_to_analyze and extracted_urls:
        text_to_analyze = extracted_urls[0]

    challan_evidence = analyze_challan_text(text_to_analyze)
    scam_evidence = analyze_scam_language(text_to_analyze)

    # ── ENRICHED mode: threat intelligence lookups ────────────────────────────
    intel_results_raw = []
    intel_evidence: list[EvidenceItem] = []

    if effective_mode == "ENRICHED" and extracted_urls:
        try:
            from backend.intelligence.intel_aggregator import IntelAggregator
            aggregator = IntelAggregator()
            intel_results_raw, intel_evidence, intel_notes = aggregator.run(extracted_urls)
            processing_notes.extend(intel_notes)
        except Exception as exc:
            traceback.print_exc()
            processing_notes.append(
                f"Threat intelligence aggregation encountered an unexpected error: {exc}"
            )

    # ── Aggregate evidence ────────────────────────────────────────────────────
    all_evidence, high_count, medium_count, low_count = aggregate_evidence(
        url_evidence,
        challan_evidence,
        scam_evidence,
        intel_evidence,
    )

    # ── Verdict ───────────────────────────────────────────────────────────────
    verdict, risk_level, reasoning, actions = compute_verdict(
        evidence=all_evidence,
        url_analyses=url_analyses,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        input_type=input_type,
    )

    # ── ENRICHED mode privacy note ────────────────────────────────────────────
    if effective_mode == "ENRICHED":
        processing_notes.insert(0,
            "ENRICHED mode: URL strings were submitted to external threat-intelligence "
            "services (URLhaus, and Google Safe Browsing if configured). "
            "No user personal data is transmitted — only URL strings."
        )

    # ── Log to DB (hash only — no personal data) ──────────────────────────────
    try:
        log_input = content or (filename or "") + f"|{len(file_bytes or b'')} bytes"
        log_analysis(
            input_content=log_input,
            input_type=input_type,
            verdict=verdict,
            risk_level=risk_level,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
        )
    except Exception:
        processing_notes.append("Database logging failed — analysis result unaffected.")

    # ── Build intel_results schema list ──────────────────────────────────────
    intel_results_schema = [_to_schema(r) for r in intel_results_raw]

    # ── Build response ────────────────────────────────────────────────────────
    return AnalysisResult(
        verdict=verdict,
        risk_level=risk_level,
        analysis_mode=effective_mode,
        evidence=all_evidence,
        extracted_text=extracted_text or None,
        extracted_urls=extracted_urls,
        url_analyses=url_analyses,
        intel_results=intel_results_schema,
        verdict_reasoning=reasoning,
        recommended_actions=actions,
        processing_notes=processing_notes,
        input_type_processed=input_type,
        high_severity_count=high_count,
        medium_severity_count=medium_count,
        low_severity_count=low_count,
    )


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    from backend.intelligence.urlhaus_provider import URLhausProvider
    from backend.intelligence.gsb_provider import GoogleSafeBrowsingProvider
    return {
        "status": "ok",
        "ml_model_loaded": _ml_model is not None,
        "intel_providers": {
            "urlhaus": URLhausProvider().is_available(),
            "google_safe_browsing": GoogleSafeBrowsingProvider().is_available(),
        },
        "disclaimer": (
            "CivicShield provides an evidence-based assessment and does not certify "
            "the authenticity of a government communication."
        ),
    }
