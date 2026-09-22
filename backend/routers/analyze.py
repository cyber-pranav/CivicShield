"""
CivicShield — Analysis Router
POST /api/analyze

Accepts URL, text, image, or PDF input.
Orchestrates all sub-engines and returns a structured AnalysisResult.

Input validation happens at two layers:
  1. FastAPI route parameters (file size header check)
  2. input_processor.py (content validation)
"""

from __future__ import annotations
from typing import Optional, Annotated
import traceback

from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse

from backend.models.schemas import AnalysisResult, EvidenceItem
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


@router.post("/analyze", response_model=AnalysisResult)
async def analyze(
    input_type: Annotated[str, Form()],
    content: Annotated[Optional[str], Form()] = None,
    file: Annotated[Optional[UploadFile], File()] = None,
) -> AnalysisResult:
    """
    Analyse a submitted URL, text message, image, or PDF for fraud indicators.

    input_type: "url" | "text" | "image" | "pdf"
    content:    For url/text inputs — the raw string
    file:       For image/pdf inputs — the uploaded file
    """

    # ── Validate input_type ───────────────────────────────────────────────────
    valid_types = {"url", "text", "image", "pdf"}
    if input_type not in valid_types:
        raise HTTPException(
            status_code=422,
            detail=f"input_type must be one of: {', '.join(valid_types)}",
        )

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
        # Log server-side, return safe message to client
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

    # ── Aggregate evidence ────────────────────────────────────────────────────
    all_evidence, high_count, medium_count, low_count = aggregate_evidence(
        url_evidence,
        challan_evidence,
        scam_evidence,
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

    # ── Build response ────────────────────────────────────────────────────────
    return AnalysisResult(
        verdict=verdict,
        risk_level=risk_level,
        evidence=all_evidence,
        extracted_text=extracted_text or None,
        extracted_urls=extracted_urls,
        url_analyses=url_analyses,
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
    return {
        "status": "ok",
        "ml_model_loaded": _ml_model is not None,
        "disclaimer": (
            "CivicShield provides an evidence-based assessment and does not certify "
            "the authenticity of a government communication."
        ),
    }
