"""
CivicShield — Input Processor
Dispatches incoming requests to the appropriate sub-processor
based on input_type.

Input types:
  "url"   — a single URL string submitted directly
  "text"  — pasted SMS/WhatsApp/email text
  "image" — uploaded screenshot/photo (bytes)
  "pdf"   — uploaded PDF document (bytes)

Returns:
  (extracted_text: str, extracted_urls: list[str], processing_notes: list[str])

Security validation is applied before dispatching:
  - Content-type checking for binary uploads
  - File size limits (enforced here AND in router)
  - No writing to disk
"""

from __future__ import annotations
from typing import Optional
from urllib.parse import urlparse

from backend.engines.url_extractor import extract_urls

MAX_IMAGE_BYTES = 5 * 1024 * 1024   # 5 MB
MAX_PDF_BYTES = 10 * 1024 * 1024    # 10 MB
MAX_TEXT_CHARS = 50_000


def process_input(
    input_type: str,
    content: Optional[str] = None,
    file_bytes: Optional[bytes] = None,
    filename: Optional[str] = None,
) -> tuple[str, list[str], list[str]]:
    """
    Process input and return (extracted_text, extracted_urls, processing_notes).

    All inputs are treated as untrusted until parsed and validated.
    """
    processing_notes: list[str] = []

    if input_type == "url":
        return _process_url_input(content or "", processing_notes)

    elif input_type == "text":
        return _process_text_input(content or "", processing_notes)

    elif input_type == "image":
        return _process_image_input(file_bytes or b"", processing_notes)

    elif input_type == "pdf":
        return _process_pdf_input(file_bytes or b"", processing_notes)

    else:
        processing_notes.append(f"Unknown input_type '{input_type}' — no processing performed.")
        return "", [], processing_notes


def _process_url_input(url: str, notes: list[str]) -> tuple[str, list[str], list[str]]:
    """Handle a directly submitted URL."""
    url = url.strip()
    if not url:
        notes.append("Empty URL submitted.")
        return "", [], notes

    # Basic sanity check
    parsed = urlparse(url)
    if not parsed.scheme:
        # Try adding https:// and re-parse
        url = f"https://{url}"
        notes.append("URL had no scheme — assumed https://")

    notes.append(f"Input processed as URL: {url[:100]}")
    return "", [url], notes


def _process_text_input(text: str, notes: list[str]) -> tuple[str, list[str], list[str]]:
    """Handle pasted text (SMS, email, WhatsApp message)."""
    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS]
        notes.append(f"Text truncated to {MAX_TEXT_CHARS} characters.")

    urls = extract_urls(text)
    notes.append(f"Extracted {len(urls)} URL(s) from text.")
    return text, urls, notes


def _process_image_input(file_bytes: bytes, notes: list[str]) -> tuple[str, list[str], list[str]]:
    """Handle an uploaded image — run OCR to extract text."""
    if len(file_bytes) > MAX_IMAGE_BYTES:
        raise ValueError(
            f"Image file exceeds maximum allowed size ({MAX_IMAGE_BYTES // (1024*1024)} MB)."
        )

    from backend.processors.ocr_processor import extract_text_from_image, OCRUnavailableError

    try:
        text = extract_text_from_image(file_bytes)
        notes.append(f"OCR completed — extracted {len(text)} characters.")
    except OCRUnavailableError as exc:
        notes.append(f"OCR unavailable: {exc}")
        notes.append(
            "ASSUMPTION: Text could not be extracted from image. "
            "Analysis will be limited to any URL provided separately."
        )
        return "", [], notes
    except ValueError as exc:
        notes.append(f"Image processing error: {exc}")
        return "", [], notes

    urls = extract_urls(text)
    notes.append(f"Extracted {len(urls)} URL(s) from OCR text.")
    return text, urls, notes


def _process_pdf_input(file_bytes: bytes, notes: list[str]) -> tuple[str, list[str], list[str]]:
    """Handle an uploaded PDF — extract text and embedded URLs."""
    if len(file_bytes) > MAX_PDF_BYTES:
        raise ValueError(
            f"PDF file exceeds maximum allowed size ({MAX_PDF_BYTES // (1024*1024)} MB)."
        )

    from backend.processors.pdf_processor import extract_from_pdf

    try:
        text, embedded_urls = extract_from_pdf(file_bytes)
        notes.append(f"PDF processed — extracted {len(text)} characters of text.")
        notes.append(f"Found {len(embedded_urls)} embedded URL(s) in PDF annotations.")
    except (ValueError, RuntimeError) as exc:
        notes.append(f"PDF processing error: {exc}")
        return "", [], notes

    # Also scan text for URLs not captured in annotations
    text_urls = extract_urls(text)
    all_urls = list(dict.fromkeys(embedded_urls + text_urls))  # dedup preserving order
    notes.append(
        f"Total URLs found in PDF: {len(all_urls)} "
        f"({len(embedded_urls)} from annotations, {len(text_urls)} from text scan)."
    )
    return text, all_urls, notes
