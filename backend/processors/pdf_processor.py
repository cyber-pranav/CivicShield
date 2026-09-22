"""
CivicShield — PDF Processor
Extracts text and embedded URLs from uploaded PDF files using PyMuPDF (fitz).

SECURITY NOTE:
  - PDFs are processed in-memory via bytes — NOT saved to disk
  - PDFs are NOT executed or rendered to a browser
  - JavaScript within PDFs is NOT evaluated (PyMuPDF does not execute JS)
  - Encrypted PDFs: extraction attempted but gracefully handled if locked

File size limit: enforced in the router (10MB max)
"""

from __future__ import annotations
import io
import re
from typing import Optional


def extract_from_pdf(pdf_bytes: bytes) -> tuple[str, list[str]]:
    """
    Extract text content and embedded URLs from a PDF file.

    Args:
        pdf_bytes: Raw bytes of the PDF file.

    Returns:
        (extracted_text, embedded_urls)
        - extracted_text: All text concatenated across pages
        - embedded_urls: URLs found in PDF link annotations

    Raises:
        ValueError: If the bytes are not a valid PDF.
        RuntimeError: If PyMuPDF is not installed.
    """
    try:
        import fitz  # PyMuPDF
    except ImportError:
        raise RuntimeError(
            "PyMuPDF is not installed. Install with: pip install PyMuPDF"
        )

    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception as exc:
        raise ValueError(f"Could not open PDF: {exc}") from exc

    text_parts: list[str] = []
    embedded_urls: list[str] = []
    seen_urls: set[str] = set()

    for page_num in range(len(doc)):
        page = doc[page_num]

        # Extract text
        page_text = page.get_text("text")
        if page_text.strip():
            text_parts.append(page_text)

        # Extract link annotations (these may contain URLs not visible in text)
        for link in page.get_links():
            if link.get("kind") == fitz.LINK_URI:
                uri = link.get("uri", "").strip()
                if uri and uri not in seen_urls:
                    seen_urls.add(uri)
                    embedded_urls.append(uri)

    doc.close()

    full_text = "\n\n--- Page Break ---\n\n".join(text_parts)
    return full_text.strip(), embedded_urls
