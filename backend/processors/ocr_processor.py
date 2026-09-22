"""
CivicShield — OCR Processor
Extracts text from uploaded image files using pytesseract (Tesseract OCR).

ASSUMPTION: Tesseract OCR must be installed as a system package.
  - Windows: https://github.com/UB-Mannheim/tesseract/wiki
  - Linux: sudo apt-get install tesseract-ocr
  - macOS: brew install tesseract

If Tesseract is not installed, this module will raise OCRUnavailableError
with a clear error message — it will NOT silently fail.

Supported image formats: JPEG, PNG, BMP, TIFF, WebP (via Pillow)
File size limit: enforced in the router (5MB)

SECURITY NOTE: Uploaded images are NOT saved to disk.
They are processed in-memory via BytesIO and immediately discarded.
"""

from __future__ import annotations
import io
from PIL import Image


class OCRUnavailableError(RuntimeError):
    """Raised when Tesseract is not installed or not on PATH."""
    pass


def extract_text_from_image(image_bytes: bytes) -> str:
    """
    Run OCR on image bytes and return extracted text.

    Args:
        image_bytes: Raw bytes of the image file.

    Returns:
        Extracted text string (may be empty if image has no readable text).

    Raises:
        OCRUnavailableError: If Tesseract is not installed.
        ValueError: If the image format is not supported or the bytes are corrupt.
    """
    try:
        import pytesseract
    except ImportError:
        raise OCRUnavailableError(
            "pytesseract is not installed. Install it with: pip install pytesseract. "
            "Also install Tesseract OCR from https://github.com/UB-Mannheim/tesseract/wiki"
        )

    try:
        img = Image.open(io.BytesIO(image_bytes))
    except Exception as exc:
        raise ValueError(f"Could not open image: {exc}") from exc

    # Convert to RGB if needed (handles RGBA, palette images, etc.)
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")

    try:
        text = pytesseract.image_to_string(img, lang="eng")
    except pytesseract.TesseractNotFoundError:
        raise OCRUnavailableError(
            "Tesseract OCR executable not found. "
            "Install Tesseract from https://github.com/UB-Mannheim/tesseract/wiki "
            "and ensure it is on your system PATH."
        )

    return text.strip()
