"""
CivicShield — End-to-End API Integration Tests

Tests POST /api/analyze across URL, text, image, and PDF inputs,
verifying response schemas, exact verdicts, error semantics, and
the 5 synthetic demo cases.
"""

import sys
import io
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from backend.main import app

client = TestClient(app)


# ─────────────────────────────────────────────────────────────────────────────
# Health Check
# ─────────────────────────────────────────────────────────────────────────────

def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "disclaimer" in data


# ─────────────────────────────────────────────────────────────────────────────
# Schema & Contract Verification on /api/analyze
# ─────────────────────────────────────────────────────────────────────────────

def _assert_valid_analysis_response(data: dict):
    """Verify all fields required by backend/models/schemas.py and frontend types."""
    required_fields = [
        "verdict",
        "risk_level",
        "evidence",
        "extracted_text",
        "extracted_urls",
        "url_analyses",
        "verdict_reasoning",
        "recommended_actions",
        "official_verification_url",
        "disclaimer",
        "processing_notes",
        "input_type_processed",
        "high_severity_count",
        "medium_severity_count",
        "low_severity_count",
    ]
    for field in required_fields:
        assert field in data, f"Missing required response field: '{field}'"

    assert data["verdict"] in ("Likely Genuine", "Likely Fraudulent", "Unable to Verify")
    assert data["risk_level"] in ("HIGH", "MEDIUM", "LOW", "UNKNOWN")
    assert isinstance(data["evidence"], list)
    assert isinstance(data["processing_notes"], list)
    assert isinstance(data["recommended_actions"], list)
    assert data["official_verification_url"] == "https://echallan.parivahan.gov.in/"
    assert "does not certify" in data["disclaimer"]

    # Verify count integrity
    highs = sum(1 for e in data["evidence"] if e["severity"] == "HIGH")
    meds = sum(1 for e in data["evidence"] if e["severity"] == "MEDIUM")
    lows = sum(1 for e in data["evidence"] if e["severity"] == "LOW")
    assert data["high_severity_count"] == highs
    assert data["medium_severity_count"] == meds
    assert data["low_severity_count"] == lows


# ─────────────────────────────────────────────────────────────────────────────
# URL Inputs (Acceptance Matrix Cases 1 - 5)
# ─────────────────────────────────────────────────────────────────────────────

def test_case_1_official_url():
    """CASE 1: https://echallan.parivahan.gov.in/ -> Likely Genuine, LOW."""
    response = client.post("/api/analyze", data={"input_type": "url", "content": "https://echallan.parivahan.gov.in/"})
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["verdict"] == "Likely Genuine"
    assert data["risk_level"] == "LOW"


def test_case_2_ip_url():
    """CASE 2: http://192.168.1.1/echallan/pay -> Likely Fraudulent, HIGH."""
    response = client.post("/api/analyze", data={"input_type": "url", "content": "http://192.168.1.1/echallan/pay"})
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["verdict"] == "Likely Fraudulent"
    assert data["risk_level"] == "HIGH"


def test_case_3_apk_url():
    """CASE 3: http://192.168.1.1/echallan.apk -> Likely Fraudulent, HIGH."""
    response = client.post("/api/analyze", data={"input_type": "url", "content": "http://192.168.1.1/echallan.apk"})
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["verdict"] == "Likely Fraudulent"
    assert data["risk_level"] == "HIGH"


def test_case_4_xyz_tld_url():
    """CASE 4: https://echallan-parivahan.xyz/pay -> Likely Fraudulent, HIGH."""
    response = client.post("/api/analyze", data={"input_type": "url", "content": "https://echallan-parivahan.xyz/pay"})
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["verdict"] == "Likely Fraudulent"
    assert data["risk_level"] == "HIGH"


def test_case_5_lookalike_suffix():
    """CASE 5: https://echallan.parivahan.gov.in.evil.com/ -> NOT Likely Genuine."""
    response = client.post("/api/analyze", data={"input_type": "url", "content": "https://echallan.parivahan.gov.in.evil.com/"})
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["verdict"] != "Likely Genuine"


# ─────────────────────────────────────────────────────────────────────────────
# Malformed and Unsupported URLs (Cases 14 & 15)
# ─────────────────────────────────────────────────────────────────────────────

def test_case_14_malformed_url():
    """CASE 14: Malformed URL -> NOT Likely Genuine (deterministic Unable to Verify)."""
    response = client.post("/api/analyze", data={"input_type": "url", "content": "hello not a url"})
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["verdict"] != "Likely Genuine"
    assert data["verdict"] == "Unable to Verify"
    assert any("invalid url format" in n.lower() for n in data["processing_notes"])


def test_case_15_unsupported_url_scheme():
    """CASE 15: Unsupported scheme -> NOT Likely Genuine."""
    response = client.post("/api/analyze", data={"input_type": "url", "content": "javascript:alert(1)"})
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["verdict"] != "Likely Genuine"
    assert data["verdict"] == "Unable to Verify"
    assert any("unsupported url scheme" in n.lower() for n in data["processing_notes"])


def test_empty_url_input():
    """Empty URL input -> NOT Likely Genuine."""
    response = client.post("/api/analyze", data={"input_type": "url", "content": ""})
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["verdict"] != "Likely Genuine"
    assert data["verdict"] == "Unable to Verify"


# ─────────────────────────────────────────────────────────────────────────────
# Text Cases (Cases 6 - 11)
# ─────────────────────────────────────────────────────────────────────────────

def test_case_6_one_high_signal():
    """CASE 6: One HIGH signal only -> Unable to Verify."""
    # Only arrest threat, no other signals
    text = "An FIR will be filed against you."
    response = client.post("/api/analyze", data={"input_type": "text", "content": text})
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["high_severity_count"] == 1
    assert data["verdict"] == "Unable to Verify"
    assert data["risk_level"] == "MEDIUM"


def test_case_7_two_high_signals():
    """CASE 7: Two HIGH signals (OTP + UPI) -> Likely Fraudulent, HIGH."""
    text = "Please share OTP to pay challan via UPI ID: traffic@okaxis immediately."
    response = client.post("/api/analyze", data={"input_type": "text", "content": text})
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["high_severity_count"] >= 2
    assert data["verdict"] == "Likely Fraudulent"
    assert data["risk_level"] == "HIGH"


def test_case_10_no_signals_no_official_domain():
    """CASE 10: No suspicious signals + no official domain -> Unable to Verify."""
    text = "Hello, your vehicle registration check is complete. Have a safe journey."
    response = client.post("/api/analyze", data={"input_type": "text", "content": text})
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["high_severity_count"] == 0
    assert data["medium_severity_count"] == 0
    assert data["verdict"] == "Unable to Verify"
    assert data["risk_level"] == "LOW"


def test_case_11_official_url_with_high_suspicious_evidence():
    """CASE 11: Official URL + HIGH signal -> NEVER Likely Genuine."""
    text = (
        "Pay your challan at https://echallan.parivahan.gov.in/ "
        "and share your secret OTP immediately or you will be arrested."
    )
    response = client.post("/api/analyze", data={"input_type": "text", "content": text})
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["verdict"] != "Likely Genuine"


# ─────────────────────────────────────────────────────────────────────────────
# Image & PDF Failure Semantics (Cases 12 & 13)
# ─────────────────────────────────────────────────────────────────────────────

def test_case_12_empty_image():
    """CASE 12: Image with no readable text -> NOT Likely Genuine (Unable to Verify)."""
    # Create a small blank white PNG in-memory
    img = Image.new("RGB", (100, 100), color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    response = client.post(
        "/api/analyze",
        data={"input_type": "image"},
        files={"file": ("blank.png", buf.getvalue(), "image/png")},
    )
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["verdict"] != "Likely Genuine"
    assert data["verdict"] == "Unable to Verify"


def test_case_12_corrupt_image():
    """Corrupt image bytes -> Unable to Verify with clear processing error note."""
    corrupt_bytes = b"NOT_AN_IMAGE_FILE_DATA_RANDOM_CORRUPTION"
    response = client.post(
        "/api/analyze",
        data={"input_type": "image"},
        files={"file": ("corrupt.png", corrupt_bytes, "image/png")},
    )
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["verdict"] != "Likely Genuine"
    assert data["verdict"] == "Unable to Verify"
    assert any("error" in n.lower() or "image" in n.lower() for n in data["processing_notes"])


def test_case_13_corrupt_pdf():
    """CASE 13: Corrupt PDF -> Unable to Verify with processing error note."""
    corrupt_bytes = b"NOT_A_VALID_PDF_STREAM"
    response = client.post(
        "/api/analyze",
        data={"input_type": "pdf"},
        files={"file": ("corrupt.pdf", corrupt_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["verdict"] != "Likely Genuine"
    assert data["verdict"] == "Unable to Verify"
    assert any("pdf" in n.lower() for n in data["processing_notes"])


def test_case_13_pdf_no_extractable_text():
    """PDF with no extractable text -> Unable to Verify."""
    import fitz
    doc = fitz.open()
    doc.new_page()  # blank page
    pdf_bytes = doc.tobytes()
    doc.close()

    response = client.post(
        "/api/analyze",
        data={"input_type": "pdf"},
        files={"file": ("blank.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["verdict"] != "Likely Genuine"
    assert data["verdict"] == "Unable to Verify"


def test_case_13_pdf_with_visible_official_url():
    """PDF with visible official e-Challan URL -> Likely Genuine."""
    import fitz
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text(
        (50, 72),
        "Traffic Challan Notice: Pay at https://echallan.parivahan.gov.in/ for DL 01 AB 1234"
    )
    pdf_bytes = doc.tobytes()
    doc.close()

    response = client.post(
        "/api/analyze",
        data={"input_type": "pdf"},
        files={"file": ("notice.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["verdict"] == "Likely Genuine"
    assert data["risk_level"] == "LOW"


def test_case_13_pdf_with_embedded_phishing_url():
    """PDF with embedded phishing link annotation -> Likely Fraudulent."""
    import fitz
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((50, 72), "Click here to pay your pending challan")
    link = {
        "kind": fitz.LINK_URI,
        "from": fitz.Rect(50, 60, 200, 80),
        "uri": "http://echallan-parivahan.xyz/pay",
    }
    page.insert_link(link)
    pdf_bytes = doc.tobytes()
    doc.close()

    response = client.post(
        "/api/analyze",
        data={"input_type": "pdf"},
        files={"file": ("phish.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["verdict"] == "Likely Fraudulent"
    assert data["risk_level"] == "HIGH"


# ─────────────────────────────────────────────────────────────────────────────
# Five Synthetic Demo Cases (Section 20)
# ─────────────────────────────────────────────────────────────────────────────

def test_demo_a_genuine_echallan():
    """Demo A: Genuine-looking e-Challan -> Likely Genuine."""
    content = (
        "Traffic Challan Notice - Ministry of Road Transport & Highways\n\n"
        "Dear Vehicle Owner,\n"
        "A traffic challan has been issued against your vehicle (DL 01 AB 1234) for violation of Rule 119(1).\n"
        "Challan No: CH2024MH098765\n"
        "Amount Due: Rs. 1,000/-\n"
        "Pay online at the official government portal: https://echallan.parivahan.gov.in/\n"
        "For queries, visit: https://parivahan.gov.in/"
    )
    response = client.post("/api/analyze", data={"input_type": "text", "content": content})
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["verdict"] == "Likely Genuine"
    assert data["risk_level"] == "LOW"


def test_demo_b_lookalike_domain():
    """Demo B: Fake e-Challan Lookalike Domain -> Likely Fraudulent."""
    content = (
        "URGENT: Traffic Challan Issued Against Your Vehicle (MH 12 XY 9988).\n"
        "Challan Amount: Rs. 2,000/-\n"
        "Pay now to avoid legal action: http://echallan-parivahan-gov.xyz/pay?id=9988\n"
        "This is your FINAL NOTICE. Pay within 24 hours."
    )
    response = client.post("/api/analyze", data={"input_type": "text", "content": content})
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["verdict"] == "Likely Fraudulent"
    assert data["risk_level"] == "HIGH"


def test_demo_c_apk_download():
    """Demo C: Fake e-Challan APK Download -> Likely Fraudulent."""
    content = (
        "[Important] Your Vehicle Challan Is Pending. Challan No: 2024/RTO/45821.\n"
        "Download the official RTO Challan Payment App: http://rto-pay-india.ml/download/rto_challan_v2.apk\n"
        "Install the app, enter your vehicle number and pay securely.\n"
        "Do not share this link with anyone. Valid for 48 hours only."
    )
    response = client.post("/api/analyze", data={"input_type": "text", "content": content})
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["verdict"] == "Likely Fraudulent"
    assert data["risk_level"] == "HIGH"


def test_demo_d_urgent_arrest_language():
    """Demo D: Urgent arrest threats -> Likely Fraudulent."""
    content = (
        "FINAL LEGAL NOTICE — NON-BAILABLE WARRANT.\n"
        "Your vehicle (TN 22 AB 5566) has unpaid challans.\n"
        "You will be ARRESTED if payment is not made TODAY.\n"
        "An FIR will be filed under Motor Vehicle Act.\n"
        "Pay immediately: https://bit.ly/3fakechallan"
    )
    response = client.post("/api/analyze", data={"input_type": "text", "content": content})
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["verdict"] == "Likely Fraudulent"
    assert data["risk_level"] == "HIGH"


def test_demo_e_upi_payment():
    """Demo E: Suspicious UPI payment -> Likely Fraudulent."""
    content = (
        "Traffic Violation Notice for Vehicle GJ 01 ZZ 2233. Amount: Rs. 3,200.\n"
        "Please pay via UPI immediately. UPI ID: traffic.challan@okaxis\n"
        "Google Pay / PhonePe accepted. Payment deadline: Today before 11:59 PM."
    )
    response = client.post("/api/analyze", data={"input_type": "text", "content": content})
    assert response.status_code == 200
    data = response.json()
    _assert_valid_analysis_response(data)
    assert data["verdict"] == "Likely Fraudulent"
    assert data["risk_level"] == "HIGH"
