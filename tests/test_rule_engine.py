"""
CivicShield — Rule Engine Unit Tests

Tests the e-Challan Rule Engine and Scam Language Engine.

Run with: python -m pytest tests/test_rule_engine.py -v
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from backend.engines.challan_rule_engine import analyze_challan_text
from backend.engines.scam_language_engine import analyze_scam_language
from backend.models.schemas import EvidenceItem


def _find_by_rule_id(items: list[EvidenceItem], rule_id: str) -> list[EvidenceItem]:
    return [e for e in items if e.rule_id == rule_id]


def _has_severity(items: list[EvidenceItem], severity: str) -> bool:
    return any(e.severity == severity for e in items)


# ─────────────────────────────────────────────────────────────────────────────
# APK download request detection
# ─────────────────────────────────────────────────────────────────────────────

def test_apk_download_detected():
    text = "Your challan is pending. Please download the app from this link to pay: bit.ly/xyz.apk"
    evidence = analyze_challan_text(text)
    apk_items = _find_by_rule_id(evidence, "APK_DOWNLOAD_REQUEST")
    assert len(apk_items) == 1
    assert apk_items[0].severity == "HIGH"


def test_install_app_detected():
    text = "Install the application to avoid vehicle seizure."
    evidence = analyze_challan_text(text)
    apk_items = _find_by_rule_id(evidence, "APK_DOWNLOAD_REQUEST")
    assert len(apk_items) == 1


# ─────────────────────────────────────────────────────────────────────────────
# OTP / credential request detection
# ─────────────────────────────────────────────────────────────────────────────

def test_otp_request_detected():
    text = "Please share OTP received on your registered number to complete challan payment."
    evidence = analyze_challan_text(text)
    otp_items = _find_by_rule_id(evidence, "OTP_CREDENTIAL_REQUEST")
    assert len(otp_items) == 1
    assert otp_items[0].severity == "HIGH"


def test_password_request_detected():
    text = "Enter your password to access the challan portal."
    evidence = analyze_challan_text(text)
    otp_items = _find_by_rule_id(evidence, "OTP_CREDENTIAL_REQUEST")
    assert len(otp_items) == 1


# ─────────────────────────────────────────────────────────────────────────────
# UPI payment request detection
# ─────────────────────────────────────────────────────────────────────────────

def test_upi_id_detected():
    text = "Pay your challan of Rs 500 via UPI ID: traffic@okaxis immediately."
    evidence = analyze_challan_text(text)
    upi_items = _find_by_rule_id(evidence, "UPI_PAYMENT_REQUEST")
    assert len(upi_items) == 1
    assert upi_items[0].severity == "HIGH"


def test_google_pay_mention_detected():
    text = "Scan and pay via Google Pay or PhonePe to clear your challan."
    evidence = analyze_challan_text(text)
    upi_items = _find_by_rule_id(evidence, "UPI_PAYMENT_REQUEST")
    assert len(upi_items) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Arrest / legal threat detection
# ─────────────────────────────────────────────────────────────────────────────

def test_arrest_threat_detected():
    text = "If you do not pay within 24 hours, an FIR will be filed and you will be arrested."
    evidence = analyze_challan_text(text)
    arrest_items = _find_by_rule_id(evidence, "ARREST_THREAT")
    assert len(arrest_items) == 1
    assert arrest_items[0].severity == "HIGH"


def test_warrant_threat_detected():
    text = "A non-bailable warrant has been issued against your vehicle registration."
    evidence = analyze_challan_text(text)
    arrest_items = _find_by_rule_id(evidence, "ARREST_THREAT")
    assert len(arrest_items) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Urgent payment deadline
# ─────────────────────────────────────────────────────────────────────────────

def test_urgent_payment_detected():
    text = "This is your final notice. Pay immediately to avoid legal action."
    evidence = analyze_challan_text(text)
    urgent_items = _find_by_rule_id(evidence, "URGENT_PAYMENT_DEADLINE")
    assert len(urgent_items) == 1
    assert urgent_items[0].severity == "MEDIUM"


# ─────────────────────────────────────────────────────────────────────────────
# Genuine signals
# ─────────────────────────────────────────────────────────────────────────────

def test_official_portal_reference_genuine():
    text = "Check your challan at echallan.parivahan.gov.in using your vehicle number."
    evidence = analyze_challan_text(text)
    genuine_items = [e for e in evidence if e.evidence_type == "GENUINE_SIGNAL"]
    assert len(genuine_items) >= 1


def test_challan_number_format_genuine():
    text = "Your Challan No: CH2024098765 has been issued. Visit parivahan.gov.in to pay."
    evidence = analyze_challan_text(text)
    genuine_items = [e for e in evidence if e.evidence_type == "GENUINE_SIGNAL"]
    assert len(genuine_items) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# Scam language engine
# ─────────────────────────────────────────────────────────────────────────────

def test_secrecy_instruction_detected():
    text = "Do not share this message with anyone. This is confidential."
    evidence = analyze_scam_language(text)
    secrecy_items = _find_by_rule_id(evidence, "SECRECY_INSTRUCTION")
    assert len(secrecy_items) == 1
    assert secrecy_items[0].severity == "HIGH"


def test_prize_claim_detected():
    text = "Congratulations! You have won a cash prize of Rs 50,000."
    evidence = analyze_scam_language(text)
    prize_items = _find_by_rule_id(evidence, "PRIZE_REWARD_CLAIM")
    assert len(prize_items) == 1


def test_urgency_language_detected():
    text = "Act now! This is your last chance to avoid penalty."
    evidence = analyze_scam_language(text)
    urgency_items = _find_by_rule_id(evidence, "URGENCY_LANGUAGE")
    assert len(urgency_items) == 1
    assert urgency_items[0].severity == "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# Empty input handling
# ─────────────────────────────────────────────────────────────────────────────

def test_empty_text_returns_empty_evidence():
    assert analyze_challan_text("") == []
    assert analyze_scam_language("") == []


def test_none_text_handled_gracefully():
    # None is handled by the engine returning empty list
    assert analyze_challan_text(None) == []
