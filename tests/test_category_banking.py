import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_banking_phishing_basic():
    """Test a standard banking phishing SMS."""
    payload = {
        "input_type": "text",
        "content": "Dear customer your a/c is blocked. Update PAN immediately via http://update-pan-sbi.xyz"
    }
    response = client.post("/api/analyze", data=payload)
    assert response.status_code == 200
    data = response.json()
    
    # Should resolve to banking_phishing category
    assert data["detected_category"] == "banking_phishing"
    assert data["verdict"] == "Likely Fraudulent"
    assert data["risk_level"] == "HIGH"
    
    # Check that banking-specific recommended actions are present
    actions = data["recommended_actions"]
    assert any("Contact your bank directly" in a for a in actions)
    assert any("Never share your OTP" in a for a in actions)
    
    # Verify the rule matched
    evidence_ids = [e["rule_id"] for e in data["evidence"]]
    assert "ACCOUNT_BLOCKED_BANKING" in evidence_ids

def test_banking_phishing_db_phrase():
    """Test banking phishing detected via dynamic DB phrases."""
    # Note: We rely on the language rules matching for now as the DB is wiped in testing.
    # But we can test the financial reward rule from YAML.
    payload = {
        "input_type": "text",
        "content": "Redeem reward points up to 5000 Rs today. Click here http://hdfcbank-rewards.tk"
    }
    response = client.post("/api/analyze", data=payload)
    assert response.status_code == 200
    data = response.json()
    
    assert data["detected_category"] == "banking_phishing"
    assert data["verdict"] == "Likely Fraudulent"
    evidence_ids = [e["rule_id"] for e in data["evidence"]]
    assert "FINANCIAL_REWARD_SCAM" in evidence_ids

def test_mixed_signals_priority():
    """
    Test mixed signals: government_notice + banking_phishing.
    Must resolve to government_notice due to the priority ladder.
    """
    payload = {
        "input_type": "text",
        "content": "E-challan generated for vehicle MH01AB1234. Pay fine immediately or your bank account blocked. Update PAN immediately."
    }
    response = client.post("/api/analyze", data=payload)
    assert response.status_code == 200
    data = response.json()
    
    # Check that both rules fired
    evidence_ids = [e["rule_id"] for e in data["evidence"]]
    assert any(eid in evidence_ids for eid in ["VEHICLE_NUMBER_FORMAT", "CHALLAN_KEYWORD", "CHALLAN_IMPERSONATION"])
    assert "ACCOUNT_BLOCKED_BANKING" in evidence_ids
    
    # Priority ladder must enforce government_notice
    assert data["detected_category"] == "government_notice"
