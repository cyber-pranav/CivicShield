import os
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.database import get_all_indicators, _SessionLocal, Indicator, init_db

from backend.limiter import limiter

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_teardown():
    limiter.reset()
    init_db()
    # Set fake admin key
    os.environ["ADMIN_API_KEY"] = "test-secret-key"
    
    # Cleanup DB before each test
    session = _SessionLocal()
    session.query(Indicator).delete()
    session.commit()
    session.close()
    
    yield
    
    # Cleanup after test
    session = _SessionLocal()
    session.query(Indicator).delete()
    session.commit()
    session.close()


def test_admin_requires_auth():
    response = client.post("/api/admin/indicators", json={
        "indicator_type": "phrase",
        "value": "fake phrase"
    })
    # Will fail missing header
    assert response.status_code == 422
    
    response = client.post("/api/admin/indicators", headers={"x-admin-key": "wrong-key"}, json={
        "indicator_type": "phrase",
        "value": "fake phrase"
    })
    assert response.status_code == 401


def test_crud_indicator():
    headers = {"x-admin-key": "test-secret-key"}
    
    # Create
    create_payload = {
        "indicator_type": "phrase",
        "value": "fake phrase",
        "category": "government_notice",
        "severity": "HIGH",
        "source": "manual",
        "description": "A test phrase"
    }
    response = client.post("/api/admin/indicators", headers=headers, json=create_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["value"] == "fake phrase"
    ind_id = data["id"]
    
    # List
    response = client.get("/api/admin/indicators", headers=headers)
    assert response.status_code == 200
    assert len(response.json()) == 1
    
    # Update
    response = client.patch(f"/api/admin/indicators/{ind_id}", headers=headers, json={"is_active": False})
    assert response.status_code == 200
    assert response.json()["is_active"] is False
    
    # Delete
    response = client.delete(f"/api/admin/indicators/{ind_id}", headers=headers)
    assert response.status_code == 200
    
    # List again
    response = client.get("/api/admin/indicators", headers=headers)
    assert len(response.json()) == 0


def test_dynamic_indicator_affects_analysis():
    headers = {"x-admin-key": "test-secret-key"}
    
    # Add a brand keyword
    client.post("/api/admin/indicators", headers=headers, json={
        "indicator_type": "brand_keyword",
        "value": "superfakebrand",
        "category": "government_notice",
        "severity": "HIGH",
        "source": "manual"
    })
    
    # Analyze a URL containing it
    response = client.post("/api/analyze", data={
        "input_type": "url",
        "content": "https://www.superfakebrand-login.com"
    })
    
    assert response.status_code == 200
    data = response.json()
    
    # It should have triggered a brand keyword impersonation
    found = False
    for ev in data["evidence"]:
        if "superfakebrand" in ev["finding"]:
            found = True
            break
            
    assert found is True
