"""
CivicShield — Rate Limiter Tests
"""

import pytest
from fastapi.testclient import TestClient
from backend.main import app
from slowapi.errors import RateLimitExceeded
from backend.limiter import limiter

client = TestClient(app)

def test_rate_limiter_blocks_excessive_requests(monkeypatch):
    """
    Test that hitting the /health endpoint more than 60 times
    within a minute from the same IP yields a 429 response.
    """
    # Reset limiter for clean state before testing
    limiter.reset()

    # The limit is 60/minute for health. Let's send 60 successful requests.
    for i in range(60):
        response = client.get("/api/health", headers={"X-Forwarded-For": "192.168.1.100"})
        assert response.status_code == 200, f"Request {i+1} failed prematurely."

    # The 61st request should be blocked.
    response = client.get("/api/health", headers={"X-Forwarded-For": "192.168.1.100"})
    
    assert response.status_code == 429
    data = response.json()
    assert "error" in data
    assert "Rate limit exceeded" in data["error"]
