"""Tests for the FastAPI API module."""

import pytest
from fastapi.testclient import TestClient
from api.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_health_check(client):
    """GET /health returns ok status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "model_version" in data


def test_predict_success(client):
    """POST /predict returns valid result."""
    response = client.post("/predict", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.json()
    assert "label" in data
    assert "probability" in data
    assert data["label"] in ["phishing", "legitimate"]
    assert 0 <= data["probability"] <= 1


def test_predict_validation_empty_url(client):
    """Empty URL returns 422 validation error."""
    response = client.post("/predict", json={"url": ""})
    assert response.status_code == 422


def test_predict_validation_long_url(client):
    """URL exceeding max length returns 422."""
    long_url = "https://" + "a" * 2050
    response = client.post("/predict", json={"url": long_url})
    assert response.status_code == 422


def test_batch_predict(client):
    """POST /predict/batch handles multiple URLs."""
    response = client.post("/predict/batch", json={"urls": ["https://google.com", "https://facebook.com"]})
    assert response.status_code == 200
    data = response.json()
    assert "results" in data
    assert len(data["results"]) == 2


def test_batch_predict_limit(client):
    """Batch with more than 100 URLs returns error."""
    urls = ["https://example.com"] * 101
    response = client.post("/predict/batch", json={"urls": urls})
    assert response.status_code == 422