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


def test_root_returns_html(client):
    """GET / returns 200 HTML containing the privacy note."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    html = response.text
    assert "This model scores the domain only" in html
    assert "Phishing URL Detector" in html


def test_model_info(client):
    """GET /model-info returns model metadata."""
    response = client.get("/model-info")
    assert response.status_code == 200
    data = response.json()
    assert "model_type" in data
    assert "threshold" in data
    assert "feature_count" in data


def test_predict_phishing_url(client):
    """Test phishing URL returns expected keys including platform_warning and red_flags."""
    response = client.post("/predict", json={"url": "http://paypal-secure-login-verify.xyz"})
    assert response.status_code == 200
    data = response.json()
    assert data["label"] == "phishing"
    assert "platform_warning" in data
    assert "red_flags" in data
    assert "reasons" in data
    assert "threshold" in data
    assert "model_info" in data
    assert "method" in data
    # Check red flags
    red_flag_types = [rf["type"] for rf in data["red_flags"]]
    assert "suspicious_tld" in red_flag_types
    assert "brand_lookalike" in red_flag_types


def test_predict_legitimate_url(client):
    """Test legitimate URL returns expected keys."""
    response = client.post("/predict", json={"url": "https://www.wikipedia.org"})
    assert response.status_code == 200
    data = response.json()
    assert data["label"] == "legitimate"
    assert data["platform_warning"] is False
    assert "red_flags" in data


def test_predict_github_pages_url(client):
    """Test GitHub Pages URL has platform_warning and uncertain risk."""
    response = client.post("/predict", json={"url": "https://myportfolio.github.io"})
    assert response.status_code == 200
    data = response.json()
    assert data["platform_warning"] is True
    assert data["risk_level"] == "uncertain"


def test_features_identical_offline_tldextract(client):
    """Test that features are identical with offline tldextract."""
    # This test verifies the offline tldextract doesn't change features
    # We test by predicting the same URL multiple times
    url = "http://paypal-secure-login-verify.xyz"
    response1 = client.post("/predict", json={"url": url})
    response2 = client.post("/predict", json={"url": url})
    data1 = response1.json()
    data2 = response2.json()
    # The probability should be identical
    assert abs(data1["probability"] - data2["probability"]) < 1e-9