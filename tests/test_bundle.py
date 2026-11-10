"""Tests for the Vercel deployment bundle."""

import sys
import pytest
from fastapi.testclient import TestClient

# Import the app from the bundle
sys.path.insert(0, "src")
from api.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_root_returns_html(client):
    """GET / returns 200 HTML containing the privacy note."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    html = response.text
    assert "This model scores the domain only" in html
    assert "Phishing URL Detector" in html


def test_model_info(client):
    """GET /model-info returns model metadata with all required fields."""
    response = client.get("/model-info")
    assert response.status_code == 200
    data = response.json()
    
    # Required fields present and non-zero/non-empty
    assert "model_type" in data
    assert data["model_type"]
    assert "threshold" in data
    assert data["threshold"] is not None
    assert "feature_count" in data
    assert data["feature_count"] is not None
    assert "in_distribution" in data
    assert data["in_distribution"]
    assert "independent_1to1" in data
    assert data["independent_1to1"]
    assert "independent_1to10" in data
    assert data["independent_1to10"]
    assert "recall_free_hosted" in data
    assert data["recall_free_hosted"]
    assert "recall_non_free_hosted" in data
    assert data["recall_non_free_hosted"]
    assert "note_1to3000" in data
    assert data["note_1to3000"]
    
    # Check in_distribution has required keys
    in_dist = data["in_distribution"]
    assert "accuracy" in in_dist
    assert "test_set_size" in in_dist
    assert "source" in in_dist
    
    # Check independent_1to1 has required keys
    ind_1to1 = data["independent_1to1"]
    assert "accuracy" in ind_1to1
    assert "confusion_matrix" not in ind_1to1  # We use test_set_size instead
    assert "source" in ind_1to1
    assert "precision_ci" in ind_1to1
    assert "recall_ci" in ind_1to1
    
    # Check independent_1to10 has required keys
    ind_1to10 = data["independent_1to10"]
    assert "accuracy" in ind_1to10
    assert "source" in ind_1to10
    assert "precision_ci" in ind_1to10
    assert "recall_ci" in ind_1to10


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
    assert data["method"] == "xgboost-contributions"
    
    # Check red flags
    red_flag_types = [rf["type"] for rf in data["red_flags"]]
    assert "suspicious_tld" in red_flag_types
    assert "brand_lookalike" in red_flag_types
    
    # Check reasons have direction
    for reason in data["reasons"]:
        assert "direction" in reason
        assert reason["direction"] in ["raises", "lowers"]


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


def test_predict_validation_empty_url(client):
    """Empty URL returns 422 validation error."""
    response = client.post("/predict", json={"url": ""})
    assert response.status_code == 422


def test_predict_validation_long_url(client):
    """URL exceeding max length returns 422."""
    long_url = "https://" + "a" * 2050
    response = client.post("/predict", json={"url": long_url})
    assert response.status_code == 422