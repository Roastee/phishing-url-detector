"""Unit tests for the prediction module."""

import warnings

from phishdetect.features import FEATURE_NAMES
from phishdetect.predict import predict_url, batch_predict


def test_predict_url_output_schema():
    """verify output has all required keys and correct types."""
    url = "https://example.com"
    result = predict_url(url)

    assert "url" in result
    assert "label" in result
    assert "probability" in result
    assert "risk_level" in result
    assert "reasons" in result

    assert result["label"] in ["phishing", "legitimate"]
    assert 0.0 <= result["probability"] <= 1.0
    assert result["risk_level"] in ["low", "medium", "high"]
    assert isinstance(result["reasons"], list)


def test_probability_in_valid_range():
    """probability should always be between 0 and 1."""
    urls = [
        "https://google.com",
        "http://bit.ly/abc123",
        "https://verify-paypal.login.tk/secure",
    ]
    for url in urls:
        result = predict_url(url)
        assert 0.0 <= result["probability"] <= 1.0


def test_obvious_phishing_scores_high():
    """phishing-like URLs should score higher than clean ones."""
    clean_url = "https://google.com"
    suspicious_url = "https://verify-paypal.login.tk/secure"

    clean_result = predict_url(clean_url)
    suspicious_result = predict_url(suspicious_url)

    # Suspicious should have higher probability
    assert suspicious_result["probability"] > clean_result["probability"]


def test_batch_predict():
    """batch endpoint handles multiple urls."""
    urls = ["https://google.com", "https://bit.ly/abc"]
    results = batch_predict(urls)

    assert len(results) == len(urls)
    for r in results:
        assert "probability" in r


def test_reason_names_in_feature_names():
    """Every reason name must be in FEATURE_NAMES."""
    urls = [
        "https://www.google.com/search?q=python",
        "http://paypal-secure-login-verify.xyz",
        "https://bit.ly/abc123",
        "https://verify-paypal.login.tk/secure",
    ]
    for url in urls:
        result = predict_url(url)
        for reason in result["reasons"]:
            assert reason["feature"] in FEATURE_NAMES, (
                f"Reason feature '{reason['feature']}' not in FEATURE_NAMES"
            )


def test_google_url_normalization_identical_probability():
    """google.com with/without scheme, www, path must give identical probabilities."""
    urls = [
        "https://www.google.com/search?q=python",
        "http://www.google.com/search?q=python",
        "https://www.google.com",
        "http://www.google.com",
        "https://google.com",
        "http://google.com",
        "google.com",
    ]
    probabilities = [predict_url(u)["probability"] for u in urls]
    first = probabilities[0]
    for i, p in enumerate(probabilities[1:], 1):
        assert p == first, (
            f"URL {i} ({urls[i]}) probability {p} differs from {first}"
        )


def test_predict_url_no_warnings():
    """predict_url should not raise any warnings."""
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        predict_url("https://www.google.com")
        predict_url("http://paypal-secure-login-verify.xyz")
        predict_url("https://bit.ly/abc123")