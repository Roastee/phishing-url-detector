"""Prediction module for phishing URL detection.

Provides a single source of truth for URL prediction,
used by both the API and the Streamlit UI.
"""

import json
import os
from typing import Dict, List

import joblib
import pandas as pd

from .features import FEATURE_NAMES, extract_features, feature_context

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "model.joblib")
METADATA_PATH = os.path.join(PROJECT_ROOT, "models", "metadata.json")

_model = None
_metadata = None
_scaler = None


def _load_model():
    """Lazy-load the model and metadata."""
    global _model, _metadata, _scaler
    if _model is None:
        loaded = joblib.load(MODEL_PATH)
        # Handle both old format (just model) and new format (dict with model/scaler)
        if isinstance(loaded, dict):
            _model = loaded.get('model', loaded)
            _scaler = loaded.get('scaler', None)
        else:
            _model = loaded
            _scaler = None
    if _metadata is None and os.path.exists(METADATA_PATH):
        with open(METADATA_PATH) as f:
            _metadata = json.load(f)
    return _model, _metadata


def predict_url(url: str) -> Dict:
    """Predict whether a URL is phishing or legitimate.

    Returns:
        Dict with keys: url, label, probability, risk_level, reasons
    """
    model, metadata = _load_model()
    features = extract_features(url)
    # Create DataFrame with proper feature names to avoid sklearn warnings
    feature_df = pd.DataFrame([[features[name] for name in FEATURE_NAMES]], columns=FEATURE_NAMES)

    # Apply scaling if scaler is available
    if _scaler is not None:
        feature_array = _scaler.transform(feature_df)
    else:
        feature_array = feature_df

    if hasattr(model, "predict_proba"):
        prob_phishing = float(model.predict_proba(feature_array)[0, 1])
    else:
        prob_phishing = 1.0 if model.predict(feature_array)[0] == 1 else 0.0

    # Cap probability at 99.9% to never show 100%
    prob_phishing = min(prob_phishing, 0.999)

    label = "phishing" if prob_phishing >= _metadata.get("threshold", 0.5) else "legitimate"
    if prob_phishing < 0.3:
        risk_level = "low"
    elif prob_phishing < 0.7:
        risk_level = "medium"
    else:
        risk_level = "high"

    # Build reasons from top contributing features
    reasons = _generate_reasons(features, url)

    return {
        "url": url,
        "label": label,
        "probability": prob_phishing,
        "risk_level": risk_level,
        "reasons": reasons[:5],
    }


def batch_predict(urls: List[str]) -> List[Dict]:
    """Predict for multiple URLs."""
    return [predict_url(url) for url in urls]


def _generate_reasons(features: Dict, url: str) -> List[Dict]:
    """Generate human-readable reasons for the prediction.

    Only uses features in FEATURE_NAMES. The impact is a simple
    heuristic based on feature values; for SHAP-based contributions
    use explain.explain_url.
    """
    ctx = feature_context(url)
    reasons = []

    # Only consider features that are actually in FEATURE_NAMES
    for fname in FEATURE_NAMES:
        val = features.get(fname, 0.0)
        # Skip zero-value features for brevity
        if val == 0.0:
            continue
        explanation = _explain_feature_simple(fname, val, ctx)
        # Simple impact: use the value itself as a rough impact
        # (This is not SHAP; for real contributions see explain.py)
        impact = val
        reasons.append({
            "feature": fname,
            "value": val,
            "impact": float(impact),
            "explanation": explanation,
        })

    # Sort by absolute impact
    reasons.sort(key=lambda x: abs(x["impact"]), reverse=True)
    return reasons


def _explain_feature_simple(name: str, value: float, ctx: dict) -> str:
    """Generate a plain-English explanation for a feature value."""
    if name == "host_length":
        return f"Host length is {value:.0f} characters"
    elif name == "dot_count":
        return f"Domain contains {value:.0f} dots"
    elif name == "hyphen_count":
        return f"Domain contains {value:.0f} hyphens"
    elif name == "underscore_count":
        return f"Domain contains {value:.0f} underscores"
    elif name == "digit_count":
        return f"Domain contains {value:.0f} digits"
    elif name == "digit_ratio":
        return f"Digits make up {value*100:.1f}% of the domain"
    elif name == "subdomain_count":
        return f"Domain has {value:.0f} subdomain levels"
    elif name == "is_suspicious_tld":
        if value > 0:
            return f"Uses suspicious TLD '{ctx.get('tld', '')}'"
        return "Uses a standard TLD"
    elif name == "uses_punycode":
        if value > 0:
            return "Uses punycode encoding"
        return "Uses standard ASCII"
    elif name == "has_ip_address":
        if value > 0:
            return "Hostname is an IP address"
        return "Hostname is a domain name"
    elif name == "longest_digit_run":
        return f"Longest digit run is {value:.0f} characters"
    elif name == "longest_consonant_run":
        return f"Longest consonant run is {value:.0f} characters"
    elif name == "brand_in_subdomain":
        if value > 0:
            brands = ', '.join(ctx.get('brands', [])) or 'a known brand'
            return f"Contains brand '{brands}' in subdomain"
        return "No brand impersonation"
    elif name == "suspicious_keyword_count":
        if value > 0:
            kws = ', '.join(ctx.get('suspicious_keywords', [])) or 'suspicious keywords'
            return f"Contains {value:.0f} suspicious keywords ({kws})"
        return "No suspicious keywords"
    elif name == "uses_url_shortener":
        if value > 0:
            return f"Uses URL shortener '{ctx.get('shortener', '')}'"
        return "Not a URL shortener"
    elif name == "host_entropy":
        return f"Host entropy is {value:.2f}"
    else:
        return f"{name} = {value:.2f}"