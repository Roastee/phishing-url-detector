"""Prediction module for phishing URL detection.

Provides a single source of truth for URL prediction,
used by both the API and the Streamlit UI.
"""

import json
import os
from typing import Dict, List

import joblib
import numpy as np

from .features import FEATURE_NAMES, extract_features, feature_context, compute_red_flags, compute_platform_warning

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
        Dict with keys: url, label, probability, risk_level, reasons,
        platform_warning, red_flags, threshold, model_info, method
    """
    model, metadata = _load_model()
    features = extract_features(url)
    ctx = feature_context(url)
    # Create numpy array with proper feature order
    feature_array = np.array([[features[name] for name in FEATURE_NAMES]], dtype=np.float64)

    # Apply scaling if scaler is available
    if _scaler is not None:
        # Avoid sklearn warning about feature names by temporarily setting them
        original_feature_names = getattr(_scaler, "feature_names_in_", None)
        _scaler.feature_names_in_ = np.array(FEATURE_NAMES, dtype=object)
        feature_array = _scaler.transform(feature_array)
        # Restore original feature names
        if original_feature_names is not None:
            _scaler.feature_names_in_ = original_feature_names
        else:
            delattr(_scaler, "feature_names_in_")

    if hasattr(model, "predict_proba"):
        prob_phishing = float(model.predict_proba(feature_array)[0, 1])
    else:
        prob_phishing = 1.0 if model.predict(feature_array)[0] == 1 else 0.0

    # Cap probability at 99.9% to never show 100%
    prob_phishing = min(prob_phishing, 0.999)

    threshold = _metadata.get("threshold", 0.5)
    label = "phishing" if prob_phishing >= threshold else "legitimate"
    if prob_phishing < 0.3:
        risk_level = "low"
    elif prob_phishing < 0.7:
        risk_level = "medium"
    else:
        risk_level = "high"

    # Build reasons from top contributing features (with direction)
    reasons = _generate_reasons(features, url, threshold)

    # Compute red flags
    red_flags = compute_red_flags(url, ctx)

    # Compute platform warning
    platform_warning = compute_platform_warning(url, ctx)

    # If platform warning, adjust risk level to "uncertain" for display
    if platform_warning:
        risk_level = "uncertain"

    model_info = {
        "model_type": metadata.get("deployed_model", "XGBoost"),
        "threshold": threshold,
        "feature_count": metadata.get("feature_count", 17),
    }

    return {
        "url": url,
        "label": label,
        "probability": prob_phishing,
        "risk_level": risk_level,
        "reasons": reasons[:5],
        "platform_warning": platform_warning,
        "red_flags": red_flags,
        "threshold": threshold,
        "model_info": model_info,
        "method": "heuristic",  # or "shap" if SHAP is used
    }


def batch_predict(urls: List[str]) -> List[Dict]:
    """Predict for multiple URLs."""
    return [predict_url(url) for url in urls]


def _generate_reasons(features: Dict, url: str, threshold: float = 0.5) -> List[Dict]:
    """Generate human-readable reasons for the prediction.

    Only uses features in FEATURE_NAMES. The impact is a simple
    heuristic based on feature values; for SHAP-based contributions
    use explain.explain_url.

    Args:
        features: Dict of feature values
        url: The URL being analyzed
        threshold: Decision threshold (used to determine direction)
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
        # Determine direction: raises or lowers risk
        # Features that are typically phishing indicators raise risk
        phishing_indicators = {
            "is_suspicious_tld", "uses_punycode", "has_ip_address",
            "brand_in_subdomain", "suspicious_keyword_count", "uses_url_shortener",
            "host_entropy", "on_known_hosting_platform"
        }
        # Features that are typically legitimate indicators lower risk
        legitimate_indicators = set()  # None in our current feature set
        if fname in phishing_indicators:
            direction = "raises"
        elif fname in legitimate_indicators:
            direction = "lowers"
        else:
            # For continuous features, use correlation with phishing
            # Higher values of these typically indicate phishing
            if fname in ["host_length", "dot_count", "hyphen_count", "underscore_count",
                         "digit_count", "digit_ratio", "subdomain_count",
                         "longest_digit_run", "longest_consonant_run"]:
                direction = "raises"
            else:
                direction = "neutral"
        reasons.append({
            "feature": fname,
            "value": val,
            "impact": float(impact),
            "direction": direction,
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