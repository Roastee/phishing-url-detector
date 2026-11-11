"""Prediction module for phishing URL detection.

Provides a single source of truth for URL prediction,
using xgboost.Booster directly with manual scaling.
"""

import json
from pathlib import Path
from typing import Dict, List

import numpy as np
import xgboost as xgb

from .features import FEATURE_NAMES, extract_features, feature_context, compute_red_flags, compute_platform_warning

# Resolve paths relative to this file's location (src/phishdetect/)
BASE_DIR = Path(__file__).resolve().parents[2]  # repo root

def _resolve_model_path(filename: str) -> Path:
    candidates = [
        BASE_DIR / "models" / filename,
        Path.cwd() / "models" / filename,
        Path(__file__).resolve().parents[1] / "models" / filename,
    ]
    for c in candidates:
        if c.exists():
            return c
    return candidates[0]

MODEL_UBJ_PATH = _resolve_model_path("model.ubj")
METADATA_PATH = _resolve_model_path("metadata.json")

_booster = None
_metadata = None
_scaler_mean = None
_scaler_scale = None


def _load_model() -> tuple:
    """Lazy-load the booster and metadata."""
    global _booster, _metadata, _scaler_mean, _scaler_scale
    if _booster is None:
        model_path = _resolve_model_path("model.ubj")
        _booster = xgb.Booster()
        _booster.load_model(str(model_path))
    if _metadata is None:
        meta_path = _resolve_model_path("metadata.json")
        with open(meta_path, "r") as f:
            _metadata = json.load(f)
        _scaler_mean = np.array(_metadata["scaler_mean"], dtype=np.float64)
        _scaler_scale = np.array(_metadata["scaler_scale"], dtype=np.float64)
    return _booster, _metadata


def predict_url(url: str) -> Dict:
    """Predict whether a URL is phishing or legitimate.

    Returns:
        Dict with keys: url, label, probability, risk_level, reasons,
        platform_warning, red_flags, threshold, model_info, method
    """
    booster, metadata = _load_model()
    features = extract_features(url)
    ctx = feature_context(url)

    # Create feature array and apply scaling manually: (x - mean) / scale
    feature_array = np.array([[features[name] for name in FEATURE_NAMES]], dtype=np.float64)
    feature_array = (feature_array - _scaler_mean) / _scaler_scale

    # Predict with booster (output_margin=False gives probability)
    dmatrix = xgb.DMatrix(feature_array)
    prob_phishing = float(booster.predict(dmatrix)[0])

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

    # Build reasons from real XGBoost feature contributions (pred_contribs)
    reasons = _generate_reasons_from_contributions(booster, feature_array, features, url, ctx)

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
        "method": "xgboost-contributions",
    }


def batch_predict(urls: List[str]) -> List[Dict]:
    """Predict for multiple URLs."""
    return [predict_url(url) for url in urls]


def _generate_reasons_from_contributions(booster: xgb.Booster, feature_array: np.ndarray, raw_features: dict, url: str, ctx: dict) -> List[Dict]:
    """Generate reasons from XGBoost feature contributions (SHAP-like).

    Returns top 5 features by absolute contribution with direction.
    """
    dmatrix = xgb.DMatrix(feature_array)
    # pred_contribs returns (n_samples, n_features + 1) where last column is bias
    contribs = booster.predict(dmatrix, pred_contribs=True)
    # contribs shape: (1, 18) - 17 features + 1 bias
    feature_contribs = contribs[0, :-1]  # exclude bias
    _ = contribs[0, -1]  # bias (unused)

    reasons = []
    for i, fname in enumerate(FEATURE_NAMES):
        val = raw_features.get(fname, 0.0)
        contrib = float(feature_contribs[i])
        # Skip zero contributions for brevity
        if contrib == 0.0:
            continue
        explanation = _explain_feature_simple(fname, val, ctx)
        direction = "raises" if contrib > 0 else "lowers"
        reasons.append({
            "feature": fname,
            "value": val,
            "impact": contrib,
            "direction": direction,
            "explanation": explanation,
        })

    # Sort by absolute contribution
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
    elif name == "on_known_hosting_platform":
        if value > 0:
            return "Hosted on a known free hosting platform"
        return "Not on a known free hosting platform"
    else:
        return f"{name} = {value:.2f}"