"""SHAP-based explainability module for phishing URL predictions."""

import os
import numpy as np
import pandas as pd

from .features import FEATURE_NAMES, extract_features, feature_context
from .predict import _load_model, _scaler

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
REPORTS_PATH = os.path.join(PROJECT_ROOT, "reports")

_explainer = None


def _get_explainer():
    """Get or create the SHAP explainer for the model."""
    global _explainer
    if _explainer is None:
        model, _ = _load_model()
        try:
            import shap
        except ImportError:
            raise ImportError("shap is required for explainability features. Install it with: pip install shap")
        if hasattr(model, 'coef_'):
            _explainer = shap.LinearExplainer(model, np.zeros((1, len(FEATURE_NAMES))))
        else:
            _explainer = shap.TreeExplainer(model)
    return _explainer


def explain_url(url: str, max_reasons: int = 5) -> dict:
    """Generate SHAP-based explanation for a single URL."""
    model, _ = _load_model()
    features = extract_features(url)
    # Use DataFrame with proper feature names to avoid sklearn warnings
    feature_df = pd.DataFrame([[features[name] for name in FEATURE_NAMES]], columns=FEATURE_NAMES)

    if _scaler is not None:
        feature_array = _scaler.transform(feature_df)
    else:
        feature_array = feature_df

    explainer = _get_explainer()
    shap_values = explainer.shap_values(feature_array)

    if isinstance(shap_values, list):
        shap_vals = shap_values[1][0]
    else:
        shap_vals = shap_values[0]

    base_value = explainer.expected_value
    if isinstance(base_value, (list, np.ndarray)):
        base_value = base_value[1] if len(base_value) > 1 else base_value[0]

    ctx = feature_context(url)
    reasoning = []
    for i, fname in enumerate(FEATURE_NAMES):
        val = features[fname]
        impact = float(shap_vals[i]) if not np.isnan(shap_vals[i]) else 0.0
        reasoning.append({
            "feature": fname,
            "value": val,
            "impact": impact,
            "explanation": _explain_feature(fname, val, impact, ctx),
        })

    reasoning.sort(key=lambda x: abs(x["impact"]), reverse=True)

    return {
        "shap_values": shap_vals.tolist(),
        "base_value": float(base_value),
        "reasons": reasoning[:max_reasons],
    }


def _explain_feature(name: str, value: float, impact: float, ctx: dict) -> str:
    """Generate human-readable explanation for a feature."""
    if name == "host_length":
        base = f"Host length is {value:.0f} characters"
    elif name == "dot_count":
        base = f"Domain contains {value:.0f} dots"
    elif name == "hyphen_count":
        base = f"Domain contains {value:.0f} hyphens"
    elif name == "underscore_count":
        base = f"Domain contains {value:.0f} underscores"
    elif name == "digit_count":
        base = f"Domain contains {value:.0f} digits"
    elif name == "digit_ratio":
        base = f"Digits make up {value*100:.1f}% of the domain"
    elif name == "subdomain_count":
        base = f"Domain has {value:.0f} subdomain levels"
    elif name == "is_suspicious_tld":
        base = "Uses a suspicious TLD" if value > 0 else "Uses a standard TLD"
    elif name == "uses_punycode":
        base = "Uses punycode encoding" if value > 0 else "Uses standard ASCII"
    elif name == "has_ip_address":
        base = "Hostname is an IP address" if value > 0 else "Hostname is a domain name"
    elif name == "longest_digit_run":
        base = f"Longest digit run is {value:.0f} characters"
    elif name == "longest_consonant_run":
        base = f"Longest consonant run is {value:.0f} characters"
    elif name == "brand_in_subdomain":
        if value > 0:
            brands = ', '.join(ctx.get('brands', [])) or 'a known brand'
            base = f"Contains brand '{brands}' in subdomain"
        else:
            base = "No brand impersonation"
    elif name == "suspicious_keyword_count":
        if value > 0:
            kws = ', '.join(ctx.get('suspicious_keywords', [])) or 'suspicious keywords'
            base = f"Contains {value:.0f} suspicious keywords ({kws})"
        else:
            base = "No suspicious keywords"
    elif name == "uses_url_shortener":
        if value > 0:
            base = f"Uses URL shortener '{ctx.get('shortener', '')}'"
        else:
            base = "Not a URL shortener"
    elif name == "host_entropy":
        base = f"Host entropy is {value:.2f}"
    else:
        base = f"{name} = {value:.2f}"

    if impact > 0:
        return base + " — increases phishing risk."
    elif impact < 0:
        return base + " — decreases phishing risk."
    else:
        return base + " — neutral."


def generate_global_plot(sample_size: int = 500, output_path: str = None) -> str:
    """Generate a global SHAP summary plot."""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed, skipping plot")
        return None

    import pandas as pd
    # Load training data
    X_train = pd.read_pickle(os.path.join(PROJECT_ROOT, "reports", "X_train.pkl"))

    if len(X_train) > sample_size:
        X_sample = X_train.sample(n=sample_size, random_state=42)
    else:
        X_sample = X_train

    model, _ = _load_model()

    X_scaled = _scaler.transform(X_sample) if _scaler is not None else X_sample

    explainer = _get_explainer()
    shap_values = explainer.shap_values(X_scaled)

    if isinstance(shap_values, list):
        shap_vals = shap_values[1]
    else:
        shap_vals = shap_values

    if output_path is None:
        output_path = os.path.join(REPORTS_PATH, "shap_summary.png")

    os.makedirs(REPORTS_PATH, exist_ok=True)

    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    plt.figure(figsize=(10, 8))
    shap.summary_plot(shap_vals, X_sample, feature_names=FEATURE_NAMES, show=False)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()

    return output_path