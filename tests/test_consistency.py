"""Consistency tests: ensure metadata, metrics, predict.py, and app.py agree."""
import json
import os
import re


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")


def _load_metadata():
    with open(os.path.join(MODELS_DIR, "metadata.json")) as f:
        return json.load(f)


def _load_metrics():
    with open(os.path.join(REPORTS_DIR, "metrics.json")) as f:
        return json.load(f)


def test_metadata_threshold_matches_metrics():
    meta = _load_metadata()
    metrics = _load_metrics()
    dep = metrics.get("deployment_info", {})
    assert meta["threshold"] == dep.get("default_threshold"), (
        f"metadata.threshold={meta['threshold']} != "
        f"metrics.deployment_info.default_threshold={dep.get('default_threshold')}"
    )
    assert meta["threshold"] == metrics["threshold_selection"]["default_threshold"], (
        "metadata.threshold != metrics.threshold_selection.default_threshold"
    )


def test_deployed_model_consistent():
    meta = _load_metadata()
    metrics = _load_metrics()
    assert meta["deployed_model"] == metrics["deployment_info"]["deployed_model"], (
        "metadata.deployed_model != metrics.deployment_info.deployed_model"
    )
    # In-distribution test metrics must exist for the deployed model
    assert meta["deployed_model"] in metrics["in_distribution_test"], (
        f"metrics.in_distribution_test missing {meta['deployed_model']}"
    )


def test_feature_names_consistent():
    meta = _load_metadata()
    metrics = _load_metrics()
    dep = metrics.get("deployment_info", {})
    assert meta["feature_names"] == dep.get("feature_names"), (
        "metadata.feature_names != metrics.deployment_info.feature_names"
    )


def test_predict_py_uses_metadata_threshold():
    predict_path = os.path.join(PROJECT_ROOT, "src", "phishdetect", "predict.py")
    with open(predict_path, encoding="utf-8") as f:
        content = f.read()
    # The decision line must reference _metadata threshold, not a hardcoded 0.5
    assert re.search(r'_metadata\.get\("threshold"', content), (
        "predict.py does not read threshold from metadata"
    )
    # The literal hardcoded decision should not exist anymore
    assert 'prob_phishing >= 0.5' not in content, (
        "predict.py still uses a hardcoded 0.5 threshold"
    )


def test_model_joblib_threshold_matches():
    import joblib
    bundle = joblib.load(os.path.join(MODELS_DIR, "model.joblib"))
    meta = _load_metadata()
    assert bundle.get("threshold") == meta["threshold"], (
        f"model.joblib threshold={bundle.get('threshold')} != "
        f"metadata.threshold={meta['threshold']}"
    )
    assert bundle.get("feature_names") == meta["feature_names"], (
        "model.joblib feature_names != metadata.feature_names"
    )


def test_independent_test_fpr_present():
    metrics = _load_metrics()
    indep = metrics.get("independent_test", {})
    # At least one ratio-based entry must have an fpr
    fprs = [v.get("fpr") for v in indep.values() if isinstance(v, dict)]
    assert any(f is not None for f in fprs), "independent_test has no fpr"