"""Metadata consistency tests."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from phishdetect.features import FEATURE_NAMES


def test_feature_names_match():
    """Test that metadata feature_names matches FEATURE_NAMES."""
    metadata_path = os.path.join(os.path.dirname(__file__), "..", "models", "metadata.json")
    with open(metadata_path) as f:
        metadata = json.load(f)
    
    assert metadata["feature_names"] == FEATURE_NAMES, (
        f"metadata.feature_names != FEATURE_NAMES\n"
        f"metadata: {metadata['feature_names']}\n"
        f"FEATURE_NAMES: {FEATURE_NAMES}"
    )
    assert metadata["feature_count"] == len(FEATURE_NAMES), (
        f"feature_count mismatch: {metadata['feature_count']} != {len(FEATURE_NAMES)}"
    )

def test_deployed_model_matches_file():
    """Test that deployed model in metadata matches the actual model file."""
    metadata_path = os.path.join(os.path.dirname(__file__), "..", "models", "metadata.json")
    with open(metadata_path) as f:
        metadata = json.load(f)
    
    # The model file is model.joblib
    model_path = os.path.join(os.path.dirname(__file__), "..", "models", "model.joblib")
    assert os.path.exists(model_path), f"Model file not found: {model_path}"
    
    import joblib
    bundle = joblib.load(model_path)
    
    # Check deployed_model matches
    assert metadata["deployed_model"] == "XGBoost", (
        f"Expected deployed_model=XGBoost, got {metadata['deployed_model']}"
    )
    
    # Check feature_names in model bundle matches
    if "feature_names" in bundle:
        assert bundle["feature_names"] == metadata["feature_names"], (
            "model.joblib feature_names != metadata.feature_names"
        )

def test_threshold_matches_predict_py():
    """Test that threshold in metadata matches what predict.py uses."""
    metadata_path = os.path.join(os.path.dirname(__file__), "..", "models", "metadata.json")
    with open(metadata_path) as f:
        metadata = json.load(f)
    
    metadata_threshold = metadata["threshold"]
    
    # Check predict.py uses _metadata.get("threshold")
    predict_path = os.path.join(os.path.dirname(__file__), "..", "src", "phishdetect", "predict.py")
    with open(predict_path, encoding="utf-8") as f:
        predict_content = f.read()
    
    # The decision line must reference _metadata threshold
    assert '_metadata.get("threshold"' in predict_content, (
        "predict.py does not read threshold from metadata"
    )
    # Should not have hardcoded 0.5
    assert 'prob_phishing >= 0.5' not in predict_content, (
        "predict.py still uses hardcoded 0.5 threshold"
    )
    
    # Verify the threshold value
    assert metadata_threshold == 0.58, f"Expected threshold 0.58, got {metadata_threshold}"

def test_metadata_threshold_matches_metrics():
    """Test that metadata threshold matches metrics.json deployment_info."""
    metadata_path = os.path.join(os.path.dirname(__file__), "..", "models", "metadata.json")
    metrics_path = os.path.join(os.path.dirname(__file__), "..", "reports", "metrics.json")
    
    with open(metadata_path) as f:
        metadata = json.load(f)
    with open(metrics_path) as f:
        metrics = json.load(f)
    
    dep = metrics.get("deployment_info", {})
    assert metadata["threshold"] == dep.get("default_threshold"), (
        f"metadata.threshold={metadata['threshold']} != "
        f"metrics.deployment_info.default_threshold={dep.get('default_threshold')}"
    )
    assert metadata["threshold"] == metrics["threshold_selection"]["default_threshold"], (
        "metadata.threshold != metrics.threshold_selection.default_threshold"
    )