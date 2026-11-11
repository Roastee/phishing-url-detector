#!/usr/bin/env python
"""Equivalence proof: compare joblib bundle (old) vs Booster (new) predictions."""
import joblib
import json
import numpy as np
import xgboost as xgb
from pathlib import Path

# Load joblib bundle (old path)
bundle = joblib.load('models/model.joblib')
scaler = bundle['scaler']
model_old = bundle['model']  # XGBoost model in sklearn wrapper
feature_names = bundle['feature_names']

# Load metadata (new path scaler values)
with open('models/metadata.json') as f:
    metadata = json.load(f)

scaler_mean_new = np.array(metadata['scaler_mean'], dtype=np.float64)
scaler_scale_new = np.array(metadata['scaler_scale'], dtype=np.float64)

print("=== Scaler comparison ===")
print(f"Old mean shape: {scaler.mean_.shape}")
print(f"New mean shape: {scaler_mean_new.shape}")
print(f"Max |mean diff|: {np.max(np.abs(scaler.mean_ - scaler_mean_new)):.10e}")
print(f"Max |scale diff|: {np.max(np.abs(scaler.scale_ - scaler_scale_new)):.10e}")

# Load Booster model (new path)
booster = xgb.Booster()
booster.load_model('models/model.ubj')

# Load test data
# Use independent test data
import pandas as pd

# Load phishing URLs
phishing_df = pd.read_csv('data/independent_test/phishing.csv')
print(f"\nPhishing URLs: {len(phishing_df)}")

# Load legitimate URLs (popular)
legit_popular = pd.read_csv('data/independent_test/legitimate_popular.csv')
print(f"Legitimate popular URLs: {len(legit_popular)}")

# Load legitimate long tail
legit_long = pd.read_csv('data/independent_test/legitimate_long_tail.csv')
print(f"Legitimate long tail URLs: {len(legit_long)}")

# Combine for a mixed set - take a sample to get 2000+ URLs
np.random.seed(42)
phishing_sample = phishing_df.sample(n=min(298, len(phishing_df)), random_state=42)
legit_sample = pd.concat([
    legit_popular.sample(n=min(8891, len(legit_popular)), random_state=42),
    legit_long.sample(n=min(1200, len(legit_long)), random_state=42)
])

test_urls = list(phishing_sample['URL'].values) + list(legit_sample['URL'].values)
print(f"\nTotal test URLs: {len(test_urls)}")

# Import feature extraction
import sys
sys.path.insert(0, 'src')
from phishdetect.features import extract_features, FEATURE_NAMES

def predict_old(url):
    """Old path: joblib bundle with sklearn wrapper."""
    features = extract_features(url)
    x = np.array([[features[name] for name in FEATURE_NAMES]], dtype=np.float64)
    x_scaled = (x - scaler.mean_) / scaler.scale_
    prob = model_old.predict_proba(x_scaled)[0, 1]
    return float(prob)

def predict_new(url):
    """New path: Booster with manual scaling from metadata."""
    features = extract_features(url)
    x = np.array([[features[name] for name in FEATURE_NAMES]], dtype=np.float64)
    x_scaled = (x - scaler_mean_new) / scaler_scale_new
    dmatrix = xgb.DMatrix(x_scaled)
    prob = float(booster.predict(dmatrix)[0])
    return prob

# Compare on all test URLs
print("\n=== Probability comparison ===")
max_diff = 0.0
diffs = []
max_url = ""
max_p_old = 0.0
max_p_new = 0.0
for i, url in enumerate(test_urls):
    p_old = predict_old(url)
    p_new = predict_new(url)
    diff = abs(p_old - p_new)
    diffs.append(diff)
    if diff > max_diff:
        max_diff = diff
        max_url = url
        max_p_old = p_old
        max_p_new = p_new

print(f"Max absolute probability difference: {max_diff:.10e}")
if max_url:
    print(f"  URL: {max_url}")
    print(f"  Old: {max_p_old:.10f}")
    print(f"  New: {max_p_new:.10f}")
print(f"Mean diff: {np.mean(diffs):.10e}")
print(f"Median diff: {np.median(diffs):.10e}")
print(f"99th percentile diff: {np.percentile(diffs, 99):.10e}")

# Also test 30 edge cases
print("\n=== Edge cases ===")
edge_cases = [
    "http://example.com",
    "https://example.com",
    "http://www.example.com",
    "https://www.example.com",
    "example.com",
    "http://192.168.1.1",
    "https://192.168.1.1",
    "http://paypal.com",
    "https://paypal.com",
    "http://paypal-secure-login.xyz",
    "https://paypal-secure-login.xyz",
    "http://bit.ly/abc123",
    "https://bit.ly/abc123",
    "http://xn--example.com",
    "https://xn--example.com",
    "http://github.io",
    "https://github.io",
    "http://myapp.herokuapp.com",
    "https://myapp.herokuapp.com",
    "http://localhost",
    "https://localhost",
    "http://example.tk",
    "https://example.tk",
    "http://verify-account-login.ml",
    "https://verify-account-login.ml",
    "http://example.com:8080/path",
    "https://example.com:8080/path",
    "http://sub.domain.example.com",
    "https://sub.domain.example.com",
    "http://example.com/very/long/path/with/many/segments/here",
]

for url in edge_cases:
    p_old = predict_old(url)
    p_new = predict_new(url)
    diff = abs(p_old - p_new)
    if diff > 1e-10:
        print(f"  {url}: old={p_old:.10f}, new={p_new:.10f}, diff={diff:.2e}")

print(f"\n=== RESULT ===")
print(f"Max absolute probability difference across {len(test_urls)} URLs: {max_diff:.10e}")
print(f"Target (< 1e-6): {'PASS' if max_diff < 1e-6 else 'FAIL'}")