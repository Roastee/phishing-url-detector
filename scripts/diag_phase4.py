"""Phase 4 diagnostics script."""
import json
from phishdetect.features import FEATURE_NAMES, extract_features, feature_context
from phishdetect.predict import predict_url
import joblib
import pandas as pd
import numpy as np

# Test URL
url = "http://paypal-secure-login-verify.xyz"

print("=" * 60)
print("URL:", url)
print("=" * 60)

# Extract features
features = extract_features(url)
print("\nExtracted Features:")
for k, v in features.items():
    if v != 0:
        print(f"  {k}: {v}")

# Get prediction
result = predict_url(url)
print("\nPrediction:")
print(f"  Label: {result['label']}")
print(f"  Probability: {result['probability']}")
print(f"  Risk Level: {result['risk_level']}")
print("\nPredict Reasons:")
for reason in result['reasons']:
    print(f"  {reason['feature']}: val={reason['value']}, impact={reason['impact']}, {reason['explanation']}")

# Get feature context
ctx = feature_context(url)
print("\nFeature Context:")
print(f"  Suspicious keywords: {ctx['suspicious_keywords']}")
print(f"  Brands: {ctx['brands']}")
print(f"  TLD: {ctx['tld']}")
print(f"  Shortener: {ctx['shortener']}")
print(f"  Is IP: {ctx['is_ip']}")
print(f"  Host: {ctx['host']}")

# Global feature importance using the model's feature_importances_
print("\n" + "=" * 60)
print("Global Feature Importance (model.feature_importances_)")
print("=" * 60)

model_data = joblib.load('models/model.joblib')
model = model_data['model']

if hasattr(model, 'feature_importances_'):
    importances = model.feature_importances_
    for i, fname in enumerate(FEATURE_NAMES):
        print(f"  {fname}: {importances[i]:.6f}")

# Test legitimate long domains
print("\n" + "=" * 60)
print("Long Legitimate Domains")
print("=" * 60)
legit_domains = [
    "https://metropolitanmuseumofart.org",
    "https://massachusettsgeneralhospital.org",
    "https://northeasternuniversity.edu",
    "https://brighamandwomenshospital.org",
    "https://johnshopkinsmedicine.org",
]
for d in legit_domains:
    r = predict_url(d)
    print(f"  {d}: prob={r['probability']:.4f}, label={r['label']}")

# Test short phishing lookalikes
print("\n" + "=" * 60)
print("Short Phishing Lookalikes")
print("=" * 60)
phish_domains = [
    "http://paypa1.tk",
    "http://amaz0n.xyz",
    "http://micros0ft.ml",
    "http://g00gle.ga",
    "http://faceb00k.cf",
]
for d in phish_domains:
    r = predict_url(d)
    print(f"  {d}: prob={r['probability']:.4f}, label={r['label']}")