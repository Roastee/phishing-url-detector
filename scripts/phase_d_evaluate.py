"""Phase D: Independent Real-World Evaluation

Run this after building the independent test set with phase_d_build_test_set.py
"""
import os
import pandas as pd
import numpy as np
import joblib
import json

from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix
)

# Load model
model_data = joblib.load('models/model.joblib')
model = model_data['model']
scaler = model_data['scaler']

# Load features
from src.phishdetect.features import extract_features, FEATURE_NAMES

# Load independent test set
phish_df = pd.read_csv('data/independent_test/phishing.csv')
popular_df = pd.read_csv('data/independent_test/legitimate_popular.csv')
long_tail_df = pd.read_csv('data/independent_test/legitimate_long_tail.csv')

print(f"Phishing: {len(phish_df)}")
print(f"Legitimate (popular): {len(popular_df)}")
print(f"Legitimate (long-tail): {len(long_tail_df)}")

# Combine
all_legit = pd.concat([popular_df, long_tail_df], ignore_index=True)
df = pd.concat([phish_df, all_legit], ignore_index=True)

print(f"\nTotal independent test URLs: {len(df)}")

# Extract features
print("Extracting features...")
X_feat = []
for url in df['URL']:
    X_feat.append(extract_features(url))
X = pd.DataFrame(X_feat)
y = df['Label'].values

# Scale
X_scaled = scaler.transform(X)

# Predict
y_pred = model.predict(X_scaled)
y_proba = model.predict_proba(X_scaled)[:, 1]

# Evaluate overall
metrics = {
    'accuracy': accuracy_score(y, y_pred),
    'precision': precision_score(y, y_pred),
    'recall': recall_score(y, y_pred),
    'f1': f1_score(y, y_pred),
    'roc_auc': roc_auc_score(y, y_proba),
    'pr_auc': average_precision_score(y, y_proba),
    'confusion_matrix': confusion_matrix(y, y_pred).tolist(),
}

print("\n=== Independent Test Results (Overall) ===")
for k, v in metrics.items():
    if k != 'confusion_matrix':
        print(f"  {k}: {v:.4f}")
    else:
        print(f"  {k}: {v}")

# Evaluate per slice
print("\n=== Per-Slice Results ===")
slices = {
    'popular': popular_df,
    'long_tail': long_tail_df
}

for name, legit_df in slices.items():
    slice_df = pd.concat([phish_df, legit_df], ignore_index=True)
    X_feat = []
    for url in slice_df['URL']:
        X_feat.append(extract_features(url))
    X = pd.DataFrame(X_feat)
    X_scaled = scaler.transform(X)
    y_slice = slice_df['Label'].values
    y_pred = model.predict(X_scaled)
    y_proba = model.predict_proba(X_scaled)[:, 1]
    
    cm = confusion_matrix(y_slice, y_pred)
    fpr = cm[0, 1] / (cm[0, 0] + cm[0, 1]) if (cm[0, 0] + cm[0, 1]) > 0 else 0
    
    m = {
        'precision': precision_score(y_slice, y_pred),
        'recall': recall_score(y_slice, y_pred),
        'f1': f1_score(y_slice, y_pred),
        'roc_auc': roc_auc_score(y_slice, y_proba),
        'confusion_matrix': cm.tolist(),
        'false_positive_rate': fpr,
    }
    print(f"\n  {name} slice:")
    for k, v in m.items():
        if k != 'confusion_matrix':
            print(f"    {k}: {v:.4f}")
        else:
            print(f"    {k}: {v}")

# Load in-distribution metrics for comparison
with open('reports/metrics.json') as f:
    in_dist = json.load(f)

lr_in = in_dist['in_distribution_test']['LogisticRegression']

print("\n=== Generalization Gap ===")
print(f"In-distribution F1:     {lr_in['f1']:.4f}")
print(f"Independent F1 (overall): {metrics['f1']:.4f}")
print(f"Gap:                    {lr_in['f1'] - metrics['f1']:.4f}")

# Save results
results = {
    'independent_test': metrics,
    'per_slice': {},
    'generalization_gap': {
        'f1_gap': float(lr_in['f1'] - metrics['f1']),
        'precision_gap': float(lr_in['precision'] - metrics['precision']),
        'recall_gap': float(lr_in['recall'] - metrics['recall']),
    }
}
with open('reports/independent_metrics.json', 'w') as f:
    json.dump(results, f, indent=2)

print("\nSaved to reports/independent_metrics.json")