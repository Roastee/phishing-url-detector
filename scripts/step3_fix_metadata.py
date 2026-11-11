#!/usr/bin/env python
"""Fix metadata.json with correct metrics from reports/*.json."""
import json
import os

# Load source metrics
with open('reports/metrics.json') as f:
    metrics = json.load(f)

with open('reports/independent_metrics.json') as f:
    independent_metrics = json.load(f)

# Load existing metadata to preserve other fields
with open('models/metadata.json') as f:
    metadata = json.load(f)

# Extract XGBoost in-distribution metrics
xgb_in_dist = metrics['in_distribution_test']['XGBoost']

# Extract independent test ratios
ratio_1_to_1 = metrics['independent_test']['ratio_1_to_1']
ratio_1_to_10 = metrics['independent_test']['ratio_1_to_10']

# Extract recall CIs for free-hosted vs non-free-hosted
recall_free = metrics['recall_free_hosting_bootstrap_95ci']
recall_non_free = metrics['recall_non_free_hosting_bootstrap_95ci']

# The 1:3000 run (from independent_metrics.json)
indep_3000 = independent_metrics['independent_test']

# Build new metadata structure
new_metadata = {
    "deployed_model": metadata["deployed_model"],
    "feature_count": metadata["feature_count"],
    "feature_names": metadata["feature_names"],
    "threshold": metadata["threshold"],
    "threshold_precision_090": metadata["threshold_precision_090"],
    "threshold_low_fpr_2pct": metadata["threshold_low_fpr_2pct"],
    "training_date": metadata["training_date"],
    "model_comparison": metadata["model_comparison"],
    "scaler_mean": metadata["scaler_mean"],
    "scaler_scale": metadata["scaler_scale"],
    
    # FIXED: in_distribution_metrics -> XGBoost in_distribution_test
    "in_distribution": {
        "accuracy": xgb_in_dist["accuracy"],
        "precision": xgb_in_dist["precision"],
        "recall": xgb_in_dist["recall"],
        "f1": xgb_in_dist["f1"],
        "roc_auc": xgb_in_dist["roc_auc"],
        "fpr": xgb_in_dist["fpr"],
        "test_set_size": {
            "phishing": 2524,  # from training: 2524 phishing in test split
            "legitimate": 2524,  # from training: 2524 legitimate in test split
            "total": 5048
        },
        "source": "reports/metrics.json:in_distribution_test.XGBoost"
    },
    
    # FIXED: independent_test_metrics -> split into 1:1 and 1:10 with CIs
    "independent_1to1": {
        "accuracy": ratio_1_to_1["accuracy"],
        "precision": ratio_1_to_1["precision"],
        "recall": ratio_1_to_1["recall"],
        "f1": ratio_1_to_1["f1"],
        "roc_auc": ratio_1_to_1["roc_auc"],
        "pr_auc": ratio_1_to_1["pr_auc"],
        "fpr": ratio_1_to_1["fpr"],
        "precision_ci": [ratio_1_to_1["precision_ci_lower"], ratio_1_to_1["precision_ci_upper"]],
        "recall_ci": [ratio_1_to_1["recall_ci_lower"], ratio_1_to_1["recall_ci_upper"]],
        "f1_ci": [ratio_1_to_1["f1_ci_lower"], ratio_1_to_1["f1_ci_upper"]],
        "roc_auc_ci": [ratio_1_to_1["roc_auc_ci_lower"], ratio_1_to_1["roc_auc_ci_upper"]],
        "pr_auc_ci": [ratio_1_to_1["pr_auc_ci_lower"], ratio_1_to_1["pr_auc_ci_upper"]],
        "fpr_ci": [ratio_1_to_1["fpr_ci_lower"], ratio_1_to_1["fpr_ci_upper"]],
        "phishing_count": ratio_1_to_1["phishing_count"],
        "legitimate_count": ratio_1_to_1["legitimate_count"],
        "test_set_size": ratio_1_to_1["test_set_size"],
        "source": "reports/metrics.json:independent_test.ratio_1_to_1"
    },
    
    "independent_1to10": {
        "accuracy": ratio_1_to_10["accuracy"],
        "precision": ratio_1_to_10["precision"],
        "recall": ratio_1_to_10["recall"],
        "f1": ratio_1_to_10["f1"],
        "roc_auc": ratio_1_to_10["roc_auc"],
        "pr_auc": ratio_1_to_10["pr_auc"],
        "fpr": ratio_1_to_10["fpr"],
        "precision_ci": [ratio_1_to_10["precision_ci_lower"], ratio_1_to_10["precision_ci_upper"]],
        "recall_ci": [ratio_1_to_10["recall_ci_lower"], ratio_1_to_10["recall_ci_upper"]],
        "f1_ci": [ratio_1_to_10["f1_ci_lower"], ratio_1_to_10["f1_ci_upper"]],
        "roc_auc_ci": [ratio_1_to_10["roc_auc_ci_lower"], ratio_1_to_10["roc_auc_ci_upper"]],
        "pr_auc_ci": [ratio_1_to_10["pr_auc_ci_lower"], ratio_1_to_10["pr_auc_ci_upper"]],
        "fpr_ci": [ratio_1_to_10["fpr_ci_lower"], ratio_1_to_10["fpr_ci_upper"]],
        "phishing_count": ratio_1_to_10["phishing_count"],
        "legitimate_count": ratio_1_to_10["legitimate_count"],
        "test_set_size": ratio_1_to_10["test_set_size"],
        "source": "reports/metrics.json:independent_test.ratio_1_to_10"
    },
    
    # Recall by hosting type
    "recall_free_hosted": {
        "mean": recall_free["mean"],
        "ci_lower": recall_free["ci_lower"],
        "ci_upper": recall_free["ci_upper"],
        "source": "reports/metrics.json:recall_free_hosting_bootstrap_95ci"
    },
    
    "recall_non_free_hosted": {
        "mean": recall_non_free["mean"],
        "ci_lower": recall_non_free["ci_lower"],
        "ci_upper": recall_non_free["ci_upper"],
        "source": "reports/metrics.json:recall_non_free_hosting_bootstrap_95ci"
    },
    
    # Note about 1:3000 run
    "note_1to3000": {
        "accuracy": indep_3000["accuracy"],
        "precision": indep_3000["precision"],
        "recall": indep_3000["recall"],
        "f1": indep_3000["f1"],
        "roc_auc": indep_3000["roc_auc"],
        "pr_auc": indep_3000["pr_auc"],
        "confusion_matrix": indep_3000["confusion_matrix"],
        "note": "ratio 1:3000, precision not comparable due to extreme class imbalance",
        "source": "reports/independent_metrics.json:independent_test"
    }
}

# Save new metadata
with open('models/metadata.json', 'w') as f:
    json.dump(new_metadata, f, indent=2)

print("metadata.json updated successfully!")
print("\n=== New structure ===")
for k in new_metadata.keys():
    if isinstance(new_metadata[k], dict):
        print(f"  {k}: {{...}}")
    else:
        print(f"  {k}: {new_metadata[k]}")