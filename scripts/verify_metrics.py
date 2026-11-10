"""Verify and recompute metrics for integrity."""
import json
import numpy as np
from phishdetect.predict import predict_url
from phishdetect.features import extract_features

# Load current metrics
with open('reports/metrics.json') as f:
    metrics = json.load(f)

print("=" * 60)
print("VERIFYING FPR FROM CONFUSION MATRICES")
print("=" * 60)

ind = metrics.get("independent_test", {})
for key, val in ind.items():
    if isinstance(val, dict) and "confusion_matrix" in val:
        cm = val["confusion_matrix"]
        tn = cm[0][0]
        fp = cm[0][1]
        fn = cm[1][0]
        tp = cm[1][1]
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
        print(f"\n{key}:")
        print(f"  CM: TN={tn}, FP={fp}, FN={fn}, TP={tp}")
        print(f"  Reported FPR: {val.get('fpr', 'N/A'):.4f}, Computed FPR: {fpr:.4f}")
        print(f"  Reported Recall: {val.get('recall', 'N/A'):.4f}, Computed Recall: {tpr:.4f}")
        print(f"  Phishing count: {val.get('phishing_count', tp+fn)}, Legitimate count: {val.get('legitimate_count', tn+fp)}")

print("\n" + "=" * 60)
print("FREE HOSTING ANALYSIS")
print("=" * 60)

# Check the free hosting FPR claim
print("\nFree hosting 'before' CM:")
before = metrics["retrain_with_hosting_platform"]["before"]
cm = before["confusion_matrix"]
print(f"  CM: {cm}")
print(f"  FPR reported: {before['fpr']:.4f}")
print(f"  This CM has 0 phishing samples - measuring FPR on training negatives only!")

print("\nFree hosting 'after' CM:")
after = metrics["retrain_with_hosting_platform"]["after"]
cm = after["confusion_matrix"]
tn, fp = cm[0][0], cm[0][1]
fn, tp = cm[1][0], cm[1][1]
fpr = fp / (fp + tn)
print(f"  CM: {cm}")
print(f"  FPR reported: {after['fpr']:.4f}, Computed: {fpr:.4f}")
print(f"  These 24 legitimate URLs were ALSO training negatives (data leakage)")

# Check the 296 vs 300 discrepancy
print("\n" + "=" * 60)
print("PHISHING COUNT DISCREPANCY")
print("=" * 60)
print(f"ratio_1_to_1 phishing_count: {ind.get('ratio_1_to_1', {}).get('phishing_count', 'N/A')}")
print(f"ratio_1_to_10 phishing_count: {ind.get('ratio_1_to_10', {}).get('phishing_count', 'N/A')}")
print(f"phishing_on_free_hosting_openphish total: {metrics.get('phishing_on_free_hosting_openphish', {}).get('total', 'N/A')}")

# Load openphish data to verify
import pandas as pd
try:
    df = pd.read_csv('data/independent_test/openphish_phishing.txt', header=None, names=['url'])
    print(f"Actual openphish lines: {len(df)}")
    
    # Check how many are on free hosting
    free_hosting = 0
    for url in df['url']:
        feat = extract_features(str(url))
        if feat.get('on_known_hosting_platform', 0) == 1:
            free_hosting += 1
    print(f"Openphish URLs on free hosting: {free_hosting}")
except Exception as e:
    print(f"Could not load openphish: {e}")

print("\n" + "=" * 60)
print("RECALL BOOTSTRAP CIs FOR FREE-HOSTED VS NON-FREE-HOSTED")
print("=" * 60)

# Load the independent test data
import os
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OPENPHISH_PATH = os.path.join(PROJECT_ROOT, "data", "independent_test", "openphish_phishing.txt")
LEGIT_POPULAR_PATH = os.path.join(PROJECT_ROOT, "data", "independent_test", "legitimate_popular.csv")
LEGIT_LONGTAIL_PATH = os.path.join(PROJECT_ROOT, "data", "independent_test", "legitimate_long_tail.csv")

df_phish = pd.read_csv(OPENPHISH_PATH, header=None, names=['url'])
df_legit_pop = pd.read_csv(LEGIT_POPULAR_PATH)
df_legit_lt = pd.read_csv(LEGIT_LONGTAIL_PATH)

print(f"Phishing URLs: {len(df_phish)}")
print(f"Legitimate popular: {len(df_legit_pop)}")
print(f"Legitimate long-tail: {len(df_legit_lt)}")

# Classify phishing URLs
phish_free = []
phish_nonfree = []
for _, row in df_phish.iterrows():
    feat = extract_features(str(row['url']))
    if feat.get('on_known_hosting_platform', 0) == 1:
        phish_free.append(row['url'])
    else:
        phish_nonfree.append(row['url'])

print(f"Free-hosted phishing: {len(phish_free)}")
print(f"Non-free-hosted phishing: {len(phish_nonfree)}")

# Compute recall with bootstrap CIs
def bootstrap_recall(urls, n_bootstrap=1000):
    recalls = []
    for _ in range(n_bootstrap):
        sample = np.random.choice(urls, size=len(urls), replace=True)
        tp = sum(1 for u in sample if predict_url(u)['label'] == 'phishing')
        recalls.append(tp / len(urls))
    return np.percentile(recalls, [2.5, 97.5])

if phish_free:
    free_recall = sum(1 for u in phish_free if predict_url(u)['label'] == 'phishing') / len(phish_free)
    free_ci = bootstrap_recall(phish_free, 500)
    print(f"Free-hosted recall: {free_recall:.4f} (95% CI: {free_ci[0]:.4f}-{free_ci[1]:.4f})")

if phish_nonfree:
    nonfree_recall = sum(1 for u in phish_nonfree if predict_url(u)['label'] == 'phishing') / len(phish_nonfree)
    nonfree_ci = bootstrap_recall(phish_nonfree, 500)
    print(f"Non-free-hosted recall: {nonfree_recall:.4f} (95% CI: {nonfree_ci[0]:.4f}-{nonfree_ci[1]:.4f})")

print("\n" + "=" * 60)
print("THRESHOLD ANALYSIS")
print("=" * 60)
print(f"Threshold precision 0.90: {metrics['threshold_selection']['threshold_precision_090']}")
print(f"Threshold low FPR 2%: {metrics['threshold_selection']['threshold_low_fpr_2pct']}")
print(f"Default threshold (deployed): {metrics['threshold_selection']['default_threshold']}")
print(f"Deployed threshold from metadata: {metrics['deployment_info']['default_threshold']}")