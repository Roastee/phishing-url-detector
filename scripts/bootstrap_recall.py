"""Bootstrap recall for free-hosted vs non-free-hosted phishing."""
from phishdetect.predict import predict_url
from phishdetect.features import extract_features
import pandas as pd
import numpy as np

df = pd.read_csv('data/independent_test/openphish_phishing.txt', header=None, names=['url'])
phish_free = []
phish_nonfree = []
for _, row in df.iterrows():
    feat = extract_features(str(row['url']))
    if feat.get('on_known_hosting_platform', 0) == 1:
        phish_free.append(row['url'])
    else:
        phish_nonfree.append(row['url'])

print(f'Free: {len(phish_free)}, Non-free: {len(phish_nonfree)}')

def bootstrap_recall(urls, n=500):
    rec = []
    for _ in range(n):
        sample = np.random.choice(urls, size=len(urls), replace=True)
        tp = sum(1 for u in sample if predict_url(u)['label'] == 'phishing')
        rec.append(tp / len(urls))
    return np.percentile(rec, [2.5, 97.5])

free_recall = sum(1 for u in phish_free if predict_url(u)['label'] == 'phishing') / len(phish_free)
free_ci = bootstrap_recall(phish_free, 500)
print(f'Free-hosted recall: {free_recall:.4f} (95% CI: {free_ci[0]:.4f}-{free_ci[1]:.4f})')

nonfree_recall = sum(1 for u in phish_nonfree if predict_url(u)['label'] == 'phishing') / len(phish_nonfree)
nonfree_ci = bootstrap_recall(phish_nonfree, 500)
print(f'Non-free-hosted recall: {nonfree_recall:.4f} (95% CI: {nonfree_ci[0]:.4f}-{nonfree_ci[1]:.4f})')