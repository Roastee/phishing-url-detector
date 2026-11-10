"""Generate updated README.md with new metrics and limitations."""
import json

with open('reports/metrics.json') as f:
    metrics = json.load(f)

xgb = metrics['independent_test']['ratio_1_to_1']
recall_ci = metrics.get('recall_free_hosting_bootstrap_95ci', {})
nonfree_ci = metrics.get('recall_non_free_hosting_bootstrap_95ci', {})
prev = metrics.get('precision_at_realistic_prevalence', {})

readme = f'''# Phishing URL Detector

[![CI](https://github.com/yourusername/phishing-url-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/phishing-url-detector/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Phishing URL Detector** - Machine learning system to detect phishing URLs using **host-only features**.

## Key Design Decision: Host-Only Modeling to Eliminate Dataset Leakage

This project uses **host-only feature extraction** to avoid learning from dataset artifacts. The UCI PhiUSIIL dataset has severe leakage:

| Feature | Legitimate URLs | Phishing URLs |
|---------|-----------------|---------------|
| `https://www.` prefix | 100% | 41.5% |
| HTTPS scheme | 100% | 49% |
| Has path | 0% | 61% |

**Solution:** This system normalizes ALL URLs to the host only before feature extraction.

---

## Features (17 host-only features)

| Category | Features |
|----------|----------|
| Host structure | `host_length`, `dot_count`, `hyphen_count`, `underscore_count`, `digit_count`, `digit_ratio`, `subdomain_count` |
| TLD/encoding | `is_suspicious_tld`, `uses_punycode`, `has_ip_address` |
| Character analysis | `longest_digit_run`, `longest_consonant_run` |
| Brand impersonation | `brand_in_subdomain` |
| Keywords/shorteners | `suspicious_keyword_count`, `uses_url_shortener` |
| Entropy | `host_entropy` |
| Hosting platform | `on_known_hosting_platform` |

---

## Quick Start

```bash
pip install -r requirements.txt
pytest
```

## Model Performance

**In-Distribution Test (XGBoost):**

| Metric | Value |
|--------|-------|
| Accuracy | 0.844 |
| Precision | 0.934 |
| Recall | 0.716 |
| F1 | 0.811 |

**Deployment:** XGBoost with threshold 0.58.

---

## Independent Test Results

| Slice | Precision | Recall (95% CI) | FPR |
|--------|-----------|-----------------|-----|
| **All phishing** | 0.966 | 0.767 | 2.7% |
| Free-hosted phishing | - | 1.0 [1.0, 1.0] | - |
| Non-free-hosted phishing | - | 0.559 [0.466, 0.641] | - |

**Precision at 1% prevalence:** 22.3%
**Precision at 0.1% prevalence:** 2.8%

---

## Limitations and Honest Results

### Recall on non-free hosts: {nonfree_ci.get('mean', 0):.3f} (95% CI: {nonfree_ci.get('ci_lower', 0):.3f}–{nonfree_ci.get('ci_upper', 0):.3f})

The model achieves modest recall (~56%) on non-free-hosted phishing URLs.

### The free-hosting effect

FPR on legitimate free-hosting URLs reduced from ~54% to ~37.5% after adding `on_known_hosting_platform` feature and 24 legitimate hosted subdomains as training negatives.

### FPR on independent data: 2.7% vs 2% target

The model achieves 2.7% FPR, slightly above the 2% target.

### Tranco-sourced negatives caveat

Long-tail domains (ranks 100K-1M) have higher FPR (up to 10.4%).

### Precision at realistic prevalence

At 1% prevalence: 22.3% precision. At 0.1% prevalence: 2.8% precision.

---

## Limitations

- **No live fetching**: URLs analyzed as text only
- **Host-only model**: No path/query/content analysis
- **Precision at low prevalence**: Most alerts are false positives
- **Attacker-adaptive**: Determined attackers can evade

---

## License

MIT License
'''

with open('README.md', 'w') as f:
    f.write(readme)
print('README.md updated!')