# Phishing URL Detector

[![CI](https://github.com/YOUR_GITHUB_USERNAME/phishing-url-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_GITHUB_USERNAME/phishing-url-detector/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Phishing URL Detector** - Machine learning system to detect phishing URLs using **host-only features**.

## Key Finding: Dataset Leakage in Original Features

The UCI PhiUSIIL dataset contains severe leakage that inflated performance of full-URL models:

| Feature | Legitimate URLs | Phishing URLs |
|---------|-----------------|---------------|
| `https://www.` prefix | 100% | 41.5% |
| HTTPS scheme | 100% | 49% |
| Has path | 0% | 61% |

A full-URL model exploiting these artifacts scored **0.9935 F1**. The host-only redesign eliminates this leakage.

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

---

## Model Performance

### In-Distribution Test (n=17,783 test samples)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR |
|-------|----------|-----------|--------|-----|---------|-----|
| LogisticRegression | 0.842 | 0.916 | 0.730 | 0.812 | 0.871 | 0.0588 |
| RandomForest | 0.838 | 0.908 | 0.726 | 0.807 | 0.865 | 0.0641 |
| **XGBoost (deployed)** | **0.844** | **0.934** | **0.716** | **0.811** | **0.862** | **0.0442** |

**Deployment:** XGBoost with threshold **0.58** (selected for ~2% FPR on validation).

### Independent Test Results

| Slice | n (phishing) | n (legitimate) | Precision | Recall (95% CI) | FPR |
|-------|--------------|----------------|-----------|-----------------|-----|
| **All phishing (1:1)** | 296 | 296 | 0.966 | 0.767 [0.720, 0.813] | 2.7% |
| **All phishing (1:10)** | 296 | 2,960 | 0.676 | 0.767 [0.718, 0.815] | 3.7% |
| Free-hosted phishing | 169 | — | — | 1.000 [1.000, 1.000] | — |
| Non-free-hosted phishing | 131 | — | — | 0.559 [0.466, 0.641] | — |

*Note: OpenPhish source has 300 URLs; 296 used in evaluation (4 failed feature extraction).*

**Precision at 1% prevalence:** 22.3%  
**Precision at 0.1% prevalence:** 2.8%

---

## Limitations and Honest Results

### Recall on non-free hosts: 0.559 (95% CI: 0.466–0.641)

The model achieves modest recall (~56%) on non-free-hosted phishing URLs. This is the primary limitation.

### The free-hosting effect

On a hand-built list of **24 legitimate free-hosted URLs** (GitHub Pages, Netlify, WordPress.com, etc.), which were **also used as training negatives**, **9 were still flagged as phishing (37.5% FPR)**. Because these same URLs were in the training data, the true FPR on free-hosted legitimate sites is **likely higher than 37.5%**. The earlier claim "FPR reduced from ~54% to ~37.5%" measured on training data and is not a valid generalization estimate.

The free-hosted recall of ~100% reflects a **shared-platform shortcut**: the model learns that `on_known_hosting_platform=1` correlates with phishing in the training data (27.8% of training phishing URLs used free hosting). This same feature causes false positives on legitimate sites hosted on GitHub Pages, Netlify, Vercel, and similar platforms.

### FPR on independent data

The model achieves **2.7% FPR** on the 1:1 independent test (n=296 legitimate), slightly above the 2% target. On the 1:10 slice (n=2,960 legitimate), FPR is **3.7%**.

### Long-tail FPR

Long-tail legitimate domains (Tranco ranks 100K–1M) show FPR up to **4.4%** (measured on the 1:10 long-tail slice, n=1,480).

### Length bias

The model shows **no significant length bias**: long legitimate domains (e.g., `metropolitanmuseumofart.org`, 26 chars) score low probability (0.16–0.27), while short phishing lookalikes (e.g., `paypa1.tk`, 9 chars) score high (0.99+). Host length is a feature but is outweighed by suspicious TLD, brand impersonation, and keyword signals.

### Platform warning in UI

When `on_known_hosting_platform == 1`, the UI shows a yellow notice that the domain alone cannot separate legitimate from malicious sites on shared platforms, and risk is shown as "uncertain" instead of "high".

### Precision at realistic prevalence

At 1% prevalence: 22.3% precision. At 0.1% prevalence: 2.8% precision. Most alerts will be false positives in production.

### Tranco-sourced negatives caveat

Training negatives are sourced from Tranco top 1M. This may not represent all legitimate URL patterns encountered in the wild.

---

## Ethics Note

This tool performs **text-only analysis** of URLs. It never fetches, visits, or resolves submitted URLs. Intended for **research and educational use**. Not a substitute for professional security tools or human judgment.

---

## License

MIT License
