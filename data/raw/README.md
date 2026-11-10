# Phishing URL Dataset

This directory contains the raw data for phishing URL detection.

## PhiUSIIL Phishing URL Dataset

**Source**: UCI Machine Learning Repository  
**URL**: https://archive.ics.uci.edu/dataset/10788/phiusiil-url  
**License**: See UCI terms - CC BY 4.0

## Dataset Characteristics (After Cleaning)

- **Rows**: 235,370 unique URLs
- **Columns**: `URL` (string), `Label` (0=legitimate, 1=phishing)
- **Class balance**: 43% phishing (100,520), 57% legitimate (134,850)
- **URL length**: Legitimate ~27 chars, Phishing ~46 chars (avg)

## Important Notes & Leakage Issues

**Major Leakage Issue:**
- Legitimate URLs: 100% use `https://` scheme
- Phishing URLs: ~50% use `http://`, ~50% use `https://`
- The `uses_https` feature will be a powerful predictor

**Additional Characteristics:**
- All URLs are fully qualified (http:// or https://)
- No `https://www.` prefix distinction between classes
- Some legitimate URLs are extremely long (max 6,097 chars)

## Download Instructions

To get the original dataset from UCI:

```bash
# Download manually from:
# https://archive.ics.uci.edu/dataset/10788/phiusiil-url

# Or use wget/curl:
wget https://archive.ics.uci.edu/ml/machine-learning-databases/00619/PhiUSIIL_URL.csv -O data/raw/raw_dataset.csv
```

## Data Processing (Applied Before Training)

1. Strip whitespace from URLs
2. Normalize scheme and host to lowercase
3. Remove duplicate URLs (keep first occurrence)
4. **IMPORTANT**: Original labels are inverted - dataset has 0=phishing, 1=legitimate, so we flip to 1=phishing, 0=legitimate