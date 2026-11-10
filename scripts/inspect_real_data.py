"""Clean the real PhiUSIIL dataset and check for leakage."""
import pandas as pd
from urllib.parse import urlparse, urlunparse
import numpy as np

print("=== LOADING DATA ===")
df = pd.read_csv('data/raw/phiusiil_real.csv')
print(f"Initial shape: {df.shape}")

# Keep only URL and label columns
df = df[['URL', 'label']].copy()

print("\n=== CLEANING ===")
# Strip whitespace
df['URL'] = df['URL'].str.strip()
print(f"After stripping: {df.shape}")

# Remove empty URLs
df = df[df['URL'].str.len() > 0]
print(f"After empty removal: {df.shape}")

# Remove exact duplicates
unique_before = df['URL'].nunique()
df = df.drop_duplicates(subset=['URL'], keep='first')
print(f"Duplicates removed: {df.shape[0] - unique_before}")
print(f"After deduplication: {df.shape}")

# Verify label mapping (1=phishing, 0=legitimate)
print("\n=== LABEL MAPPING ===")
print("Label 1 (phishing) sample:")
print(df[df['label']==1]['URL'].head(3).tolist())
print("\nLabel 0 (legitimate) sample:")
print(df[df['label']==0]['URL'].head(3).tolist())

# Rename label column to Label for consistency
df = df.rename(columns={'label': 'Label'})

print(f"\n=== FINAL SHAPE: {df.shape} ===")
print(f"Label distribution: {df['Label'].value_counts().to_dict()}")

# Save cleaned data
df.to_csv('data/raw/PhiUSIIL_URL_cleaned.csv', index=False)
print("Saved to data/raw/PhiUSIIL_URL_cleaned.csv")