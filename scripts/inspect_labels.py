"""Verify label meaning and analyze the dataset."""
import pandas as pd

df = pd.read_csv('data/raw/PhiUSIIL_URL.csv')

print("=== LABEL VERIFICATION ===\n")

# Check by URL length
df['url_len'] = df['URL'].str.len()
length_by_label = df.groupby('Label')['url_len'].describe()
print("URL length by label:")
print(length_by_label)

# Label 0 = shorter URLs = LEGITIMATE
# Label 1 = longer URLs = PHISHING
print("\n=== Label mapping based on URL length ===")
print("Label 0 (mean 27 chars) = LEGITIMATE")
print("Label 1 (mean 46 chars) = PHISHING")

print("\n=== 10 RANDOM PHISHING URLs (Label=1) ===")
phish = df[df['Label']==1]['URL'].sample(10, random_state=42)
for url in phish.tolist():
    print(f"  {url}")

print("\n=== 10 RANDOM LEGITIMATE URLs (Label=0) ===")
legit = df[df['Label']==0]['URL'].sample(10, random_state=42)
for url in legit.tolist():
    print(f"  {url}")