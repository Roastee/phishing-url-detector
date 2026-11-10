"""Download OpenPhish feed and Tranco top-1M for independent testing."""
import os
import requests

# Download OpenPhish feed
print("Downloading OpenPhish feed...")
try:
    resp = requests.get("https://openphish.com/feed.txt", timeout=60)
    resp.raise_for_status()
    with open("data/independent_test/openphish_phishing.txt", "w") as f:
        f.write(resp.text)
    urls = [l.strip() for l in resp.text.splitlines() if l.strip()]
    print(f"Downloaded {len(urls)} phishing URLs from OpenPhish")
except Exception as e:
    print(f"Failed to download OpenPhish: {e}")

# Download Tranco top-1M
print("Downloading Tranco top-1M...")
try:
    resp = requests.get("https://tranco-list.eu/top-1m.csv.zip", timeout=120)
    resp.raise_for_status()
    import zipfile, io
    with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
        z.extractall("data/independent_test/")
    print("Extracted Tranco top-1M")
except Exception as e:
    print(f"Failed to download Tranco: {e}")

print("Done!")