"""Phase D: Build independent test set from OpenPhish and Tranco.

Splits:
- Phishing: OpenPhish feed (all 300 URLs)
- Legitimate: 50% from Tranco ranks 1-10,000 (popular), 50% from Tranco ranks 100,000-1,000,000 (long-tail)
- Remove any domain that appears in training data
"""
import os
import pandas as pd
import urllib.parse
import re

def extract_host(url):
    u = url.strip()
    if not re.match(r"^\w+://", u):
        u = "http://" + u
    parsed = urllib.parse.urlparse(u)
    host = parsed.netloc.lower().split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return host

def build_independent_test():
    """Build independent test set from OpenPhish and Tranco."""
    
    openphish_path = "data/independent_test/openphish_phishing.txt"
    tranco_path = "data/independent_test/top-1m.csv"
    
    if not os.path.exists(openphish_path):
        print(f"ERROR: {openphish_path} not found!")
        return
    if not os.path.exists(tranco_path):
        print(f"ERROR: {tranco_path} not found!")
        return
    
    # Load OpenPhish phishing URLs
    with open(openphish_path) as f:
        phish_urls = [line.strip() for line in f if line.strip()]
    print(f"Loaded {len(phish_urls)} phishing URLs from OpenPhish")
    
    # Load Tranco top-1M
    tranco_df = pd.read_csv(tranco_path, header=None, names=['rank', 'domain'])
    print(f"Loaded {len(tranco_df)} domains from Tranco")
    
    # Split Tranco into two slices
    popular = tranco_df.head(10000)['domain'].tolist()  # ranks 1-10,000
    long_tail = tranco_df.iloc[99999:1000000]['domain'].tolist()  # ranks 100,000-1,000,000
    print(f"Popular slice (ranks 1-10k): {len(popular)} domains")
    print(f"Long-tail slice (ranks 100k-1M): {len(long_tail)} domains")
    
    # Load training hosts to remove overlap
    train_hosts = pd.read_pickle('reports/train_hosts.pkl')
    train_domains = set(train_hosts)
    print(f"Training domains: {len(train_domains)}")
    
    # Build legitimate URLs with https://www. prefix
    popular_urls = ["https://www." + d for d in popular]
    long_tail_urls = ["https://www." + d for d in long_tail]
    
    # Filter out training domains
    popular_filtered = [u for u, d in zip(popular_urls, popular) if d not in train_domains]
    long_tail_filtered = [u for u, d in zip(long_tail_urls, long_tail) if d not in train_domains]
    
    # Filter phishing URLs
    phish_hosts = [extract_host(u) for u in phish_urls]
    filtered_phish = [u for u, h in zip(phish_urls, phish_hosts) if h not in train_domains]
    
    print(f"\nAfter removing training domain overlap:")
    print(f"  Phishing: {len(filtered_phish)} / {len(phish_urls)}")
    print(f"  Legitimate (popular): {len(popular_filtered)} / {len(popular_urls)}")
    print(f"  Legitimate (long-tail): {len(long_tail_filtered)} / {len(long_tail_urls)}")
    
    # Save
    os.makedirs('data/independent_test', exist_ok=True)
    pd.DataFrame({'URL': filtered_phish, 'Label': 1, 'source': 'openphish'}).to_csv('data/independent_test/phishing.csv', index=False)
    pd.DataFrame({'URL': popular_filtered, 'Label': 0, 'slice': 'popular'}).to_csv('data/independent_test/legitimate_popular.csv', index=False)
    pd.DataFrame({'URL': long_tail_filtered, 'Label': 0, 'slice': 'long_tail'}).to_csv('data/independent_test/legitimate_long_tail.csv', index=False)
    
    print("\nSaved independent test sets to data/independent_test/")

def extract_host(url):
    u = url.strip()
    if not re.match(r"^\w+://", u):
        u = "http://" + u
    parsed = urllib.parse.urlparse(u)
    host = parsed.netloc.lower().split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return host

if __name__ == "__main__":
    import urllib.parse
    build_independent_test()