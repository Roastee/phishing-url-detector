import tldextract, tempfile, pandas as pd, numpy as np, re, urllib.parse, math
online = tldextract.TLDExtract(cache_dir=tempfile.gettempdir(), include_psl_private_domains=True)
offline = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=tempfile.gettempdir(), include_psl_private_domains=True)
phishing_df = pd.read_csv('data/independent_test/phishing.csv')
legit_popular = pd.read_csv('data/independent_test/legitimate_popular.csv')
legit_long = pd.read_csv('data/independent_test/legitimate_long_tail.csv')
np.random.seed(42)
urls = list(phishing_df.sample(n=298, random_state=42)['URL'].values) + list(legit_popular.sample(n=8891, random_state=42)['URL'].values) + list(legit_long.sample(n=1200, random_state=42)['URL'].values)
edge = ['http://example.com', 'https://example.com', 'http://paypal.com', 'http://github.io', 'http://myapp.herokuapp.com', 'http://example.tk', 'http://verify-account-login.ml', 'http://sub.domain.example.com', 'http://bit.ly/abc123', 'http://xn--example.com', 'http://localhost']
all_urls = urls + edge
hostdiff = 0
for u in all_urls:
    try:
        o = online(u)
        of = offline(u)
        if o.suffix != of.suffix:
            hostdiff += 1
            print(f'hostdiff: {u} online={o.suffix} offline={of.suffix}')
    except:
        pass
print(f'hostdiff total: {hostdiff}')
