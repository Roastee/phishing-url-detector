"""HOST-ONLY feature extraction for phishing URL detection."""

import math
import re
import urllib.parse
from typing import Dict, List
import tldextract

FEATURE_NAMES: List[str] = [
    "host_length", "dot_count", "hyphen_count", "underscore_count",
    "digit_count", "digit_ratio", "subdomain_count",
    "is_suspicious_tld", "uses_punycode", "has_ip_address",
    "longest_digit_run", "longest_consonant_run",
    "brand_in_subdomain", "suspicious_keyword_count", "uses_url_shortener",
    "host_entropy", "on_known_hosting_platform",
]

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "xyz", "top", "zip", "gq", "cf", "work", "date"}
KNOWN_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "adf.ly", "bit.do", "tiny.cc", "rb.gy", "cutt.ly"}
SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "account", "update", "banking", "confirm", "password", "signin", "wallet", "support", "billing", "auth", "credential"]
TARGET_BRANDS = ["paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook", "instagram", "twitter", "ebay", "linkedin", "chase", "wellsfargo", "binance"]

# Free-hosting platforms detected via PSL private suffixes
KNOWN_HOSTING_SUFFIXES = {
    "github.io", "netlify.app", "vercel.app", "wordpress.com", "blogspot.com",
    "sites.google.com", "gitlab.io", "herokuapp.com", "azurewebsites.net",
    "pages.dev", "workers.dev", "render.com", "railway.app", "fly.dev",
    "surge.sh", "glitch.me", "repl.co", "duckdns.org", "ngrok.io",
    "firebaseapp.com", "web.app", "000webhostapp.com", "wix.com", "wixsite.com",
    "weebly.com", "square.site", "ipfs.io", "pantheonsite.io", "tilda.cc",
    "cloudflareworkers.com", "gitpod.io", "cf-ipfs.com", "dweb.link",
    "ipfs.dweb.link", "id.repl.co", "vhost.link", "heroku.com",
}

def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    return -sum((text.count(c)/len(text))*math.log2(text.count(c)/len(text)) for c in set(text) if text.count(c) > 0)


def _longest_run(text: str, pattern: str) -> float:
    matches = re.findall(pattern, text)
    return float(max(len(m) for m in matches)) if matches else 0.0


def extract_features(url: str) -> Dict[str, float]:
    if not url or not isinstance(url, str):
        return {n: 0.0 for n in FEATURE_NAMES}
    try:
        u = url.strip()
        if not re.match(r"^\w+://", u):
            parsed = urllib.parse.urlparse("http://" + u)
        else:
            parsed = urllib.parse.urlparse(u)
        netloc = parsed.netloc.lower()
        host = netloc.split(":")[0]
        if host.startswith("www."):
            host = host[4:]
        extr = tldextract.extract(host)
        domain = extr.domain.lower()
        tld = extr.suffix.lower()
        subdomain = extr.subdomain.lower()
        registered_domain = f"{domain}.{tld}" if domain and tld else ""
        # Extract suffix for hosting platform detection (PSL private suffixes)
        extr_with_psl = tldextract.extract(host, include_psl_private_domains=True)
        hosting_suffix = extr_with_psl.suffix.lower() if extr_with_psl.suffix else ""
        on_known_hosting = 1.0 if hosting_suffix in KNOWN_HOSTING_SUFFIXES else 0.0
        
        result = {
            "host_length": float(len(host)),
            "dot_count": float(host.count(".")),
            "hyphen_count": float(host.count("-")),
            "underscore_count": float(host.count("_")),
            "digit_count": float(sum(1 for c in host if c.isdigit())),
            "digit_ratio": float(sum(1 for c in host if c.isdigit()) / len(host)) if host else 0.0,
            "subdomain_count": float(len([s for s in subdomain.split(".") if s])),
            "is_suspicious_tld": 1.0 if tld in SUSPICIOUS_TLDS else 0.0,
            "uses_punycode": 1.0 if "xn--" in registered_domain else 0.0,
            "has_ip_address": 1.0 if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host) else 0.0,
            "longest_digit_run": _longest_run(host, r"\d+"),
            "longest_consonant_run": _longest_run(host, r"[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]+"),
            "brand_in_subdomain": 1.0 if any(brand in (subdomain + "/" + domain).lower() and brand != domain for brand in TARGET_BRANDS) else 0.0,
            "suspicious_keyword_count": float(sum(host.lower().count(kw) for kw in SUSPICIOUS_KEYWORDS)),
            "uses_url_shortener": 1.0 if registered_domain in KNOWN_SHORTENERS or host in KNOWN_SHORTENERS else 0.0,
            "host_entropy": _shannon_entropy(host),
            "on_known_hosting_platform": on_known_hosting,
        }
        return result
    except Exception:
        return {n: 0.0 for n in FEATURE_NAMES}


def feature_context(url: str) -> dict:
    """Return human-readable context extracted from the URL's host.

    Used to enrich the plain-English explanations with concrete values
    (e.g. which keywords/brands were found, the TLD, the shortener) without
    introducing any new model features.
    """
    empty = {
        "suspicious_keywords": [],
        "brands": [],
        "tld": "",
        "shortener": "",
        "is_ip": False,
        "host": "",
    }
    if not url or not isinstance(url, str):
        return empty
    try:
        u = url.strip()
        if not re.match(r"^\w+://", u):
            parsed = urllib.parse.urlparse("http://" + u)
        else:
            parsed = urllib.parse.urlparse(u)
        netloc = parsed.netloc.lower()
        host = netloc.split(":")[0]
        if host.startswith("www."):
            host = host[4:]
        extr = tldextract.extract(host)
        domain = extr.domain.lower()
        tld = extr.suffix.lower()
        subdomain = extr.subdomain.lower()
        registered_domain = f"{domain}.{tld}" if domain and tld else ""

        keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in host.lower()]
        brand_sub = (subdomain + "/" + domain).lower()
        brands = [b for b in TARGET_BRANDS if b in brand_sub and b != domain]
        shortener = ""
        if registered_domain in KNOWN_SHORTENERS:
            shortener = registered_domain
        elif host in KNOWN_SHORTENERS:
            shortener = host

        return {
            "suspicious_keywords": keywords,
            "brands": brands,
            "tld": tld,
            "shortener": shortener,
            "is_ip": bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host)),
            "host": host,
        }
    except Exception:
        return empty