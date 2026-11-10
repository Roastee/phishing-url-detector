"""HOST-ONLY feature extraction for phishing URL detection."""

import math
import re
import urllib.parse
from typing import Dict, List
import tempfile
import tldextract

# Initialize tldextract with offline settings
TLDEXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=tempfile.gettempdir(),
    include_psl_private_domains=True
)

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
        extr = TLDEXTRACT(host)
        domain = extr.domain.lower()
        tld = extr.suffix.lower()
        subdomain = extr.subdomain.lower()
        registered_domain = f"{domain}.{tld}" if domain and tld else ""
        # Extract suffix for hosting platform detection (PSL private suffixes)
        extr_with_psl = TLDEXTRACT(host)
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
        extr = TLDEXTRACT(host)
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


def compute_red_flags(url: str, ctx: dict = None) -> list:
    """Compute rule-based red flags for a URL.

    Returns a list of red flag objects with type and matched text.
    """
    if ctx is None:
        ctx = feature_context(url)

    red_flags = []

    # Suspicious TLD
    if ctx.get("tld") in SUSPICIOUS_TLDS:
        red_flags.append({
            "type": "suspicious_tld",
            "matched": ctx.get("tld", ""),
            "description": f"Suspicious TLD: .{ctx.get('tld', '')}"
        })

    # Brand lookalike in subdomain (including hyphenated)
    for brand in ctx.get("brands", []):
        red_flags.append({
            "type": "brand_lookalike",
            "matched": brand,
            "description": f"Brand '{brand}' found in subdomain"
        })

    # Suspicious keywords
    for kw in ctx.get("suspicious_keywords", []):
        red_flags.append({
            "type": "suspicious_keyword",
            "matched": kw,
            "description": f"Suspicious keyword: '{kw}'"
        })

    # IP host
    if ctx.get("is_ip"):
        red_flags.append({
            "type": "ip_host",
            "matched": ctx.get("host", ""),
            "description": "Hostname is an IP address"
        })

    # Punycode
    if "xn--" in ctx.get("host", ""):
        red_flags.append({
            "type": "punycode",
            "matched": ctx.get("host", ""),
            "description": "Uses punycode encoding"
        })

    # URL shortener
    if ctx.get("shortener"):
        red_flags.append({
            "type": "url_shortener",
            "matched": ctx.get("shortener", ""),
            "description": f"Uses URL shortener: {ctx.get('shortener', '')}"
        })

    return red_flags


def compute_platform_warning(url: str, ctx: dict = None) -> bool:
    """Check if the URL is on a known free hosting platform."""
    if ctx is None:
        ctx = feature_context(url)
    # We need to check the hosting platform via tldextract with PSL
    # The feature extraction already computes on_known_hosting_platform
    # We'll do a quick check here
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
        extr = TLDEXTRACT(host)
        hosting_suffix = extr.suffix.lower() if extr.suffix else ""
        return hosting_suffix in KNOWN_HOSTING_SUFFIXES
    except Exception:
        return False