#!/usr/bin/env python
"""Step 4: tldextract identity check - compare online vs offline extractor."""
import tldextract
import tempfile
import urllib.parse
import re
import math

# Online extractor (default, fetches PSL from web)
TLDEXTRACT_ONLINE = tldextract.TLDExtract(
    cache_dir=tempfile.gettempdir(),
    include_psl_private_domains=True
)

# Offline extractor (used in features.py - no network fetch)
TLDEXTRACT_OFFLINE = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=tempfile.gettempdir(),
    include_psl_private_domains=True
)

FEATURE_NAMES = [
    "host_length", "dot_count", "hyphen_count", "underscore_count",
    "digit_count", "digit_ratio", "subdomain_count",
    "is_suspicious_tld", "uses_punycode", "has_ip_address",
    "longest_digit_run", "longest_consonant_run",
    "brand_in_subdomain", "suspicious_keyword_count", "uses_url_shortener",
    "host_entropy", "on_known_hosting_platform",
]