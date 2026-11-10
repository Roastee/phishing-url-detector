"""Unit tests for the HOST-ONLY feature extraction module."""

from phishdetect.features import FEATURE_NAMES, extract_features

# Expected feature names for host-only model
EXPECTED_HOST_FEATURES = [
    "host_length", "dot_count", "hyphen_count", "underscore_count",
    "digit_count", "digit_ratio", "subdomain_count",
    "is_suspicious_tld", "uses_punycode", "has_ip_address",
    "longest_digit_run", "longest_consonant_run",
    "brand_in_subdomain", "suspicious_keyword_count", "uses_url_shortener",
    "host_entropy",
]


def test_feature_names_are_host_only():
    """Feature names must NOT include path/query/scheme/www-derived features."""
    for name in FEATURE_NAMES:
        assert name not in ["path_length", "query_length", "query_param_count",
                           "uses_https", "double_slash_in_path", "url_length",
                           "path_entropy"], f"Feature {name} should not exist in host-only model"


def test_feature_names_match_output():
    """FEATURE_NAMES must match extracted keys exactly."""
    sample = extract_features("https://www.google.com/search?q=test")
    assert list(sample.keys()) == FEATURE_NAMES


def test_url_normalization_consistent():
    """Same URL with/without www, path, scheme must produce identical features."""
    urls = [
        "https://www.google.com/search?q=cats",
        "http://google.com/search?q=cats",
        "google.com",
        "https://www.google.com",
        "http://www.google.com",
    ]
    features = [extract_features(url) for url in urls]
    base = features[0]
    for url_features in features[1:]:
        assert base == url_features, "URLs should produce identical features"


def test_ip_address_detection():
    """Verify IP address detection for IPv4 in host."""
    ip_url = "http://192.168.1.1/login"
    res = extract_features(ip_url)
    assert res["has_ip_address"] == 1.0


def test_punycode_detection():
    """Verify punycode detection."""
    puny_url = "http://xn--80akhbyknj4f.xn--p1ai/"
    res = extract_features(puny_url)
    assert res["uses_punycode"] == 1.0


def test_url_shortener_detection():
    """Verify URL shortener detection."""
    short_url = "https://bit.ly/3xYz123"
    res = extract_features(short_url)
    assert res["uses_url_shortener"] == 1.0


def test_suspicious_tld_and_keywords():
    """Verify detection of suspicious TLD and keywords."""
    url = "http://verify-account.paypal.security-update.tk/login.php"
    res = extract_features(url)
    assert res["is_suspicious_tld"] == 1.0
    assert res["suspicious_keyword_count"] >= 3.0
    assert res["brand_in_subdomain"] == 1.0


def test_malformed_inputs_never_raise():
    """Malformed or non-string inputs should return default dictionary without raising."""
    for bad_input in [None, 123, "", "   ", "http://", ":::"]:
        res = extract_features(bad_input)  # type: ignore
        assert isinstance(res, dict)
        assert set(res.keys()) == set(FEATURE_NAMES)


def test_no_path_query_features():
    """Verify no path/query/scheme features exist in output."""
    feature_names = set(FEATURE_NAMES)
    forbidden = ["path_length", "query_length", "uses_https", "has_port", "double_slash_in_path"]
    for forbidden_feature in forbidden:
        assert forbidden_feature not in feature_names, f"Feature {forbidden_feature} should not exist in host-only model"


def test_data_leakage_removed():
    """
    Demonstrates the leakage removal:
    - Legitimate URL with path gets same score as bare domain
    - Scheme does not affect features
    """
    urls = [
        "https://www.google.com/search?q=cats",
        "http://google.com/search?q=cats",
        "google.com",
    ]
    outputs = [extract_features(u) for u in urls]
    for i, feat in enumerate(outputs[1:], 1):
        assert feat == outputs[0], f"URL {i} should give same features as URL 0"


def test_host_only_features_present():
    """Verify all host-only features are present in FEATURE_NAMES."""
    for feat in EXPECTED_HOST_FEATURES:
        assert feat in FEATURE_NAMES, f"Missing host-only feature: {feat}"