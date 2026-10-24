"""
tests/test_feature_extraction.py
Unit tests for URL feature extraction.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from feature_extraction import (
    extract_features,
    FEATURE_NAMES,
    get_feature_explanations,
    features_to_list,
)


class TestExtractFeatures:
    """Tests for extract_features()."""

    # ---- Valid URLs ----

    def test_valid_https_url(self):
        f = extract_features("https://www.google.com")
        assert f["has_https"] == 1
        assert f["is_ip_address"] == 0
        assert isinstance(f["url_length"], int)
        assert f["url_length"] > 0

    def test_valid_http_url(self):
        f = extract_features("http://example.com")
        assert f["has_https"] == 0

    def test_url_without_scheme(self):
        f = extract_features("google.com")
        assert isinstance(f["url_length"], int)
        assert f["url_length"] > 0

    def test_all_feature_names_present(self):
        f = extract_features("https://google.com")
        for name in FEATURE_NAMES:
            assert name in f, f"Missing feature: {name}"

    # ---- IP addresses ----

    def test_ip_address_url(self):
        f = extract_features("http://192.168.1.1/login")
        assert f["is_ip_address"] == 1

    def test_ip_address_with_port(self):
        f = extract_features("http://10.0.0.1:8080/admin")
        assert f["is_ip_address"] == 1
        assert f["has_non_standard_port"] == 1

    def test_domain_url_not_ip(self):
        f = extract_features("https://google.com")
        assert f["is_ip_address"] == 0

    # ---- HTTPS / HTTP ----

    def test_https_detected(self):
        f = extract_features("https://secure-bank.com")
        assert f["has_https"] == 1

    def test_http_detected(self):
        f = extract_features("http://not-secure.com/login")
        assert f["has_https"] == 0

    # ---- Suspicious words ----

    def test_login_word_detected(self):
        f = extract_features("http://phish.xyz/login/verify")
        assert f["has_suspicious_word"] == 1
        assert f["suspicious_word_count"] >= 1

    def test_multiple_suspicious_words(self):
        f = extract_features("http://paypal-secure-login-verify.xyz/update/account")
        assert f["suspicious_word_count"] >= 2

    def test_clean_url_no_suspicious_words(self):
        f = extract_features("https://news.bbc.co.uk/sports/football")
        assert f["has_suspicious_word"] == 0

    # ---- URL lengths ----

    def test_short_url(self):
        f = extract_features("http://a.co")
        assert f["url_length"] < 20

    def test_long_url(self):
        long_url = "http://paypa1-secure-bank.xyz/" + "a" * 100
        f = extract_features(long_url)
        assert f["url_length"] > 75

    # ---- Subdirectories ----

    def test_subdirectory_count(self):
        f = extract_features("http://example.com/a/b/c/d")
        assert f["subdirectory_count"] == 4

    def test_no_subdirectories(self):
        f = extract_features("http://example.com")
        assert f["subdirectory_count"] == 0

    # ---- Parameters ----

    def test_params_counted(self):
        f = extract_features("http://example.com/page?a=1&b=2&c=3")
        assert f["param_count"] == 3

    def test_no_params(self):
        f = extract_features("http://example.com/page")
        assert f["param_count"] == 0

    # ---- @ symbol ----

    def test_at_symbol_detected(self):
        f = extract_features("http://user@evil.com/page")
        assert f["at_symbol"] == 1

    def test_no_at_symbol(self):
        f = extract_features("https://example.com")
        assert f["at_symbol"] == 0

    # ---- URL shorteners ----

    def test_url_shortener_detected(self):
        f = extract_features("http://bit.ly/abc123")
        assert f["is_shortened"] == 1

    def test_tinyurl_detected(self):
        f = extract_features("http://tinyurl.com/xyz789")
        assert f["is_shortened"] == 1

    def test_normal_url_not_shortened(self):
        f = extract_features("https://www.github.com/user/repo")
        assert f["is_shortened"] == 0

    # ---- Dot count ----

    def test_dot_count(self):
        f = extract_features("http://sub.domain.example.co.uk/path")
        assert f["dot_count"] >= 4

    # ---- Hyphen count ----

    def test_hyphen_in_domain(self):
        f = extract_features("http://my-fake-bank-secure.com")
        assert f["hyphen_count"] >= 3
        assert f["prefix_suffix"] == 1

    # ---- Entropy ----

    def test_entropy_is_float(self):
        f = extract_features("https://google.com")
        assert isinstance(f["url_entropy"], float)
        assert f["url_entropy"] >= 0

    # ---- Subdomain count ----

    def test_subdomain_count(self):
        f = extract_features("http://a.b.c.example.com")
        assert f["subdomain_count"] >= 2

    # ---- Non-standard port ----

    def test_standard_https_port_not_flagged(self):
        f = extract_features("https://example.com:443/page")
        assert f["has_non_standard_port"] == 0

    def test_non_standard_port(self):
        f = extract_features("http://example.com:8080/admin")
        assert f["has_non_standard_port"] == 1

    # ---- Fragment ----

    def test_fragment_detected(self):
        f = extract_features("http://example.com/page#section")
        assert f["has_fragment"] == 1

    def test_no_fragment(self):
        f = extract_features("http://example.com/page")
        assert f["has_fragment"] == 0

    # ---- features_to_list ----

    def test_features_to_list_correct_length(self):
        f = extract_features("https://google.com")
        lst = features_to_list(f, FEATURE_NAMES)
        assert len(lst) == len(FEATURE_NAMES)

    def test_features_to_list_order(self):
        f = extract_features("https://google.com")
        lst = features_to_list(f, FEATURE_NAMES)
        for i, name in enumerate(FEATURE_NAMES):
            assert lst[i] == f[name]


class TestInvalidUrls:
    """Tests for invalid and edge case URLs."""

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            extract_features("")

    def test_none_raises(self):
        with pytest.raises(ValueError):
            extract_features(None)

    def test_url_too_long_raises(self):
        with pytest.raises(ValueError):
            extract_features("http://a.com/" + "x" * 2500)

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError):
            extract_features("   ")

    def test_malformed_url_no_host(self):
        # Should not crash, returns features (hostname may be empty)
        f = extract_features("http://")
        assert isinstance(f, dict)

    def test_url_with_unicode(self):
        # Should not crash
        f = extract_features("http://example.com/página")
        assert isinstance(f, dict)

    def test_just_domain(self):
        f = extract_features("example.com")
        assert isinstance(f, dict)
        assert f["url_length"] > 0


class TestExplanations:
    """Tests for get_feature_explanations()."""

    def test_ip_flagged_in_explanations(self):
        f = extract_features("http://192.168.0.1/login")
        exps = get_feature_explanations(f)
        assert any("IP" in e or "ip" in e.lower() for e in exps)

    def test_http_flagged(self):
        f = extract_features("http://example.com")
        exps = get_feature_explanations(f)
        assert any("https" in e.lower() or "encrypt" in e.lower() for e in exps)

    def test_suspicious_words_flagged(self):
        f = extract_features("http://phish.xyz/login/verify")
        exps = get_feature_explanations(f)
        assert any("keyword" in e.lower() or "suspicious" in e.lower() for e in exps)

    def test_clean_url_few_explanations(self):
        f = extract_features("https://www.github.com")
        exps = get_feature_explanations(f)
        # Clean HTTPS URL should have 0 or minimal warnings
        assert len(exps) <= 2

    def test_returns_list(self):
        f = extract_features("https://google.com")
        exps = get_feature_explanations(f)
        assert isinstance(exps, list)
