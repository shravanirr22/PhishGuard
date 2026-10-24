"""
feature_extraction.py
Extracts URL-based features for phishing detection.
All extraction is done purely via string/URL parsing — no HTTP requests are made.
"""

import re
import math
import urllib.parse
from typing import Dict, Any

# Suspicious keywords commonly found in phishing URLs
SUSPICIOUS_WORDS = [
    "login", "verify", "update", "secure", "account", "banking",
    "confirm", "password", "credential", "signin", "logon", "webscr",
    "ebayisapi", "paypal", "submit", "free", "lucky", "service",
    "access", "support", "suspend", "unusual", "security", "alert",
    "validation", "click", "user", "client", "billing", "invoice",
]

# Known URL shortening services
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd",
    "buff.ly", "adf.ly", "bitly.com", "short.io", "rb.gy", "cutt.ly",
    "rebrand.ly", "tiny.cc", "shorte.st", "link.tl", "lnkd.in",
]

# IP address pattern (v4)
IP_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)

# Hex-encoded IP pattern in URL
HEX_IP_PATTERN = re.compile(r"0x[0-9a-fA-F]{8}")


def _safe_parse(url: str) -> urllib.parse.ParseResult:
    """Parse a URL safely, adding scheme if missing."""
    url = url.strip()
    if not url.startswith(("http://", "https://", "ftp://")):
        url = "http://" + url
    return urllib.parse.urlparse(url)


def _count_digits(s: str) -> int:
    return sum(c.isdigit() for c in s)


def _count_special_chars(s: str) -> int:
    special = set("!@#$%^&*()_+-=[]{}|;':\",./<>?\\`~")
    return sum(c in special for c in s)


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_features(url: str) -> Dict[str, Any]:
    """
    Extract phishing-detection features from a URL string.

    Parameters
    ----------
    url : str
        Raw URL string provided by the user.

    Returns
    -------
    dict
        Feature dictionary with numeric and boolean values.
        Raises ValueError for completely unparseable URLs.
    """
    if not isinstance(url, str):
        raise ValueError("URL must be a non-empty string.")

    url = url.strip()
    if not url:
        raise ValueError("URL must be a non-empty string.")

    if len(url) > 2048:
        raise ValueError("URL exceeds maximum allowed length of 2048 characters.")

    parsed = _safe_parse(url)

    # --- Scheme ---
    scheme = parsed.scheme.lower()
    has_https = int(scheme == "https")

    # --- Hostname / domain ---
    hostname = parsed.hostname or ""
    is_ip_address = int(bool(IP_PATTERN.match(hostname)) or bool(HEX_IP_PATTERN.search(hostname)))

    # Use tldextract for cleaner domain parsing (with fallback)
    try:
        import tldextract
        ext = tldextract.extract(url)
        domain = ext.domain
        suffix = ext.suffix
        subdomain = ext.subdomain
        subdomain_count = len(subdomain.split(".")) if subdomain else 0
        domain_length = len(domain)
    except Exception:
        # Fallback: simple split
        parts = hostname.split(".")
        domain = parts[-2] if len(parts) >= 2 else hostname
        suffix = parts[-1] if len(parts) >= 1 else ""
        subdomain_count = max(0, len(parts) - 2)
        domain_length = len(domain)

    # --- Full URL properties ---
    full_url = url
    url_length = len(full_url)
    dot_count = full_url.count(".")
    hyphen_count = hostname.count("-")
    at_symbol = int("@" in full_url)
    double_slash_redirect = int("//" in parsed.path)

    # --- Path ---
    path = parsed.path or ""
    path_parts = [p for p in path.split("/") if p]
    subdirectory_count = len(path_parts)

    # --- Query parameters ---
    query = parsed.query or ""
    params = urllib.parse.parse_qs(query)
    param_count = len(params)

    # --- Suspicious words ---
    url_lower = full_url.lower()
    suspicious_word_count = sum(w in url_lower for w in SUSPICIOUS_WORDS)
    has_suspicious_word = int(suspicious_word_count > 0)

    # --- Digits and special characters ---
    digit_count = _count_digits(full_url)
    special_char_count = _count_special_chars(full_url)

    # --- URL shortener ---
    is_shortened = int(any(s in hostname.lower() for s in URL_SHORTENERS))

    # --- Entropy ---
    url_entropy = _shannon_entropy(full_url)
    domain_entropy = _shannon_entropy(domain)

    # --- Prefix/suffix with hyphen in domain ---
    prefix_suffix = int("-" in domain)

    # --- Port ---
    port = parsed.port
    has_non_standard_port = int(port is not None and port not in (80, 443))

    # --- Fragment ---
    has_fragment = int(bool(parsed.fragment))

    # --- Length of longest path segment ---
    longest_segment = max((len(p) for p in path_parts), default=0)

    features = {
        "url_length": url_length,
        "domain_length": domain_length,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "subdirectory_count": subdirectory_count,
        "param_count": param_count,
        "subdomain_count": subdomain_count,
        "has_https": has_https,
        "is_ip_address": is_ip_address,
        "has_suspicious_word": has_suspicious_word,
        "suspicious_word_count": suspicious_word_count,
        "at_symbol": at_symbol,
        "double_slash_redirect": double_slash_redirect,
        "digit_count": digit_count,
        "special_char_count": special_char_count,
        "is_shortened": is_shortened,
        "url_entropy": url_entropy,
        "domain_entropy": domain_entropy,
        "prefix_suffix": prefix_suffix,
        "has_non_standard_port": has_non_standard_port,
        "has_fragment": has_fragment,
        "longest_path_segment": longest_segment,
    }

    return features


def features_to_list(features: Dict[str, Any], feature_names: list) -> list:
    """Convert feature dict to ordered list matching feature_names."""
    return [features.get(name, 0) for name in feature_names]


# All feature names in training order
FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "dot_count",
    "hyphen_count",
    "subdirectory_count",
    "param_count",
    "subdomain_count",
    "has_https",
    "is_ip_address",
    "has_suspicious_word",
    "suspicious_word_count",
    "at_symbol",
    "double_slash_redirect",
    "digit_count",
    "special_char_count",
    "is_shortened",
    "url_entropy",
    "domain_entropy",
    "prefix_suffix",
    "has_non_standard_port",
    "has_fragment",
    "longest_path_segment",
]


def get_feature_explanations(features: Dict[str, Any]) -> list:
    """
    Return a list of human-readable explanations for suspicious features.
    """
    explanations = []

    if features.get("is_ip_address"):
        explanations.append("Uses raw IP address instead of domain name — common in phishing.")
    if not features.get("has_https"):
        explanations.append("Does not use HTTPS — connection is not encrypted.")
    if features.get("has_suspicious_word"):
        explanations.append(f"Contains {features['suspicious_word_count']} suspicious keyword(s) (e.g., login, verify, secure).")
    if features.get("at_symbol"):
        explanations.append("Contains '@' symbol — browser ignores everything before it, a deception trick.")
    if features.get("is_shortened"):
        explanations.append("Uses a URL shortening service — hides the true destination.")
    if features.get("hyphen_count", 0) > 2:
        explanations.append(f"Domain contains {features['hyphen_count']} hyphens — often used to mimic legitimate domains.")
    if features.get("url_length", 0) > 75:
        explanations.append(f"URL is unusually long ({features['url_length']} chars) — may be obfuscating the true destination.")
    if features.get("subdomain_count", 0) > 2:
        explanations.append(f"Has {features['subdomain_count']} subdomains — may be mimicking a trusted domain.")
    if features.get("double_slash_redirect"):
        explanations.append("Contains double-slash redirect in path — commonly used to confuse parsers.")
    if features.get("param_count", 0) > 5:
        explanations.append(f"Has {features['param_count']} query parameters — excessive parameters can indicate tracking or obfuscation.")
    if features.get("has_non_standard_port"):
        explanations.append("Uses a non-standard port — unusual for legitimate websites.")
    if features.get("url_entropy", 0) > 4.5:
        explanations.append(f"URL entropy is high ({features['url_entropy']:.2f}) — suggests random/obfuscated characters.")
    if features.get("digit_count", 0) > 10:
        explanations.append(f"URL contains {features['digit_count']} digits — may contain encoded data.")

    return explanations
