"""
CivicShield — Unified URL Structural Features
Authoritative implementation of the 12 URL structural features used
consistently across training (scripts/train_url_model.py) and
inference (backend/engines/url_risk_engine.py and ml/url_model_loader.py).

Guarantees:
- Zero runtime network access (purely structural)
- Exact feature name and order alignment between training and inference
- Standardized boolean/integer representation
"""

from __future__ import annotations
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse
import yaml

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False

# Authoritative feature list in exact order
URL_FEATURE_COLUMNS: list[str] = [
    "url_length",
    "has_ip_host",
    "scheme_is_http",
    "is_url_shortener",
    "suspicious_tld",
    "num_dots_in_domain",
    "num_hyphens_in_domain",
    "has_at_symbol",
    "has_double_slash_path",
    "path_depth",
    "brand_keyword_in_domain",
    "apk_in_url",
]

# Load rules for shorteners, TLDs, keywords
_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "url_rules.yaml"
try:
    with open(_RULES_PATH, "r", encoding="utf-8") as _f:
        _RULES = yaml.safe_load(_f)
except Exception:
    _RULES = {}

_OFFICIAL_DOMAINS: set[str] = set(_RULES.get("official_domains", []))
_URL_SHORTENERS: set[str] = set(_RULES.get("url_shorteners", []))
_SUSPICIOUS_TLDS: set[str] = set(_RULES.get("suspicious_tlds", []))
_BRAND_KEYWORDS: list[str] = _RULES.get("brand_impersonation_keywords", [])
_APK_KEYWORDS: list[str] = _RULES.get("apk_path_keywords", [])


def is_ip_address(hostname: str) -> bool:
    """Return True if hostname is a raw IPv4 or IPv6 address."""
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def is_official_gov_domain(hostname: str) -> bool:
    """
    Check if a normalized hostname is an exact official domain or genuine subdomain.
    Rejects attacker suffixes such as:
    echallan.parivahan.gov.in.evil.com
    parivahan.gov.in.attacker.com
    fakeparivahan.gov.in
    """
    if not hostname:
        return False
    norm_host = hostname.lower().rstrip(".")
    for od in _OFFICIAL_DOMAINS:
        od_norm = od.lower().rstrip(".")
        if norm_host == od_norm or norm_host.endswith("." + od_norm):
            return True
    return False


def extract_registered_domain(url: str) -> tuple[str, str, str]:
    """Returns (subdomain, registered_domain, suffix)."""
    if _TLDEXTRACT_AVAILABLE:
        ext = tldextract.extract(url)
        return ext.subdomain, ext.domain, ext.suffix
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[:-2]), parts[-2], parts[-1]
    return "", host, ""


def extract_url_features(url: str) -> dict[str, int]:
    """
    Extract the 12 canonical URL structural features as integers (0 or 1, or counts).
    """
    features: dict[str, int] = {col: 0 for col in URL_FEATURE_COLUMNS}
    if not url:
        return features

    try:
        url_str = str(url).strip()
        features["url_length"] = len(url_str)

        parsed = urlparse(url_str)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        path = parsed.path or ""
        scheme = (parsed.scheme or "").lower()

        subdomain, reg_domain, suffix = extract_registered_domain(url_str)
        full_domain = f"{reg_domain}.{suffix}".lower() if suffix else reg_domain.lower()
        full_host = hostname

        features["has_ip_host"] = int(is_ip_address(hostname))
        features["scheme_is_http"] = int(scheme == "http")
        features["is_url_shortener"] = int(hostname in _URL_SHORTENERS)

        tld_key = f".{suffix}".lower() if suffix else ""
        features["suspicious_tld"] = int(tld_key in _SUSPICIOUS_TLDS)
        features["num_dots_in_domain"] = full_host.count(".")
        features["num_hyphens_in_domain"] = full_domain.count("-")
        features["has_at_symbol"] = int("@" in url_str)
        features["has_double_slash_path"] = int("//" in path)
        features["path_depth"] = len([p for p in path.split("/") if p])

        # Brand keyword in non-official domain
        is_official = is_official_gov_domain(hostname)
        brand_hit = (not is_official) and any(kw in full_host for kw in _BRAND_KEYWORDS)
        features["brand_keyword_in_domain"] = int(brand_hit)

        # APK in URL
        url_lower = url_str.lower()
        features["apk_in_url"] = int(any(kw in url_lower for kw in _APK_KEYWORDS))

    except Exception:
        pass

    return features
