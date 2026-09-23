"""
CivicShield — URL Risk Engine
Computes structural features from a URL string and applies rule-based checks.

IMPORTANT DESIGN CONSTRAINT:
  This engine does NOT fetch, visit, or resolve any URL at runtime.
  All features are computed purely from the URL string itself.
  This means:
    - No SSRF (Server-Side Request Forgery) risk from user-submitted URLs
    - No webpage-content features (page title, page text, favicon, etc.)
    - Page-content features from PhiUSIIL dataset are NOT used here

  This is a deliberate security decision, not a limitation to hide.
  Webpage-content analysis is deferred to P2.

Features computed (URL-structural only):
  1.  url_length              — total character count
  2.  has_ip_host             — hostname is an IP address (not a domain)
  3.  scheme_is_http          — uses insecure HTTP (not HTTPS)
  4.  is_url_shortener        — hostname matches known shortener list
  5.  suspicious_tld          — TLD is in the suspicious-TLD list
  6.  num_dots_in_domain      — count of dots in registered domain + subdomain
  7.  num_hyphens_in_domain   — count of hyphens in domain
  8.  has_at_symbol           — "@" present in URL (credential-embedding trick)
  9.  has_double_slash_path   — "//" in path after scheme (redirect trick)
  10. path_depth              — number of "/" segments in path
  11. brand_keyword_in_domain — brand keyword appears in non-official domain
  12. is_official_domain      — hostname is in the official whitelist
  13. typosquat_distance      — min Levenshtein distance from known targets
  14. apk_in_url              — URL path contains .apk or app-download keyword
"""

import re
import ipaddress
import os
import yaml
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False

try:
    from Levenshtein import distance as levenshtein_distance
    _LEVENSHTEIN_AVAILABLE = True
except ImportError:
    _LEVENSHTEIN_AVAILABLE = False

from backend.models.schemas import EvidenceItem, UrlAnalysisResult
from backend.engines.url_features import (
    URL_FEATURE_COLUMNS,
    is_ip_address as _is_ip_address,
    is_official_gov_domain,
    extract_registered_domain as _extract_registered_domain,
)

# ── IDN / Unicode homograph helpers ──────────────────────────────────────────
# Punycode-encoded ACE label prefix (RFC 3492)
_ACE_PREFIX = "xn--"

# Common Unicode confusable code-point ranges (non-ASCII look-alikes)
# These ranges cover Cyrillic, Greek, and other scripts with Latin lookalikes.
_CONFUSABLE_RANGES: list[tuple[int, int]] = [
    (0x0400, 0x04FF),  # Cyrillic (а=\u0430 looks like a, е=\u0435 like e, etc.)
    (0x0370, 0x03FF),  # Greek  (ο=\u03BF looks like o, etc.)
    (0xFF00, 0xFFEF),  # Fullwidth Latin
    (0x2000, 0x206F),  # General Punctuation (various space/dash look-alikes)
]


def _has_confusable_codepoints(text: str) -> bool:
    """Return True if text contains Unicode codepoints in confusable ranges."""
    for ch in text:
        cp = ord(ch)
        if cp > 127:  # non-ASCII
            for lo, hi in _CONFUSABLE_RANGES:
                if lo <= cp <= hi:
                    return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# Load rules from YAML at module startup (fail fast if missing)
# ─────────────────────────────────────────────────────────────────────────────

_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "url_rules.yaml"

with open(_RULES_PATH, "r", encoding="utf-8") as _f:
    _RULES = yaml.safe_load(_f)

_OFFICIAL_DOMAINS: set[str] = set(_RULES.get("official_domains", []))
_URL_SHORTENERS: set[str] = set(_RULES.get("url_shorteners", []))
_SUSPICIOUS_TLDS: set[str] = set(_RULES.get("suspicious_tlds", []))
_BRAND_KEYWORDS: list[str] = _RULES.get("brand_impersonation_keywords", [])
_TYPOSQUAT_TARGETS: list[str] = _RULES.get("typosquat_targets", [])
_APK_KEYWORDS: list[str] = _RULES.get("apk_path_keywords", [])
_THRESHOLDS: dict = _RULES.get("thresholds", {})

_MAX_LEN_WARN = _THRESHOLDS.get("max_url_length_warning", 100)
_MAX_LEN_SUSP = _THRESHOLDS.get("max_url_length_suspicious", 200)
_MAX_DOTS = _THRESHOLDS.get("max_domain_dots", 4)
_TYPO_THRESHOLD = _THRESHOLDS.get("typosquat_levenshtein_threshold", 3)

_IP_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)


# ─────────────────────────────────────────────────────────────────────────────
# Feature extraction helpers
# ─────────────────────────────────────────────────────────────────────────────

def _min_typosquat_distance(domain: str) -> int:
    """
    Compute minimum Levenshtein distance from the registered domain
    to any of the known impersonation targets.
    Returns 999 if Levenshtein library not available.
    """
    if not _LEVENSHTEIN_AVAILABLE or not domain:
        return 999
    domain_lower = domain.lower()
    return min(levenshtein_distance(domain_lower, t) for t in _TYPOSQUAT_TARGETS)


# ─────────────────────────────────────────────────────────────────────────────
# Main public function
# ─────────────────────────────────────────────────────────────────────────────

def analyze_url(url: str, ml_model=None) -> UrlAnalysisResult:
    """
    Analyse a single URL for phishing/fraud risk.
    Returns a UrlAnalysisResult with full feature transparency.

    Args:
        url:      The raw URL string to analyse.
        ml_model: Optional trained sklearn pipeline (may be None).

    All features are included in the response for audit purposes.
    """
    evidence: list[EvidenceItem] = []

    # ── Parse URL ────────────────────────────────────────────────────────────
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    path = parsed.path or ""
    scheme = (parsed.scheme or "").lower()
    full_url_lower = url.lower()

    subdomain, reg_domain, suffix = _extract_registered_domain(url)
    full_domain = f"{reg_domain}.{suffix}".lower() if suffix else reg_domain.lower()
    full_host_with_sub = hostname  # includes subdomain

    # ── Compute features ─────────────────────────────────────────────────────
    features: dict = {}

    # 1. URL length
    features["url_length"] = len(url)
    if len(url) > _MAX_LEN_SUSP:
        evidence.append(EvidenceItem(
            evidence_type="URL_RISK",
            finding=f"URL is unusually long ({len(url)} characters)",
            severity="MEDIUM",
            explanation="Very long URLs are often used to hide the true destination or confuse users.",
            source="url_risk_engine",
        ))
    elif len(url) > _MAX_LEN_WARN:
        evidence.append(EvidenceItem(
            evidence_type="URL_RISK",
            finding=f"URL is moderately long ({len(url)} characters)",
            severity="LOW",
            explanation="Moderately long URLs may indicate obfuscation. Check the domain carefully.",
            source="url_risk_engine",
        ))

    # 2. IP address as hostname
    features["has_ip_host"] = _is_ip_address(hostname)
    if features["has_ip_host"]:
        evidence.append(EvidenceItem(
            evidence_type="URL_RISK",
            finding=f"URL uses a raw IP address as hostname: {hostname}",
            severity="HIGH",
            explanation=(
                "Legitimate government websites use domain names, never raw IP addresses. "
                "IP-based URLs are a strong indicator of phishing."
            ),
            source="url_risk_engine",
        ))

    # 3. HTTP vs HTTPS
    features["scheme_is_http"] = (scheme == "http")
    if scheme == "http":
        evidence.append(EvidenceItem(
            evidence_type="URL_RISK",
            finding="URL uses insecure HTTP (not HTTPS)",
            severity="MEDIUM",
            explanation=(
                "All official Government of India portals use HTTPS. "
                "An HTTP URL for a government service is suspicious."
            ),
            source="url_risk_engine",
        ))

    # 4. URL shortener
    features["is_url_shortener"] = hostname in _URL_SHORTENERS
    if features["is_url_shortener"]:
        evidence.append(EvidenceItem(
            evidence_type="URL_RISK",
            finding=f"URL is a known shortener service: {hostname}",
            severity="HIGH",
            explanation=(
                "URL shorteners hide the true destination. "
                "Official government communications never use URL shorteners. "
                "Never follow a shortened URL from an unsolicited message."
            ),
            source="url_risk_engine",
        ))

    # 5. Suspicious TLD
    tld_check = f".{suffix}".lower() if suffix else ""
    features["suspicious_tld"] = tld_check in _SUSPICIOUS_TLDS
    if features["suspicious_tld"]:
        evidence.append(EvidenceItem(
            evidence_type="URL_RISK",
            finding=f"URL uses a suspicious top-level domain: {tld_check}",
            severity="HIGH",
            explanation=(
                f"The TLD '{tld_check}' is commonly used for phishing and fraud sites. "
                "Indian government portals exclusively use .gov.in or .nic.in"
            ),
            source="url_risk_engine",
        ))

    # 6. Number of dots in full hostname
    features["num_dots_in_domain"] = full_host_with_sub.count(".")
    if features["num_dots_in_domain"] > _MAX_DOTS:
        evidence.append(EvidenceItem(
            evidence_type="URL_RISK",
            finding=f"Domain has many subdomain levels ({features['num_dots_in_domain']} dots)",
            severity="LOW",
            explanation="Excessive subdomain nesting can be used to place legitimate-looking names at the start of a URL.",
            source="url_risk_engine",
        ))

    # 7. Hyphens in domain
    features["num_hyphens_in_domain"] = full_domain.count("-")
    if features["num_hyphens_in_domain"] >= 2:
        evidence.append(EvidenceItem(
            evidence_type="URL_RISK",
            finding=f"Domain contains multiple hyphens ({features['num_hyphens_in_domain']})",
            severity="LOW",
            explanation="Multiple hyphens in a domain are often used to create lookalike URLs (e.g. echallan-parivahan-gov.in).",
            source="url_risk_engine",
        ))

    # 8. @ symbol in URL
    features["has_at_symbol"] = "@" in url
    if features["has_at_symbol"]:
        evidence.append(EvidenceItem(
            evidence_type="URL_RISK",
            finding="URL contains '@' symbol",
            severity="HIGH",
            explanation=(
                "An '@' in a URL is used for credential embedding (user:pass@host). "
                "Browsers ignore everything before '@', so the displayed domain may be fake."
            ),
            source="url_risk_engine",
        ))

    # 9. Double slash in path
    features["has_double_slash_path"] = "//" in path
    if features["has_double_slash_path"]:
        evidence.append(EvidenceItem(
            evidence_type="URL_RISK",
            finding="URL path contains '//' (redirect trick)",
            severity="MEDIUM",
            explanation="Double slashes in the URL path are sometimes used to perform open redirects.",
            source="url_risk_engine",
        ))

    # 10. Path depth
    features["path_depth"] = len([p for p in path.split("/") if p])
    if features["path_depth"] > 6:
        evidence.append(EvidenceItem(
            evidence_type="URL_RISK",
            finding=f"URL has a very deep path ({features['path_depth']} segments)",
            severity="LOW",
            explanation="Deeply nested URL paths are sometimes used to obscure the true purpose of a URL.",
            source="url_risk_engine",
        ))

    # 12. Official domain check (exact match or genuine subdomain of official domain)
    features["is_official_domain"] = is_official_gov_domain(hostname)
    if features["is_official_domain"]:
        evidence.append(EvidenceItem(
            evidence_type="DOMAIN_CHECK",
            finding=f"Domain matches official government whitelist: {hostname}",
            severity="INFO",
            explanation=(
                "The URL hostname is in the official government domain whitelist. "
                "This is a positive signal, though the full URL path should still be checked."
            ),
            source="url_risk_engine",
        ))

    # 11. Brand keyword in non-official domain
    features["brand_keyword_in_domain"] = False
    found_keywords = []
    if not features["is_official_domain"] and not _is_ip_address(hostname):
        for kw in _BRAND_KEYWORDS:
            if kw in full_host_with_sub.lower():
                features["brand_keyword_in_domain"] = True
                found_keywords.append(kw)

    if features["brand_keyword_in_domain"]:
        evidence.append(EvidenceItem(
            evidence_type="DOMAIN_CHECK",
            finding=f"Non-official domain impersonates government brand: '{', '.join(found_keywords)}' in {full_host_with_sub}",
            severity="HIGH",
            explanation=(
                f"The domain '{full_host_with_sub}' contains government service keywords "
                f"({', '.join(found_keywords)}) but is NOT an official government domain. "
                "This is a classic lookalike/impersonation technique."
            ),
            source="url_risk_engine",
        ))

    # 13. Typosquat distance
    features["typosquat_distance"] = _min_typosquat_distance(reg_domain)
    if (
        0 < features["typosquat_distance"] <= _TYPO_THRESHOLD
        and not features["is_official_domain"]
        and _LEVENSHTEIN_AVAILABLE
    ):
        evidence.append(EvidenceItem(
            evidence_type="DOMAIN_CHECK",
            finding=f"Domain '{reg_domain}' is a close spelling variant of an official service",
            severity="HIGH",
            explanation=(
                f"The registered domain '{reg_domain}' is only {features['typosquat_distance']} "
                "character(s) away from an official government service name. "
                "This is a typosquatting indicator."
            ),
            source="url_risk_engine",
        ))

    # 14. APK in URL
    features["apk_in_url"] = any(kw in full_url_lower for kw in _APK_KEYWORDS)
    if features["apk_in_url"]:
        evidence.append(EvidenceItem(
            evidence_type="URL_RISK",
            finding="URL path suggests an APK/application download",
            severity="HIGH",
            explanation=(
                "The URL path contains keywords suggesting an APK or app download. "
                "The Government of India e-Challan service does NOT distribute APK files via URL. "
                "Downloading this file could install malware."
            ),
            source="url_risk_engine",
        ))

    # 15. IDN / Unicode homograph detection
    # Check the raw hostname (before urlparse normalisation strips encoding)
    raw_hostname_lower = url.split("/")[2].lower() if url.count("/") >= 2 else hostname
    has_punycode = _ACE_PREFIX in raw_hostname_lower
    has_confusable = _has_confusable_codepoints(hostname)  # after IDNA decode

    if has_punycode:
        # Punycode labels are always suspicious in Indian govt domain context
        evidence.append(EvidenceItem(
            evidence_type="DOMAIN_CHECK",
            finding=f"Domain uses Punycode/IDN encoding: {hostname}",
            severity="HIGH",
            explanation=(
                "Punycode ('xn--') in a domain usually means the domain contains "
                "non-ASCII Unicode characters that look like Latin letters. "
                "This is a classic technique to impersonate trusted domains "
                "(e.g., xn--parivahn-... to mimic parivahan.gov.in). "
                "Official Indian government portals do not use IDN domains."
            ),
            source="url_risk_engine",
        ))
    elif has_confusable and not features["is_official_domain"]:
        evidence.append(EvidenceItem(
            evidence_type="DOMAIN_CHECK",
            finding=f"Domain contains Unicode look-alike characters: {hostname}",
            severity="HIGH",
            explanation=(
                "The domain contains non-ASCII characters from scripts "
                "(e.g., Cyrillic, Greek) that visually resemble Latin letters. "
                "This is a homograph attack: the domain looks identical to an "
                "official site but is a different host. "
                "Official Indian government portals use plain ASCII domains."
            ),
            source="url_risk_engine",
        ))

    # ── ML prediction (if model available) ───────────────────────────────────
    ml_prediction: Optional[str] = None
    ml_available = ml_model is not None
    if ml_available:
        try:
            from ml.url_model_loader import predict_url
            ml_prediction = predict_url(ml_model, url, features)
            if ml_prediction == "phishing":
                evidence.append(EvidenceItem(
                    evidence_type="URL_RISK",
                    finding="ML model classifies this URL as likely phishing",
                    severity="MEDIUM",
                    explanation=(
                        "A RandomForest model trained on URL structural features "
                        "classifies this URL as phishing. "
                        "This is a supplementary signal — the rule-based evidence above is primary."
                    ),
                    source="url_ml_model",
                ))
        except Exception as exc:
            evidence.append(EvidenceItem(
                evidence_type="PROCESSING_NOTE",
                finding=f"ML model prediction failed: {exc}",
                severity="INFO",
                explanation="Rule-based analysis was completed. ML model was unavailable.",
                source="url_ml_model",
            ))

    # ── Derive risk level ─────────────────────────────────────────────────────
    high_count = sum(1 for e in evidence if e.severity == "HIGH")
    med_count = sum(1 for e in evidence if e.severity == "MEDIUM")

    if features["is_official_domain"] and high_count == 0:
        risk_level = "LOW"
    elif high_count >= 2 or (high_count == 1 and med_count >= 1):
        risk_level = "HIGH"
    elif high_count == 1 or med_count >= 2:
        risk_level = "MEDIUM"
    elif med_count == 1:
        risk_level = "LOW"
    else:
        risk_level = "UNKNOWN"

    return UrlAnalysisResult(
        url=url,
        risk_level=risk_level,
        features=features,
        evidence=evidence,
        ml_prediction=ml_prediction,
        ml_available=ml_available,
    )
