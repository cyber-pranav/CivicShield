"""
CivicShield — URL Model Training Script
Trains a RandomForestClassifier on the PhiUSIIL Phishing URL NLP Dataset.

IMPORTANT — Feature Selection Policy:
  This script uses ONLY URL-structural features that can be computed from
  a raw URL string without fetching any webpage. This is a deliberate
  security and reliability decision:
    - No SSRF risk during inference
    - Works on any URL without network access
    - Reproducible results

  PhiUSIIL features that REQUIRE webpage access and are NOT used here:
    - Page title analysis
    - Meta description content
    - Favicon analysis
    - JavaScript execution signals
    - Page content features
    - SSL certificate details (not in URL string)
  These are explicitly dropped before training.

Dataset expected at: data/PhiUSIIL_Phishing_URL_NLP_Dataset.csv
Trained model saved to: models/url_risk_model.joblib

Usage:
  cd e:/IDT/prototype
  python scripts/train_url_model.py

Requirements:
  pip install scikit-learn joblib pandas tldextract python-levenshtein pyyaml
"""

import sys
import os
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pandas as pd
import numpy as np
import yaml
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.pipeline import Pipeline

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

DATASET_PATH = ROOT / "data" / "PhiUSIIL_Phishing_URL_NLP_Dataset.csv"
MODEL_OUTPUT_PATH = ROOT / "models" / "url_risk_model.joblib"
RANDOM_SEED = 42
TEST_SPLIT = 0.20
N_ESTIMATORS = 100

# ─────────────────────────────────────────────────────────────────────────────
# Feature computation (URL-structural only — mirrors url_risk_engine.py)
# ─────────────────────────────────────────────────────────────────────────────

import ipaddress
import re
from urllib.parse import urlparse

try:
    import tldextract
    _TLDEXTRACT_OK = True
except ImportError:
    _TLDEXTRACT_OK = False
    print("WARNING: tldextract not installed. Domain features will be limited.")

try:
    from Levenshtein import distance as levenshtein_distance
    _LEV_OK = True
except ImportError:
    _LEV_OK = False
    print("WARNING: python-levenshtein not installed. Typosquat feature skipped.")

# Load rule lists from YAML
_RULES_PATH = ROOT / "rules" / "url_rules.yaml"
with open(_RULES_PATH, "r") as f:
    _RULES = yaml.safe_load(f)

_URL_SHORTENERS = set(_RULES.get("url_shorteners", []))
_SUSPICIOUS_TLDS = set(_RULES.get("suspicious_tlds", []))
_BRAND_KEYWORDS = _RULES.get("brand_impersonation_keywords", [])
_APK_KEYWORDS = _RULES.get("apk_path_keywords", [])
_OFFICIAL_DOMAINS = set(_RULES.get("official_domains", []))


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def compute_url_features(url: str) -> dict:
    """
    Compute URL-structural features for a single URL.
    Returns a dict with all feature values.
    Any computation failure returns a 0/False default for that feature.
    """
    features = {
        "url_length": 0,
        "has_ip_host": 0,
        "scheme_is_http": 0,
        "is_url_shortener": 0,
        "suspicious_tld": 0,
        "num_dots_in_domain": 0,
        "num_hyphens_in_domain": 0,
        "has_at_symbol": 0,
        "has_double_slash_path": 0,
        "path_depth": 0,
        "brand_keyword_in_domain": 0,
        "apk_in_url": 0,
    }

    try:
        url = str(url).strip()
        if not url:
            return features

        features["url_length"] = len(url)

        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        scheme = (parsed.scheme or "").lower()

        if _TLDEXTRACT_OK:
            ext = tldextract.extract(url)
            subdomain = ext.subdomain
            reg_domain = ext.domain
            suffix = ext.suffix
        else:
            parts = hostname.split(".")
            reg_domain = parts[-2] if len(parts) >= 2 else hostname
            suffix = parts[-1] if parts else ""
            subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""

        full_domain = f"{reg_domain}.{suffix}".lower()
        full_host = hostname

        features["has_ip_host"] = int(_is_ip(hostname))
        features["scheme_is_http"] = int(scheme == "http")
        features["is_url_shortener"] = int(hostname in _URL_SHORTENERS)

        tld_key = f".{suffix}".lower()
        features["suspicious_tld"] = int(tld_key in _SUSPICIOUS_TLDS)
        features["num_dots_in_domain"] = full_host.count(".")
        features["num_hyphens_in_domain"] = full_domain.count("-")
        features["has_at_symbol"] = int("@" in url)
        features["has_double_slash_path"] = int("//" in path)
        features["path_depth"] = len([p for p in path.split("/") if p])

        # Brand keyword in non-official domain
        brand_hit = any(
            kw in full_host for kw in _BRAND_KEYWORDS
            if full_domain not in _OFFICIAL_DOMAINS
        )
        features["brand_keyword_in_domain"] = int(brand_hit)

        # APK in URL
        url_lower = url.lower()
        features["apk_in_url"] = int(any(kw in url_lower for kw in _APK_KEYWORDS))

    except Exception as e:
        pass  # Return defaults for any parsing failure

    return features


# ─────────────────────────────────────────────────────────────────────────────
# Main training pipeline
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("CivicShield — URL Model Training")
    print("=" * 60)

    if not DATASET_PATH.exists():
        print(f"\nERROR: Dataset not found at {DATASET_PATH}")
        print(
            "Download the PhiUSIIL Phishing URL NLP Dataset and place it at:\n"
            f"  {DATASET_PATH}"
        )
        sys.exit(1)

    print(f"\nLoading dataset from: {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH, low_memory=False)
    print(f"Dataset shape: {df.shape}")
    print(f"Columns: {list(df.columns)}")

    # ── Find URL column ───────────────────────────────────────────────────────
    url_col = None
    label_col = None

    for col in df.columns:
        col_lower = col.lower()
        if col_lower in ("url", "urls", "link", "address"):
            url_col = col
        if col_lower in ("label", "class", "phishing", "status", "type", "result"):
            label_col = col

    if url_col is None:
        print(
            "\nERROR: Could not identify URL column automatically.\n"
            f"Available columns: {list(df.columns)}\n"
            "Set url_col manually in this script."
        )
        sys.exit(1)

    if label_col is None:
        print(
            "\nERROR: Could not identify label column automatically.\n"
            f"Available columns: {list(df.columns)}\n"
            "Set label_col manually in this script."
        )
        sys.exit(1)

    print(f"\nURL column: '{url_col}'")
    print(f"Label column: '{label_col}'")

    # ── Clean data ────────────────────────────────────────────────────────────
    df = df[[url_col, label_col]].dropna()
    print(f"\nRows after dropping NAs: {len(df)}")
    print(f"Label distribution:\n{df[label_col].value_counts()}")

    # ── Compute features ──────────────────────────────────────────────────────
    print("\nComputing URL structural features (this may take a few minutes)...")
    feature_rows = []
    for i, url in enumerate(df[url_col]):
        if i % 10000 == 0:
            print(f"  Processing row {i}/{len(df)}...")
        feature_rows.append(compute_url_features(url))

    X = pd.DataFrame(feature_rows)
    print(f"\nFeature matrix shape: {X.shape}")
    print(f"Features: {list(X.columns)}")

    # ── Encode labels ─────────────────────────────────────────────────────────
    y_raw = df[label_col].astype(str).str.lower()
    # Normalise label: anything containing "phish" or "1" => 1, else 0
    y = y_raw.apply(lambda x: 1 if ("phish" in x or x == "1") else 0)
    print(f"\nEncoded label distribution:\n{y.value_counts()}")

    # ── Train/test split ──────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SPLIT, random_state=RANDOM_SEED, stratify=y
    )
    print(f"\nTrain size: {len(X_train)} | Test size: {len(X_test)}")

    # ── Save test set for evaluate_model.py ──────────────────────────────────
    test_set_path = ROOT / "models" / "test_set.joblib"
    joblib.dump({"X_test": X_test, "y_test": y_test}, test_set_path)
    print(f"Test set saved to: {test_set_path}")

    # ── Train model ───────────────────────────────────────────────────────────
    print(f"\nTraining RandomForestClassifier (n_estimators={N_ESTIMATORS}, seed={RANDOM_SEED})...")
    clf = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        random_state=RANDOM_SEED,
        n_jobs=-1,
        class_weight="balanced",  # handle class imbalance
    )
    clf.fit(X_train, y_train)

    # ── Feature importance ────────────────────────────────────────────────────
    print("\nFeature importances:")
    importance_pairs = sorted(
        zip(X.columns, clf.feature_importances_),
        key=lambda x: x[1],
        reverse=True,
    )
    for feat, imp in importance_pairs:
        print(f"  {feat:<35} {imp:.4f}")

    # ── Save model ────────────────────────────────────────────────────────────
    MODEL_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODEL_OUTPUT_PATH)
    print(f"\nModel saved to: {MODEL_OUTPUT_PATH}")
    print("\nTraining complete. Run scripts/evaluate_model.py to get metrics.")


if __name__ == "__main__":
    main()
