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

from backend.engines.url_features import extract_url_features, URL_FEATURE_COLUMNS


def compute_url_features(url: str) -> dict:
    """Wrapper around shared authoritative feature extractor."""
    return extract_url_features(url)


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

    X = pd.DataFrame(feature_rows)[URL_FEATURE_COLUMNS]
    print(f"\nFeature matrix shape: {X.shape}")
    print(f"Features in exact order: {list(X.columns)}")

    # ── Encode labels strictly ────────────────────────────────────────────────
    LEGITIMATE_LABELS = {"0", "legitimate", "benign", "safe", "ham", "good"}
    PHISHING_LABELS = {"1", "phishing", "phish", "malicious", "bad", "fraud"}

    def normalize_label(val) -> int:
        s = str(val).strip().lower()
        if s in LEGITIMATE_LABELS:
            return 0
        if s in PHISHING_LABELS:
            return 1
        raise ValueError(f"Unknown or ambiguous label encountered: '{val}'")

    try:
        y = df[label_col].apply(normalize_label)
    except ValueError as exc:
        print(f"\nFATAL ERROR during label normalization: {exc}")
        print("Training aborted: unknown labels must not be silently classified.")
        sys.exit(1)

    print(f"\nNormalized class distribution:\n{y.value_counts()}")

    if len(y.unique()) < 2:
        print("\nFATAL ERROR: Training dataset does not contain both classes (0 and 1).")
        sys.exit(1)

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
