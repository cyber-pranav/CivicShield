"""
CivicShield — Model Evaluation Script
Reports accuracy, precision, recall, F1, and confusion matrix on the held-out test set.

IMPORTANT: This script ONLY evaluates on the test set saved during training.
The metrics it reports are measured, not fabricated. Do not modify the test set
or use training data for evaluation.

Usage:
  cd e:/IDT/prototype
  python scripts/evaluate_model.py

Prerequisites:
  Run scripts/train_url_model.py first to generate:
    - models/url_risk_model.joblib
    - models/test_set.joblib
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

MODEL_PATH = ROOT / "models" / "url_risk_model.joblib"
TEST_SET_PATH = ROOT / "models" / "test_set.joblib"


def main():
    print("=" * 60)
    print("CivicShield — URL Model Evaluation")
    print("=" * 60)

    # ── Load model ────────────────────────────────────────────────────────────
    if not MODEL_PATH.exists():
        print(f"\nERROR: Model file not found at {MODEL_PATH}")
        print("Run scripts/train_url_model.py first.")
        sys.exit(1)

    if not TEST_SET_PATH.exists():
        print(f"\nERROR: Test set not found at {TEST_SET_PATH}")
        print("Run scripts/train_url_model.py first to generate the test set.")
        sys.exit(1)

    print(f"\nLoading model from: {MODEL_PATH}")
    model = joblib.load(MODEL_PATH)

    print(f"Loading test set from: {TEST_SET_PATH}")
    test_data = joblib.load(TEST_SET_PATH)
    X_test = test_data["X_test"]
    y_test = test_data["y_test"]

    print(f"Test set size: {len(y_test)}")
    print(f"Class distribution in test set:\n{y_test.value_counts()}")

    # ── Predict ───────────────────────────────────────────────────────────────
    print("\nRunning predictions on test set...")
    y_pred = model.predict(X_test)

    # ── Metrics ───────────────────────────────────────────────────────────────
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "=" * 60)
    print("EVALUATION RESULTS (on held-out test set)")
    print("=" * 60)
    print(f"  Accuracy  : {acc:.4f}")
    print(f"  Precision : {prec:.4f}  (phishing class)")
    print(f"  Recall    : {rec:.4f}  (phishing class)")
    print(f"  F1 Score  : {f1:.4f}  (phishing class)")

    print("\nConfusion Matrix:")
    print("  Labels: 0=legitimate, 1=phishing")
    print(f"  [[TN={cm[0,0]:>6}  FP={cm[0,1]:>6}]")
    print(f"   [FN={cm[1,0]:>6}  TP={cm[1,1]:>6}]]")

    print("\nFull Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))

    print("=" * 60)
    print(
        "NOTE: Metrics above reflect URL-structural features only.\n"
        "Webpage-content features (page title, favicon, etc.) are NOT used.\n"
        "These metrics were measured on the PhiUSIIL dataset test split.\n"
        "Real-world performance on Indian e-Challan phishing may differ."
    )
    print("=" * 60)


if __name__ == "__main__":
    main()
