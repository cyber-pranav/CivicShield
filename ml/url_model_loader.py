"""
CivicShield — ML URL Model Loader
Lazy-loads the trained URL risk model from models/url_risk_model.joblib.

Returns None if the model file does not exist — the system degrades
gracefully to rule-only analysis with a processing note in the response.

This module is intentionally thin: it only loads and exposes the model.
Feature computation lives in url_risk_engine.py.
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import Optional

import joblib
import numpy as np

from backend.engines.url_features import URL_FEATURE_COLUMNS

_MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "url_risk_model.joblib"


def load_model():
    """
    Load the trained URL risk model.
    Returns None if model file does not exist (graceful degradation).
    """
    if not _MODEL_PATH.exists():
        return None
    try:
        model = joblib.load(_MODEL_PATH)
        return model
    except Exception as exc:
        print(f"[CivicShield] Warning: Could not load ML model: {exc}")
        return None


def predict_url(model, url: str, features: dict) -> str:
    """
    Run the trained model on pre-computed URL features.

    Args:
        model:    Loaded sklearn model (pipeline or classifier).
        url:      Original URL string (for logging only).
        features: Dict from url_risk_engine.analyze_url()

    Returns:
        "phishing" or "legitimate"
    """
    if model is None:
        return "unknown"

    # Build feature vector in exact training order
    feature_vector = []
    for col in URL_FEATURE_COLUMNS:
        val = features.get(col, 0)
        # Convert booleans to int for sklearn
        feature_vector.append(int(val) if isinstance(val, bool) else (val or 0))

    X = np.array([feature_vector])
    pred = model.predict(X)[0]

    # Handle both string labels and integer labels
    if isinstance(pred, (int, float)):
        return "phishing" if int(pred) == 1 else "legitimate"
    return str(pred).lower()
