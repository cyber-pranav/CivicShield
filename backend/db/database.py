"""
CivicShield — Database
SQLite via SQLAlchemy for storing analysis session metadata.
Supports DATABASE_URL env var override to switch to PostgreSQL (or any
SQLAlchemy-compatible database) without code changes.

PRIVACY NOTE:
  - Raw document content is NOT stored
  - Only a SHA-256 hash of the input + verdict + timestamp are stored
  - This allows auditing without retaining personal data
"""

from __future__ import annotations
import hashlib
import datetime
import os
from pathlib import Path
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker

# Default: local SQLite file alongside the project root.
# Override with DATABASE_URL env var for managed Postgres on Render, etc.
_DEFAULT_DB_URL = f"sqlite:///{Path(__file__).resolve().parents[2] / 'civicshield.db'}"
_DB_URL = os.getenv("DATABASE_URL", _DEFAULT_DB_URL)

# Render Postgres URLs use postgres:// but SQLAlchemy requires postgresql://
if _DB_URL.startswith("postgres://"):
    _DB_URL = _DB_URL.replace("postgres://", "postgresql://", 1)

_connect_args = {"check_same_thread": False} if _DB_URL.startswith("sqlite") else {}
_ENGINE = create_engine(_DB_URL, connect_args=_connect_args)
_SessionLocal = sessionmaker(bind=_ENGINE, autoflush=False, autocommit=False)

Base = declarative_base()


class AnalysisSession(Base):
    __tablename__ = "analysis_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    input_hash = Column(String(64), nullable=False, index=True)
    input_type = Column(String(20), nullable=False)
    verdict = Column(String(30), nullable=False)
    risk_level = Column(String(10), nullable=False)
    detected_category = Column(String(50), default="government_notice")
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.UTC))


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_type = Column(String(50), nullable=False, index=True)
    value = Column(String(255), nullable=False)
    category = Column(String(50), nullable=False, default="government_notice")
    severity = Column(String(20), nullable=False, default="HIGH")
    source = Column(String(50), nullable=False, default="manual")
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.UTC))
    updated_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.UTC), onupdate=lambda: datetime.datetime.now(datetime.UTC))

def init_db() -> None:
    """Create tables if they don't exist."""
    Base.metadata.create_all(bind=_ENGINE)


def log_analysis(
    input_content: str,
    input_type: str,
    verdict: str,
    risk_level: str,
    high_count: int,
    medium_count: int,
    low_count: int,
    detected_category: str = "government_notice",
) -> None:
    """Log an analysis session to the database (no raw content stored)."""
    input_hash = hashlib.sha256(input_content.encode("utf-8", errors="replace")).hexdigest()
    db = _SessionLocal()
    try:
        session = AnalysisSession(
            input_hash=input_hash,
            input_type=input_type,
            verdict=verdict,
            risk_level=risk_level,
            detected_category=detected_category,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
        )
        db.add(session)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

# ─────────────────────────────────────────────────────────────────────────────
# Indicator CRUD
# ─────────────────────────────────────────────────────────────────────────────

def add_indicator(data: dict) -> dict:
    session = _SessionLocal()
    try:
        ind = Indicator(**data)
        session.add(ind)
        session.commit()
        session.refresh(ind)
        return {
            "id": ind.id, "indicator_type": ind.indicator_type, "value": ind.value,
            "category": ind.category, "severity": ind.severity, "source": ind.source,
            "description": ind.description, "is_active": ind.is_active,
            "created_at": ind.created_at.isoformat(), "updated_at": ind.updated_at.isoformat()
        }
    finally:
        session.close()

def get_active_indicators() -> list[dict]:
    session = _SessionLocal()
    try:
        results = session.query(Indicator).filter(Indicator.is_active == True).all()
        return [{"indicator_type": r.indicator_type, "value": r.value, "category": r.category, "severity": r.severity} for r in results]
    finally:
        session.close()

def get_all_indicators(indicator_type: str | None = None, category: str | None = None) -> list[dict]:
    session = _SessionLocal()
    try:
        query = session.query(Indicator)
        if indicator_type:
            query = query.filter(Indicator.indicator_type == indicator_type)
        if category:
            query = query.filter(Indicator.category == category)
            
        results = query.all()
        return [{
            "id": r.id, "indicator_type": r.indicator_type, "value": r.value,
            "category": r.category, "severity": r.severity, "source": r.source,
            "description": r.description, "is_active": r.is_active,
            "created_at": r.created_at.isoformat(), "updated_at": r.updated_at.isoformat()
        } for r in results]
    finally:
        session.close()

def update_indicator(indicator_id: int, updates: dict) -> dict | None:
    session = _SessionLocal()
    try:
        ind = session.query(Indicator).filter(Indicator.id == indicator_id).first()
        if not ind:
            return None
        for k, v in updates.items():
            if hasattr(ind, k) and v_is_not_none(v):
                setattr(ind, k, v)
        session.commit()
        session.refresh(ind)
        return {
            "id": ind.id, "indicator_type": ind.indicator_type, "value": ind.value,
            "category": ind.category, "severity": ind.severity, "source": ind.source,
            "description": ind.description, "is_active": ind.is_active,
            "created_at": ind.created_at.isoformat(), "updated_at": ind.updated_at.isoformat()
        }
    finally:
        session.close()

def v_is_not_none(v):
    return v is not None

def delete_indicator(indicator_id: int) -> bool:
    session = _SessionLocal()
    try:
        ind = session.query(Indicator).filter(Indicator.id == indicator_id).first()
        if not ind:
            return False
        session.delete(ind)
        session.commit()
        return True
    finally:
        session.close()
