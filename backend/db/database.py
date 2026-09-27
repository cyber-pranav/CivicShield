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
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text
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
