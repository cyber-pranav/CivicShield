"""
CivicShield — Database
SQLite via SQLAlchemy for storing analysis session metadata.

PRIVACY NOTE:
  - Raw document content is NOT stored
  - Only a SHA-256 hash of the input + verdict + timestamp are stored
  - This allows auditing without retaining personal data
"""

from __future__ import annotations
import hashlib
import datetime
from pathlib import Path
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker

_DB_PATH = Path(__file__).resolve().parents[2] / "civicshield.db"
_ENGINE = create_engine(f"sqlite:///{_DB_PATH}", connect_args={"check_same_thread": False})
_SessionLocal = sessionmaker(bind=_ENGINE, autoflush=False, autocommit=False)

Base = declarative_base()


class AnalysisSession(Base):
    __tablename__ = "analysis_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    input_hash = Column(String(64), nullable=False, index=True)
    input_type = Column(String(20), nullable=False)
    verdict = Column(String(30), nullable=False)
    risk_level = Column(String(10), nullable=False)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


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
