"""
CivicShield — FastAPI Application Entry Point

Starts the CivicShield backend API.
CORS is configured to allow the local Vite frontend (localhost:5173).

Run with:
  uvicorn backend.main:app --reload --port 8000
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.routers.analyze import router as analyze_router
from backend.db.database import init_db

app = FastAPI(
    title="CivicShield API",
    description=(
        "Evidence-based analysis of suspicious Indian government e-Challan/RTO communications. "
        "CivicShield provides an evidence-based assessment and does not certify the authenticity "
        "of a government communication."
    ),
    version="0.1.0",
)

import os

# CORS — allow Vite dev server, production build, and environment overrides
allowed_origins_env = os.getenv("ALLOWED_ORIGINS", "")
allowed_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
]
if allowed_origins_env:
    allowed_origins.extend([origin.strip() for origin in allowed_origins_env.split(",") if origin.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if allowed_origins_env else ["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    """Initialise the SQLite database on startup."""
    init_db()


# Include routers
app.include_router(analyze_router, prefix="/api")
