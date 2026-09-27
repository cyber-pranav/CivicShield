"""
CivicShield — FastAPI Application Entry Point

Starts the CivicShield backend API.
CORS is configured to allow the local Vite frontend (localhost:5173).

Run with:
  uvicorn backend.main:app --reload --port 8000
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from backend.limiter import limiter

from backend.routers.analyze import router as analyze_router
from backend.routers.admin import router as admin_router
from backend.db.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise the SQLite database on startup."""
    init_db()
    yield


app = FastAPI(
    title="CivicShield API",
    description=(
        "Evidence-based analysis of suspicious Indian government communications and notices, "
        "specialising in e-Challan / RTO fraud detection. "
        "CivicShield provides an evidence-based assessment and does not certify the authenticity "
        "of a government communication."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# Setup slowapi rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS — allow Vite dev server, production build, and environment overrides
allowed_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
allowed_origins_env = os.getenv("ALLOWED_ORIGINS", "")
if allowed_origins_env:
    for origin in allowed_origins_env.split(","):
        origin_clean = origin.strip()
        if origin_clean and origin_clean not in allowed_origins:
            allowed_origins.append(origin_clean)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Include routers
app.include_router(analyze_router, prefix="/api")
app.include_router(admin_router, prefix="/api/admin", tags=["admin"])
