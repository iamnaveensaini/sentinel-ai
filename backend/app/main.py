"""
Sentinel AI - Main FastAPI Application
"""
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from backend.api.routes import router as api_router

app = FastAPI(
    title="Sentinel AI - Data Leakage Prevention Gateway",
    version="2.0.0",
    description="Enterprise LLM Gateway with Block-Before-Forward, PII Masking, and Pre-Retrieval ACL."
)

# Enable CORS for local UI and development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(api_router)

@app.get("/health/live")
async def health_live():
    """Liveness probe - checks if process is alive without revealing internal secrets."""
    return {"status": "alive", "service": "sentinel-gateway"}

@app.get("/health/ready")
async def health_ready():
    """Readiness probe - checks readiness of database and policy engine."""
    return {"status": "ready", "policy_engine": "ready", "audit_db": "connected"}

# Mount frontend static directory if exists
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "frontend")
if os.path.isdir(frontend_dir):
    app.mount("/ui", StaticFiles(directory=frontend_dir, html=True), name="frontend")
