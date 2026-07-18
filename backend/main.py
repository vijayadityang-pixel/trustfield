"""
TrustField - FastAPI Application Entry Point
Bootstraps the API server, registers routes, and initializes services.
"""

import logging
import sys
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from config import settings
from db.database import init_db
from graph.neo4j_client import Neo4jClient
from api.routes_alerts import router as alerts_router
from api.routes_containment import router as containment_router
from api.routes_graph import router as graph_router
from api.routes_scan import router as scan_router
from api.routes_auth import router as auth_router
from api.routes_ml import router as ml_router
# ─── Logging Setup ────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


# ─── Lifespan ─────────────────────────────────────────────────────────────────

neo4j_client = Neo4jClient()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Async context manager for application startup and shutdown.
    Initializes DB tables, Neo4j indexes, and other services.
    """
    # ── Startup ──────────────────────────────────────────────────────────────
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"Environment: {settings.ENVIRONMENT}")

    # Initialize PostgreSQL tables
    try:
        init_db()
        logger.info("PostgreSQL database initialized")
    except Exception as exc:
        logger.error(f"Database initialization failed: {exc}")

    # Connect to Neo4j and apply indexes
    try:
        await neo4j_client.connect()
        await neo4j_client.apply_indexes()
        logger.info("Neo4j graph database ready")
    except Exception as exc:
        logger.warning(f"Neo4j initialization failed (non-fatal): {exc}")

    logger.info(f"API listening on {settings.API_HOST}:{settings.API_PORT}")
    yield

    # ── Shutdown ─────────────────────────────────────────────────────────────
    logger.info("Shutting down TrustField...")
    await neo4j_client.close()
    logger.info("Shutdown complete")


# ─── Application ──────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "TrustField — Cloud IAM Trust Graph Analysis Platform. "
        "Detects privilege escalation paths, anomalous identities, "
        "and automates incident response across AWS, Azure, GCP, and Kubernetes."
    ),
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# ─── Middleware ────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)


# ─── Exception Handlers ───────────────────────────────────────────────────────

def _sanitize_for_json(obj):
    """Recursively convert non-JSON-serializable values (e.g. bytes) to strings."""
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _sanitize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize_for_json(v) for v in obj]
    return obj


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """Return structured validation errors."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "detail": _sanitize_for_json(exc.errors()),
            "body": str(exc.body) if exc.body else None,
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Catch-all for unhandled exceptions — log and return 500."""
    logger.error(f"Unhandled exception on {request.method} {request.url}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "detail": str(exc) if settings.DEBUG else "An unexpected error occurred",
        },
    )


# ─── Routes ───────────────────────────────────────────────────────────────────

PREFIX = settings.API_PREFIX

app.include_router(alerts_router,      prefix=PREFIX)
app.include_router(containment_router, prefix=PREFIX)
app.include_router(graph_router,       prefix=PREFIX)
app.include_router(scan_router,        prefix=PREFIX)
app.include_router(auth_router,        prefix=PREFIX)
app.include_router(ml_router,          prefix=PREFIX)

# ─── Health & Info Endpoints ──────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
async def health_check():
    """Liveness probe — returns 200 if the API is running."""
    return {"status": "healthy", "service": settings.APP_NAME, "version": settings.APP_VERSION}


@app.get("/health/ready", tags=["Health"])
async def readiness_check():
    """
    Readiness probe — checks that all downstream services are reachable.
    Returns 503 if any critical dependency is unavailable.
    """
    checks = {}
    overall = "ready"

    # Check PostgreSQL
    try:
        from sqlalchemy import text
        from db.database import SessionLocal
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        checks["postgresql"] = "ok"
    except Exception as exc:
        checks["postgresql"] = f"error: {exc}"
        overall = "degraded"

    # Check Neo4j
    try:
        stats = await neo4j_client.get_graph_statistics()
        checks["neo4j"] = f"ok (nodes={stats.get('node_count', 0)})"
    except Exception as exc:
        checks["neo4j"] = f"error: {exc}"
        overall = "degraded"

    http_status = 200 if overall == "ready" else 503
    return JSONResponse(
        status_code=http_status,
        content={
            "status": overall,
            "checks": checks,
            "version": settings.APP_VERSION,
        },
    )


@app.get("/", tags=["Root"])
async def root():
    """API root — returns basic info and link to docs."""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "description": "Cloud IAM Trust Graph Analysis Platform",
        "docs": "/docs",
        "health": "/health",
    }


# ─── Entrypoint ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG,
        log_level="debug" if settings.DEBUG else "info",
        workers=1 if settings.DEBUG else 4,
    )