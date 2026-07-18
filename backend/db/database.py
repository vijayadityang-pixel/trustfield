"""
TrustField - Database Configuration
SQLAlchemy session and engine setup for PostgreSQL.
"""

from sqlalchemy import create_engine, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool
import logging

from config import settings

logger = logging.getLogger(__name__)

# ─── Engine ──────────────────────────────────────────────────────────────────

engine = create_engine(
    settings.DATABASE_URL,
    poolclass=QueuePool,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,          # Detect stale connections
    pool_recycle=3600,           # Recycle connections every hour
    echo=settings.DEBUG,         # Log SQL in debug mode
    connect_args=(
        {"options": "-c timezone=UTC"}
        if "postgresql" in settings.DATABASE_URL
        else {}
    ),
)

# ─── Session Factory ──────────────────────────────────────────────────────────

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

# ─── Base Model ───────────────────────────────────────────────────────────────

Base = declarative_base()


# ─── Dependency ───────────────────────────────────────────────────────────────

def get_db():
    """
    FastAPI dependency that yields a SQLAlchemy session.
    Ensures the session is closed after each request.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    """
    Create all database tables on startup.
    Called once from main.py at application start.
    """
    import db.models  # noqa: F401 — ensure models are registered with Base
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables initialized")


def drop_all_tables() -> None:
    """
    Drop all tables — used in testing only.
    Never call this in production.
    """
    Base.metadata.drop_all(bind=engine)
    logger.warning("All database tables dropped")