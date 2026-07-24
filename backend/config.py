"""
TrustField - Application Configuration
Pydantic Settings model loaded from environment variables / .env file.
"""

from functools import lru_cache
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Central configuration object.
    Values are loaded from environment variables or a .env file.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ─── Application ──────────────────────────────────────────────────────────
    APP_NAME: str = "TrustField"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"     # development | staging | production

    # ─── API ──────────────────────────────────────────────────────────────────
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_PREFIX: str = "/api/v1"
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
    ]

    # ─── Security / Auth ──────────────────────────────────────────────────────
    SECRET_KEY: str = "CHANGE_ME_IN_PRODUCTION_USE_256BIT_SECRET"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ─── PostgreSQL ───────────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql://trustfield:trustfield@localhost:5432/trustfield"

    # ─── Neo4j ────────────────────────────────────────────────────────────────
    NEO4J_URI: str = "neo4j://127.0.0.1:7687"
    NEO4J_USERNAME: str = "neo4j"
    NEO4J_PASSWORD: str = "trustfield"
    NEO4J_DATABASE: str = "neo4j"

    # ─── Redis / Celery ───────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    # ─── AWS ──────────────────────────────────────────────────────────────────
    AWS_REGION: str = "us-east-1"
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None
    AWS_ROLE_ARN: Optional[str] = None          # For cross-account collection
    AWS_CONTAINMENT_ROLE_ARN: Optional[str] = None      # Role assumed for containment actions (write access)
    # ─── Azure ────────────────────────────────────────────────────────────────
    AZURE_SUBSCRIPTION_ID: Optional[str] = None
    AZURE_TENANT_ID: Optional[str] = None
    AZURE_CLIENT_ID: Optional[str] = None
    AZURE_CLIENT_SECRET: Optional[str] = None

    # ─── GCP ──────────────────────────────────────────────────────────────────
    GCP_PROJECT_ID: Optional[str] = None
    GOOGLE_APPLICATION_CREDENTIALS: Optional[str] = None

    # ─── Kubernetes ───────────────────────────────────────────────────────────
    K8S_KUBECONFIG_PATH: Optional[str] = None
    K8S_CONTEXT: Optional[str] = None
    K8S_IN_CLUSTER: bool = False

    # ─── Notifications ────────────────────────────────────────────────────────
    SLACK_WEBHOOK_URL: Optional[str] = None
    GENERIC_WEBHOOK_URL: Optional[str] = None
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM: str = "trustfield@example.com"
    NOTIFICATION_EMAILS: List[str] = []

    # ─── ML ───────────────────────────────────────────────────────────────────
    ML_ANOMALY_THRESHOLD: float = 0.65
    ML_CONTAMINATION: float = 0.05
    GNN_ENABLED: bool = True

    # ─── Scan ─────────────────────────────────────────────────────────────────
    SCAN_INTERVAL_HOURS: int = 24       # Auto-scan frequency
    SCAN_MAX_CONCURRENT: int = 4        # Max parallel collector jobs


@lru_cache()
def get_settings() -> Settings:
    """Return a cached Settings singleton."""
    return Settings()


# Module-level settings instance for direct imports
settings = get_settings()