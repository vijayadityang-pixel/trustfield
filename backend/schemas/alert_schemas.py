"""
TrustField - Alert Schemas
Pydantic models for alert API request/response serialization.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict

from db.models import AlertSeverity, AlertStatus


# ─── Response ────────────────────────────────────────────────────────────────

class AlertResponse(BaseModel):
    """Full alert object returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: Optional[str] = None
    severity: AlertSeverity
    status: AlertStatus

    # Cloud context
    cloud_provider: Optional[str] = None
    account_id: Optional[str] = None
    region: Optional[str] = None
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None

    # Detection metadata
    alert_type: Optional[str] = None
    risk_score: float = 0.0
    confidence: float = 0.0
    detection_source: Optional[str] = None
    raw_evidence: Optional[dict] = None

    # Graph context
    source_node_id: Optional[str] = None
    target_node_id: Optional[str] = None
    escalation_path: Optional[list] = None

    # Analyst workflow
    analyst_notes: Optional[str] = None
    assigned_to: Optional[int] = None
    resolved_by: Optional[int] = None
    resolved_at: Optional[datetime] = None

    # Timestamps
    created_at: datetime
    updated_at: Optional[datetime] = None


# ─── Update (PATCH body) ─────────────────────────────────────────────────────

class AlertUpdate(BaseModel):
    """Fields that an analyst can update on an existing alert."""

    status: Optional[AlertStatus] = None
    analyst_notes: Optional[str] = None
    assigned_to: Optional[int] = None


# ─── Filter (query-param grouping — used internally, not as a request body) ──

class AlertFilter(BaseModel):
    """Optional filters passed to the list endpoint."""

    severity: Optional[AlertSeverity] = None
    status: Optional[AlertStatus] = None
    cloud_provider: Optional[str] = None
    skip: int = 0
    limit: int = 50


# ─── Summary ─────────────────────────────────────────────────────────────────

class AlertSummary(BaseModel):
    """Dashboard-level alert counts returned by GET /alerts/summary."""

    total: int
    critical: int
    high: int
    medium: int
    low: int
    open: int
    resolved: int
    last_24h: int