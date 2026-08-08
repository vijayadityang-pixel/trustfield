"""
TrustField - Scan Schemas
Pydantic models for scan job API request/response serialization.
"""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

from db.models import ScanStatus


# ─── Request ─────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """Body for POST /scan/ — all fields optional."""

    model_config = ConfigDict(extra="forbid")

    providers: Optional[List[str]] = None   # ["aws", "azure", "gcp", "k8s"] or subset
    reason: Optional[str] = None            # Free-text reason for the scan

# ─── Response (lightweight — returned immediately on trigger) ─────────────────

class ScanJobResponse(BaseModel):
    """Immediate response after queuing a scan job."""

    job_id: str
    status: ScanStatus
    providers: List[str]
    message: str


# ─── Detail (full record — returned by GET /scan/{job_id}) ───────────────────

class ScanJobDetail(BaseModel):
    """Full scan job record including progress and results."""

    model_config = ConfigDict(from_attributes=True)

    job_id: str = Field(validation_alias="id")
    status: ScanStatus

    providers_requested: Optional[List[str]] = None
    providers_scanned: Optional[List[str]] = None

    nodes_discovered: int = 0
    edges_discovered: int = 0
    alerts_generated: int = 0
    error_message: Optional[str] = None

    initiated_by: int

    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


# ─── Result summary ───────────────────────────────────────────────────────────

class ScanResultSummary(BaseModel):
    """Summary of a completed scan returned by GET /scan/{job_id}/results."""

    job_id: str
    nodes_discovered: int = 0
    edges_discovered: int = 0
    providers_scanned: Optional[List[str]] = None
    duration_seconds: Optional[float] = None
    completed_at: Optional[datetime] = None
    alerts_generated: int
    