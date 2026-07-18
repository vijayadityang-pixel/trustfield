"""
TrustField - Alert Routes
Handles CRUD operations and management for security alerts.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
import logging

from db.database import get_db
from db.models import Alert, AlertStatus, AlertSeverity, User
from auth.dependencies import get_current_user
from schemas.alert_schemas import (
    AlertResponse,
    AlertUpdate,
    AlertFilter,
    AlertSummary,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("/", response_model=List[AlertResponse])
async def list_alerts(
    severity: Optional[AlertSeverity] = Query(None, description="Filter by severity"),
    status: Optional[AlertStatus] = Query(None, description="Filter by status"),
    cloud_provider: Optional[str] = Query(None, description="Filter by cloud provider"),
    start_date: Optional[datetime] = Query(None, description="Filter alerts from this date"),
    end_date: Optional[datetime] = Query(None, description="Filter alerts until this date"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List all alerts with optional filtering.
    Supports filtering by severity, status, cloud provider, and date range.
    """
    query = db.query(Alert)

    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if cloud_provider:
        query = query.filter(Alert.cloud_provider == cloud_provider)
    if start_date:
        query = query.filter(Alert.created_at >= start_date)
    if end_date:
        query = query.filter(Alert.created_at <= end_date)

    alerts = query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()
    return alerts


@router.get("/summary", response_model=AlertSummary)
async def get_alert_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns a dashboard-level summary of alerts:
    - Counts by severity
    - Counts by status
    - Recent 24h activity
    """
    now = datetime.utcnow()
    yesterday = now - timedelta(hours=24)

    total = db.query(Alert).count()
    critical = db.query(Alert).filter(Alert.severity == AlertSeverity.CRITICAL).count()
    high = db.query(Alert).filter(Alert.severity == AlertSeverity.HIGH).count()
    medium = db.query(Alert).filter(Alert.severity == AlertSeverity.MEDIUM).count()
    low = db.query(Alert).filter(Alert.severity == AlertSeverity.LOW).count()
    open_count = db.query(Alert).filter(Alert.status == AlertStatus.OPEN).count()
    resolved_count = db.query(Alert).filter(Alert.status == AlertStatus.RESOLVED).count()
    recent = db.query(Alert).filter(Alert.created_at >= yesterday).count()

    return AlertSummary(
        total=total,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        open=open_count,
        resolved=resolved_count,
        last_24h=recent,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve a single alert by ID."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: int,
    update_data: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Update alert status or add analyst notes.
    Allows transitioning between OPEN → IN_PROGRESS → RESOLVED states.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    if update_data.status:
        alert.status = update_data.status
        if update_data.status == AlertStatus.RESOLVED:
            alert.resolved_at = datetime.utcnow()
            alert.resolved_by = current_user.id
    if update_data.analyst_notes:
        alert.analyst_notes = update_data.analyst_notes
    if update_data.assigned_to:
        alert.assigned_to = update_data.assigned_to

    alert.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)
    logger.info(f"Alert {alert_id} updated by user {current_user.id}")
    return alert


@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Soft-delete an alert (marks as DISMISSED).
    Only admins can permanently delete alerts.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    if current_user.role == "admin":
        db.delete(alert)
    else:
        alert.status = AlertStatus.DISMISSED
        alert.updated_at = datetime.utcnow()

    db.commit()
    logger.info(f"Alert {alert_id} dismissed by user {current_user.id}")


@router.post("/{alert_id}/escalate", response_model=AlertResponse)
async def escalate_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Escalate alert severity to the next level.
    LOW → MEDIUM → HIGH → CRITICAL
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    escalation_map = {
        AlertSeverity.LOW: AlertSeverity.MEDIUM,
        AlertSeverity.MEDIUM: AlertSeverity.HIGH,
        AlertSeverity.HIGH: AlertSeverity.CRITICAL,
        AlertSeverity.CRITICAL: AlertSeverity.CRITICAL,
    }

    old_severity = alert.severity
    alert.severity = escalation_map[alert.severity]
    alert.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)

    logger.warning(
        f"Alert {alert_id} escalated from {old_severity} to {alert.severity} "
        f"by user {current_user.id}"
    )
    return alert