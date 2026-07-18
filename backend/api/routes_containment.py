"""
TrustField - Containment Routes
Triggers and manages automated containment actions across cloud providers.
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
import logging

from db.database import get_db
from db.models import ContainmentAction, ContainmentStatus, Alert, User
from auth.dependencies import get_current_user, require_role
from containment.aws_response import AWSContainmentEngine
from containment.azure_response import AzureContainmentEngine
from containment.playbooks import PlaybookEngine
from containment.notifier import AlertNotifier
from schemas.containment_schemas import (
    ContainmentRequest,
    ContainmentResponse,
    ContainmentActionDetail,
    PlaybookListResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/containment", tags=["Containment"])

# Engine singletons (injected via DI in production)
aws_engine = AWSContainmentEngine()
azure_engine = AzureContainmentEngine()
playbook_engine = PlaybookEngine()
notifier = AlertNotifier()


async def _execute_containment(
    action: ContainmentAction,
    request: ContainmentRequest,
    db: Session,
):
    """
    Background task: executes the containment action and updates its status.
    Dispatches to the appropriate cloud engine based on provider.
    """
    try:
        action.status = ContainmentStatus.IN_PROGRESS
        action.started_at = datetime.utcnow()
        db.commit()

        provider = request.cloud_provider.lower()
        if provider == "aws":
            result = await aws_engine.execute(request.action_type, request.target_resource)
        elif provider == "azure":
            result = await azure_engine.execute(request.action_type, request.target_resource)
        else:
            raise ValueError(f"Unsupported cloud provider: {provider}")

        action.status = ContainmentStatus.COMPLETED
        action.result = result
        action.completed_at = datetime.utcnow()
        logger.info(f"Containment action {action.id} completed successfully")

    except Exception as exc:
        action.status = ContainmentStatus.FAILED
        action.error_message = str(exc)
        action.completed_at = datetime.utcnow()
        logger.error(f"Containment action {action.id} failed: {exc}")

    finally:
        db.commit()
        await notifier.send_containment_notification(action)


@router.post("/trigger", response_model=ContainmentResponse, status_code=status.HTTP_202_ACCEPTED)
async def trigger_containment(
    request: ContainmentRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["analyst", "admin"])),
):
    """
    Trigger a containment action against a specific cloud resource.
    Executes asynchronously in the background.

    Supported action types:
    - REVOKE_CREDENTIALS
    - DISABLE_ACCOUNT
    - ISOLATE_RESOURCE
    - BLOCK_IP
    - ROTATE_KEYS
    """
    # Validate the alert exists if provided
    if request.alert_id:
        alert = db.query(Alert).filter(Alert.id == request.alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Referenced alert not found")

    action = ContainmentAction(
        alert_id=request.alert_id,
        action_type=request.action_type,
        cloud_provider=request.cloud_provider,
        target_resource=request.target_resource,
        initiated_by=current_user.id,
        status=ContainmentStatus.PENDING,
        created_at=datetime.utcnow(),
    )
    db.add(action)
    db.commit()
    db.refresh(action)

    background_tasks.add_task(_execute_containment, action, request, db)
    logger.info(
        f"Containment action {action.id} queued by user {current_user.id} "
        f"against {request.target_resource}"
    )
    return ContainmentResponse(
        action_id=action.id,
        status=action.status,
        message="Containment action queued for execution",
    )


@router.get("/actions", response_model=List[ContainmentActionDetail])
async def list_containment_actions(
    alert_id: Optional[int] = None,
    cloud_provider: Optional[str] = None,
    action_status: Optional[ContainmentStatus] = None,
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all containment actions with optional filters."""
    query = db.query(ContainmentAction)
    if alert_id:
        query = query.filter(ContainmentAction.alert_id == alert_id)
    if cloud_provider:
        query = query.filter(ContainmentAction.cloud_provider == cloud_provider)
    if action_status:
        query = query.filter(ContainmentAction.status == action_status)

    actions = query.order_by(ContainmentAction.created_at.desc()).offset(skip).limit(limit).all()
    return actions


@router.get("/actions/{action_id}", response_model=ContainmentActionDetail)
async def get_containment_action(
    action_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get details of a specific containment action including execution result."""
    action = db.query(ContainmentAction).filter(ContainmentAction.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail="Containment action not found")
    return action


@router.post("/actions/{action_id}/rollback", response_model=ContainmentResponse)
async def rollback_containment(
    action_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin"])),
):
    """
    Rollback a completed containment action (admin only).
    Creates a reverse action to undo the original containment.
    """
    original = db.query(ContainmentAction).filter(ContainmentAction.id == action_id).first()
    if not original:
        raise HTTPException(status_code=404, detail="Containment action not found")
    if original.status != ContainmentStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot rollback action in {original.status} state",
        )

    rollback_action = ContainmentAction(
        alert_id=original.alert_id,
        action_type=f"ROLLBACK_{original.action_type}",
        cloud_provider=original.cloud_provider,
        target_resource=original.target_resource,
        initiated_by=current_user.id,
        status=ContainmentStatus.PENDING,
        parent_action_id=original.id,
        created_at=datetime.utcnow(),
    )
    db.add(rollback_action)
    db.commit()
    db.refresh(rollback_action)

    rollback_request = ContainmentRequest(
        action_type=rollback_action.action_type,
        cloud_provider=original.cloud_provider,
        target_resource=original.target_resource,
    )
    background_tasks.add_task(_execute_containment, rollback_action, rollback_request, db)

    return ContainmentResponse(
        action_id=rollback_action.id,
        status=rollback_action.status,
        message="Rollback action queued",
    )


@router.get("/playbooks", response_model=List[PlaybookListResponse])
async def list_playbooks(
    current_user: User = Depends(get_current_user),
):
    """List all available incident response playbooks."""
    playbooks = playbook_engine.list_playbooks()
    return playbooks


@router.post("/playbooks/{playbook_id}/run", response_model=ContainmentResponse)
async def run_playbook(
    playbook_id: str,
    alert_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["analyst", "admin"])),
):
    """
    Execute a predefined incident response playbook against an alert.
    Playbooks chain multiple containment actions in sequence.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    playbook = playbook_engine.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' not found")

    action = ContainmentAction(
        alert_id=alert_id,
        action_type=f"PLAYBOOK:{playbook_id}",
        cloud_provider=alert.cloud_provider,
        target_resource=alert.resource_id,
        initiated_by=current_user.id,
        status=ContainmentStatus.PENDING,
        created_at=datetime.utcnow(),
    )
    db.add(action)
    db.commit()
    db.refresh(action)

    background_tasks.add_task(playbook_engine.execute_playbook, playbook_id, alert, action, db)

    return ContainmentResponse(
        action_id=action.id,
        status=action.status,
        message=f"Playbook '{playbook_id}' started",
    )