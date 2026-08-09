"""
TrustField - Scan Routes
Triggers IAM collection scans across cloud providers.
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
import asyncio
import logging
import uuid
import os
from detection.path_finder import PrivilegeEscalationPathFinder
from detection.alert_generator import AlertGenerator
from db.database import get_db, SessionLocal
from db.models import ScanJob, ScanStatus, User, UserRole
from auth.dependencies import get_current_user, require_role
from collectors.aws_collector import AWSCollector
from collectors.azure_collector import AzureCollector
from collectors.gcp_collector import GCPCollector
from collectors.k8s_collector import K8sCollector
from graph.graph_builder import TrustGraphBuilder
from graph.neo4j_singleton import neo4j_client
from schemas.scan_schemas import (
    ScanRequest,
    ScanJobResponse,
    ScanJobDetail,
    ScanResultSummary,
)
from config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scan", tags=["Scans"])


graph_builder = TrustGraphBuilder(neo4j_client)
path_finder = PrivilegeEscalationPathFinder(neo4j_client)
alert_generator = AlertGenerator()
COLLECTOR_MAP = {
    "aws": AWSCollector,
    "azure": AzureCollector,
    "gcp": GCPCollector,
    "k8s": K8sCollector,
}


async def _run_scan(scan_job_id: str, providers: List[str]):
    """
    Background task: runs IAM collection for each provider,
    builds the trust graph, and updates the scan job record.
    Uses its own DB session since the request-scoped session
    is closed by the time this background task executes.
    """
    db = SessionLocal()
    try:
        scan_job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if not scan_job:
            logger.error(f"[Scan {scan_job_id}] Job not found in fresh session")
            return

        scan_job.status = ScanStatus.RUNNING
        scan_job.started_at = datetime.utcnow()
        db.commit()

        all_data = {}
        for provider in providers:
            collector_cls = COLLECTOR_MAP.get(provider)
            if not collector_cls:
                logger.warning(f"Unknown provider: {provider}, skipping")
                continue

            logger.info(f"[Scan {scan_job_id}] Collecting from {provider.upper()}")
            if provider == "aws":
                collector = collector_cls(
                    region=settings.AWS_REGION,
                    access_key_id=settings.AWS_ACCESS_KEY_ID,
                    secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                )
            elif provider == "azure":
                collector = collector_cls(
                    subscription_id=settings.AZURE_SUBSCRIPTION_ID,
                    tenant_id=settings.AZURE_TENANT_ID,
                    client_id=settings.AZURE_CLIENT_ID,
                    client_secret=settings.AZURE_CLIENT_SECRET,
                )
            elif provider == "gcp":
                if settings.GOOGLE_APPLICATION_CREDENTIALS:
                    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = settings.GOOGLE_APPLICATION_CREDENTIALS
                collector = collector_cls(project_id=settings.GCP_PROJECT_ID)
            elif provider == "k8s":
                collector = collector_cls(
                    kubeconfig_path=settings.K8S_KUBECONFIG_PATH,
                    context=settings.K8S_CONTEXT,
                    in_cluster=settings.K8S_IN_CLUSTER,
                )
            else:
                collector = collector_cls()

            provider_data = await collector.collect()
            all_data[provider] = provider_data

        logger.info(f"[Scan {scan_job_id}] Building trust graph")
        graph_stats = await graph_builder.ingest_collected_data(all_data)

        logger.info(f"[Scan {scan_job_id}] Running detection and generating alerts")
        total_new_alerts = 0
        for provider in providers:
            try:
                paths = await path_finder.find_escalation_paths(cloud_provider=provider, limit=100)
                total_new_alerts += alert_generator.generate_alerts(db, paths)
            except Exception as detect_exc:
                logger.error(f"[Scan {scan_job_id}] Detection failed for {provider}: {detect_exc}", exc_info=True)

        scan_job.status = ScanStatus.COMPLETED
        scan_job.completed_at = datetime.utcnow()
        scan_job.nodes_discovered = graph_stats.get("nodes", 0)
        scan_job.edges_discovered = graph_stats.get("edges", 0)
        scan_job.providers_scanned = providers
        scan_job.alerts_generated = total_new_alerts
        db.commit()
        logger.info(f"[Scan {scan_job_id}] Completed successfully: {graph_stats}")

    except Exception as exc:
        db.rollback()
        scan_job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if scan_job:
            scan_job.status = ScanStatus.FAILED
            scan_job.error_message = str(exc)
            scan_job.completed_at = datetime.utcnow()
            db.commit()
        logger.error(f"[Scan {scan_job_id}] Failed: {exc}", exc_info=True)

    finally:
        db.close()


@router.post("/", response_model=ScanJobResponse, status_code=202)
async def trigger_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Trigger a new cloud IAM scan.
    Specify one or more cloud providers to scan (defaults to all).
    The scan runs asynchronously — poll /scan/{job_id} for status.
    """
    providers = request.providers or list(COLLECTOR_MAP.keys())

    # Validate providers
    invalid = [p for p in providers if p not in COLLECTOR_MAP]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid providers: {invalid}. Supported: {list(COLLECTOR_MAP.keys())}",
        )

    scan_job = ScanJob(
        id=str(uuid.uuid4()),
        initiated_by=current_user.id,
        status=ScanStatus.PENDING,
        providers_requested=providers,
        created_at=datetime.utcnow(),
    )
    db.add(scan_job)
    db.commit()
    db.refresh(scan_job)

    background_tasks.add_task(_run_scan, scan_job.id, providers)
    logger.info(f"Scan job {scan_job.id} queued by user {current_user.id} for {providers}")

    return ScanJobResponse(
        job_id=scan_job.id,
        status=scan_job.status,
        providers=providers,
        message="Scan started. Poll /scan/{job_id} for status.",
    )


@router.get("/", response_model=List[ScanJobDetail])
async def list_scan_jobs(
    status: Optional[ScanStatus] = None,
    skip: int = 0,
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all scan jobs, optionally filtered by status."""
    query = db.query(ScanJob)
    if status:
        query = query.filter(ScanJob.status == status)
    jobs = query.order_by(ScanJob.created_at.desc()).offset(skip).limit(limit).all()
    return jobs


@router.get("/latest", response_model=ScanJobDetail)
async def get_latest_scan(
    cloud_provider: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the most recently completed scan job."""
    query = db.query(ScanJob).filter(ScanJob.status == ScanStatus.COMPLETED)
    job = query.order_by(ScanJob.completed_at.desc()).first()
    if not job:
        raise HTTPException(status_code=404, detail="No completed scans found")
    return job


@router.get("/{job_id}", response_model=ScanJobDetail)
async def get_scan_job(
    job_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get full details and status of a specific scan job."""
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


@router.delete("/{job_id}", status_code=204)
async def cancel_scan(
    job_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """Cancel a pending or running scan job (admin only)."""
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel job in {job.status} state",
        )
    job.status = ScanStatus.CANCELLED
    job.completed_at = datetime.utcnow()
    db.commit()
    logger.info(f"Scan job {job_id} cancelled by user {current_user.id}")


@router.get("/{job_id}/results", response_model=ScanResultSummary)
async def get_scan_results(
    job_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get the results summary of a completed scan including:
    - Node/edge counts per provider
    - New alerts generated
    - Risk score distribution
    """
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.status != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail=f"Scan job is not completed (status: {job.status})",
        )
    return ScanResultSummary(
        job_id=job.id,
        nodes_discovered=job.nodes_discovered,
        edges_discovered=job.edges_discovered,
        providers_scanned=job.providers_scanned,
        duration_seconds=(job.completed_at - job.started_at).total_seconds(),
        completed_at=job.completed_at,
        alerts_generated=job.alerts_generated
    )