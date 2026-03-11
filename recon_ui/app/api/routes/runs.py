from __future__ import annotations

"""Run/job/home/history endpoints."""

import json

from fastapi import APIRouter, Form, HTTPException, Path, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlmodel import col, select

from ...config import ACTIVE_ENRICHMENT_ENABLED
from ...db import EventLog, Job, OutOfScopeBlocked, ScopePolicy, Stage, Task, get_session
from ...orchestrator import generate_job_id, generate_scope_id
from ...scope import canonicalize_hostname
from ...services.report_service import resolve_report_path
from ...web.deps import orchestrator, templates, utcnow_iso

router = APIRouter()

JOB_ID_PATTERN = r"^job_[0-9a-f]{12}$"


@router.get("/", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    """Render the start page with recent job list."""
    with get_session() as session:
        jobs = session.exec(select(Job).order_by(col(Job.created_at).desc()).limit(3)).all()
    return templates.TemplateResponse(
        "start_run.html",
        {"request": request, "jobs": jobs, "active_enrichment_available": ACTIVE_ENRICHMENT_ENABLED},
    )


@router.post("/runs", response_class=HTMLResponse)
def create_run(
    request: Request,
    root_domain: str = Form(..., min_length=1, max_length=253),
    enable_active_enrichment: str | None = Form(default=None),
) -> HTMLResponse:
    """Create scope+job records, emit initial event, and launch async run."""
    try:
        root = canonicalize_hostname(root_domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid root domain: {exc}") from exc
    if "." not in root:
        raise HTTPException(status_code=400, detail="Root domain must include a public suffix")

    # Active enrichment remains opt-in per run even when the feature is globally available.
    active_requested = ACTIVE_ENRICHMENT_ENABLED and enable_active_enrichment == "on"
    scope_id = generate_scope_id()
    job_id = generate_job_id()

    # Seed the scope with an allow-first policy anchored on the operator-provided root domain.
    scope = ScopePolicy(
        scope_id=scope_id,
        root_domain=root,
        allow_exact=json.dumps([root]),
        allow_suffixes=json.dumps([root]),
        deny_exact=json.dumps([]),
        deny_suffixes=json.dumps([]),
        regex_deny=json.dumps([]),
    )
    job = Job(
        job_id=job_id,
        scope_id=scope_id,
        status="CREATED",
        mode=("APPROVAL_GATED_ACTIVE" if active_requested else "PASSIVE_ONLY"),
        approval_level=("HUMAN_REQUIRED" if active_requested else "NONE"),
        current_stage="SEED",
    )

    with get_session() as session:
        session.add(scope)
        session.add(job)
        session.commit()

    # Emit one durable creation event before the asynchronous worker thread takes over.
    creation_mode = "APPROVAL_GATED_ACTIVE" if active_requested else "PASSIVE_ONLY"
    orchestrator.log_event(
        job_id,
        scope_id,
        "JOB_CREATED",
        f"Job created in {creation_mode} mode",
        details={
            "root_domain": root,
            "active_enrichment_available": ACTIVE_ENRICHMENT_ENABLED,
            "active_enrichment_approved": active_requested,
        },
    )
    # Start orchestration only after the initial records and creation event are durable.
    orchestrator.start_job_async(job_id)

    with get_session() as session:
        jobs = session.exec(select(Job).order_by(col(Job.created_at).desc()).limit(3)).all()

    return templates.TemplateResponse(
        "start_run.html",
        {
            "request": request,
            "jobs": jobs,
            "active_enrichment_available": ACTIVE_ENRICHMENT_ENABLED,
            "message": f"Run {job_id} started at {utcnow_iso()}",
            "redirect_job_id": job_id,
        },
    )


@router.get("/jobs/{job_id}", response_class=HTMLResponse)
def view_job(request: Request, job_id: str = Path(..., pattern=JOB_ID_PATTERN)) -> HTMLResponse:
    """Render job detail view with stages, tasks, and recent timeline events."""
    with get_session() as session:
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        stages = session.exec(select(Stage).where(Stage.job_id == job_id).order_by(col(Stage.order_idx))).all()
        tasks = session.exec(select(Task).where(Task.job_id == job_id).order_by(col(Task.created_at))).all()
        events = session.exec(
            select(EventLog).where(EventLog.job_id == job_id).order_by(col(EventLog.timestamp).desc()).limit(50)
        ).all()
        blocked_items = session.exec(
            select(OutOfScopeBlocked)
            .where(OutOfScopeBlocked.job_id == job_id)
            .order_by(col(OutOfScopeBlocked.created_at).desc())
            .limit(200)
        ).all()
    report_exists = resolve_report_path(job_id).exists()

    return templates.TemplateResponse(
        "job_view.html",
        {
            "request": request,
            "job": job,
            "stages": stages,
            "tasks": tasks,
            "events": events,
            "blocked_items": blocked_items,
            "blocked_details_available": bool(blocked_items),
            "report_exists": report_exists,
        },
    )


@router.get("/history", response_class=HTMLResponse)
def history(request: Request) -> HTMLResponse:
    """Render job history table."""
    with get_session() as session:
        jobs = session.exec(select(Job).order_by(col(Job.created_at).desc())).all()
    return templates.TemplateResponse("history.html", {"request": request, "jobs": jobs})


@router.get("/api/jobs/{job_id}")
def get_job(job_id: str = Path(..., pattern=JOB_ID_PATTERN)) -> JSONResponse:
    """Return current job status and metrics for live refresh in UI."""
    with get_session() as session:
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

    payload = {
        "job_id": job.job_id,
        "scope_id": job.scope_id,
        "status": job.status,
        "current_stage": job.current_stage,
        "metrics": {
            "entities_total": job.entities_total,
            "evidence_total": job.evidence_total,
            "assertions_total": job.assertions_total,
            "policy_denials": job.policy_denials,
            "out_of_scope_blocked": job.out_of_scope_blocked,
        },
        "updated_at": job.updated_at.isoformat(),
    }
    return JSONResponse(payload)


@router.get("/api/jobs/{job_id}/snapshot")
def get_job_snapshot(job_id: str = Path(..., pattern=JOB_ID_PATTERN)) -> JSONResponse:
    """Return full job snapshot for real-time UI refresh (job/stages/tasks/events)."""
    with get_session() as session:
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        stages = session.exec(select(Stage).where(Stage.job_id == job_id).order_by(Stage.order_idx)).all()
        tasks = session.exec(select(Task).where(Task.job_id == job_id).order_by(Task.created_at)).all()
        events = session.exec(
            select(EventLog).where(EventLog.job_id == job_id).order_by(EventLog.timestamp.desc()).limit(50)
        ).all()
        blocked_items = session.exec(
            select(OutOfScopeBlocked)
            .where(OutOfScopeBlocked.job_id == job_id)
            .order_by(OutOfScopeBlocked.created_at.desc())
            .limit(200)
        ).all()

    # Keep the payload intentionally denormalized so the browser can refresh from one request.
    payload = {
        "job": {
            "job_id": job.job_id,
            "scope_id": job.scope_id,
            "status": job.status,
            "current_stage": job.current_stage,
            "entities_total": job.entities_total,
            "evidence_total": job.evidence_total,
            "assertions_total": job.assertions_total,
            "policy_denials": job.policy_denials,
            "out_of_scope_blocked": job.out_of_scope_blocked,
            "updated_at": job.updated_at.isoformat(),
        },
        "stages": [
            {
                "stage_id": s.stage_id,
                "name": s.name,
                "status": s.status,
                "tier": s.tier,
                "started_at": s.started_at.isoformat(),
                "ended_at": s.ended_at.isoformat() if s.ended_at else None,
            }
            for s in stages
        ],
        "tasks": [
            {
                "task_id": t.task_id,
                "task_type": t.task_type,
                "status": t.status,
                "tier": t.tier,
                "planner_source": t.planner_source,
                "created_at": t.created_at.isoformat(),
            }
            for t in tasks
        ],
        "events": [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "severity": e.severity,
                "event_type": e.event_type,
                "message": e.message,
            }
            for e in events
        ],
        "blocked_items": [
            {
                "block_id": b.block_id,
                "hostname": b.hostname,
                "reason": b.reason,
                "source": b.source,
                "task_id": b.task_id,
                "created_at": b.created_at.isoformat(),
            }
            for b in blocked_items
        ],
        "blocked_details_available": bool(blocked_items),
    }
    return JSONResponse(payload)
