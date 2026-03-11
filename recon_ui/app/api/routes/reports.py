from __future__ import annotations

"""Report view, generation, enrichment, and download endpoints."""

from fastapi import APIRouter, HTTPException, Path, Request
from fastapi.responses import HTMLResponse, Response
from sqlmodel import select

from ...config import REPORTS_DIR, get_report_llm_model
from ...db import Job, get_session
from ...services.report_service import (
    build_report_markdown,
    enrich_report_with_ai,
    report_file_path,
    report_meta,
    resolve_report_path,
)
from ...web.deps import orchestrator, templates

router = APIRouter()

JOB_ID_PATTERN = r"^job_[0-9a-f]{12}$"


@router.get("/jobs/{job_id}/report", response_class=HTMLResponse)
def view_job_report(request: Request, job_id: str = Path(..., pattern=JOB_ID_PATTERN)) -> HTMLResponse:
    """Render generated report if present; otherwise show generation prompt."""
    with get_session() as session:
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

    report_path = resolve_report_path(job_id)
    report_text = report_path.read_text(encoding="utf-8") if report_path.exists() else ""
    meta = report_meta(report_path, report_text) if report_path.exists() else None
    return templates.TemplateResponse(
        "report_view.html",
        {
            "request": request,
            "job": job,
            "report_text": report_text,
            "report_exists": report_path.exists(),
            "report_meta": meta,
            "report_message": "",
        },
    )


@router.post("/jobs/{job_id}/report/generate", response_class=HTMLResponse)
def generate_job_report(
    request: Request,
    job_id: str = Path(..., pattern=JOB_ID_PATTERN),
) -> HTMLResponse:
    """Generate and persist report draft for completed jobs."""
    with get_session() as session:
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.current_stage != "DONE" and job.status not in {"COMPLETED", "FAILED"}:
            raise HTTPException(status_code=400, detail="Report generation is available when job is done")

    # Build the report from persisted state so reruns remain reproducible.
    report_text, generated_at = build_report_markdown(job_id)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = report_file_path(job_id)
    report_path.write_text(report_text, encoding="utf-8")
    orchestrator.log_event(
        job_id,
        job.scope_id,
        "REPORT_GENERATED",
        "Report generated",
        actor="REPORTER",
        details={"path": str(report_path), "generated_at": generated_at},
    )

    return templates.TemplateResponse(
        "report_view.html",
        {
            "request": request,
            "job": job,
            "report_text": report_text,
            "report_exists": True,
            "report_meta": report_meta(report_path, report_text),
            "report_message": "Report generated from current job data.",
        },
    )


@router.post("/jobs/{job_id}/report/enrich", response_class=HTMLResponse)
def enrich_job_report_endpoint(
    request: Request,
    job_id: str = Path(..., pattern=JOB_ID_PATTERN),
) -> HTMLResponse:
    """Enrich existing report text using an LLM and persist the result."""
    with get_session() as session:
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.current_stage != "DONE" and job.status not in {"COMPLETED", "FAILED"}:
            raise HTTPException(status_code=400, detail="AI enrichment is available when job is done")

    report_path = resolve_report_path(job_id)
    if not report_path.exists():
        raise HTTPException(status_code=400, detail="Generate the report before AI enrichment")

    # The enrichment step starts from the saved markdown so the UI and disk stay consistent.
    current_report = report_path.read_text(encoding="utf-8")
    try:
        enriched_report = enrich_report_with_ai(job, current_report)
    except HTTPException as exc:
        return templates.TemplateResponse(
            "report_view.html",
            {
                "request": request,
                "job": job,
                "report_text": current_report,
                "report_exists": True,
                "report_meta": report_meta(report_path, current_report),
                "report_message": f"AI enrichment failed: {exc.detail}",
            },
            status_code=200,
        )

    # Replace the on-disk report with the enriched version only after the model call succeeds.
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    target_path = report_file_path(job_id)
    target_path.write_text(enriched_report, encoding="utf-8")
    model = get_report_llm_model()
    orchestrator.log_event(
        job_id,
        job.scope_id,
        "REPORT_ENRICHED",
        "Report enriched with AI",
        actor="REPORTER",
        details={"path": str(target_path), "model": model},
    )

    return templates.TemplateResponse(
        "report_view.html",
        {
            "request": request,
            "job": job,
            "report_text": enriched_report,
            "report_exists": True,
            "report_meta": report_meta(target_path, enriched_report),
            "report_message": f"Report enriched with AI using model {model}.",
        },
    )


@router.get("/jobs/{job_id}/report.md")
def download_job_report(job_id: str = Path(..., pattern=JOB_ID_PATTERN)) -> Response:
    """Download generated report as markdown."""
    with get_session() as session:
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

    report_path = resolve_report_path(job_id)
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not generated yet")

    payload = report_path.read_text(encoding="utf-8")
    headers = {"Content-Disposition": f'attachment; filename="{job_id}_report.md"'}
    return Response(content=payload, media_type="text/markdown; charset=utf-8", headers=headers)
