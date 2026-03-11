from __future__ import annotations

"""Evidence, entity tree, and evidence detail endpoints."""

import json
import math
import os
import re
import tarfile
from io import BytesIO
from tempfile import NamedTemporaryFile
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from sqlalchemy import func
from fastapi import APIRouter, Body, HTTPException, Path, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from starlette.background import BackgroundTask
from sqlmodel import col, select

from ...db import Assertion, Entity, Evidence, Job, Task, get_session
from ...scope import canonicalize_hostname
from ...services.acunetix_workflow_service import (
    get_acunetix_scan_report_path,
    get_acunetix_scan_workflow,
    import_acunetix_scan_to_job,
    list_acunetix_scan_workflows,
    start_acunetix_scan_workflow,
)
from ...services.dast_service import discover_available_dast_tools
from ...services.evidence_service import resolve_linked_entity, resolve_local_artifact, safe_read_raw_evidence
from ...web.deps import templates

router = APIRouter()
JOB_ID_PATTERN = r"^job_[0-9a-f]{12}$"
EVIDENCE_ID_PATTERN = r"^evd_[0-9a-f]{12}$"
TASK_ID_PATTERN = r"^tsk_[0-9a-f]{12}$"
SAFE_FILTER_PATTERN = r"^[A-Za-z0-9_.:-]{1,64}$"
SAFE_OPTIONAL_FILTER_PATTERN = r"^(?:|[A-Za-z0-9_.:-]{1,64})$"
TASK_ID_OPTIONAL_PATTERN = r"^(?:|tsk_[0-9a-f]{12})$"
WORKFLOW_ID_PATTERN = r"^acx_[0-9a-f]{12}$"
NAABU_TCP_PORT_RE = re.compile(r"\b(?P<port>\d{1,5})/tcp\b", re.IGNORECASE)
NAABU_COLON_PORT_RE = re.compile(r":(?P<port>\d{1,5})(?:\b|/)")


def _format_endpoint_netloc(host: str, port: int | None) -> str:
    """Build a normalized netloc for one scanned endpoint."""
    return f"{host}:{port}" if port is not None else host


def _compose_endpoint_url(
    scheme: str,
    host: str,
    *,
    port: int | None = None,
    path: str = "/",
    query: str = "",
) -> str | None:
    """Build one normalized HTTP(S) endpoint URL for DAST launches."""
    normalized_scheme = scheme.strip().lower()
    if normalized_scheme not in {"http", "https"}:
        return None
    try:
        normalized_host = canonicalize_hostname(host)
    except ValueError:
        return None
    if port is not None and not (1 <= port <= 65535):
        return None
    normalized_path = path or "/"
    return urlunsplit((normalized_scheme, _format_endpoint_netloc(normalized_host, port), normalized_path, query, ""))


def _normalize_endpoint_url(raw_url: str, *, fallback_port: int | None = None) -> str | None:
    """Normalize one parsed collector URL and keep the endpoint port explicit."""
    candidate = raw_url.strip()
    if not candidate:
        return None
    parsed = urlsplit(candidate)
    hostname = parsed.hostname or ""
    try:
        parsed_port = parsed.port
    except ValueError:
        return None
    port = parsed_port if parsed_port is not None else fallback_port
    return _compose_endpoint_url(
        parsed.scheme,
        hostname,
        port=port,
        path=parsed.path or "/",
        query=parsed.query,
    )

def _read_gau_urls(blob_ref: str) -> set[str]:
    """Read gau artifact and return normalized non-empty URL lines."""
    resolved = resolve_local_artifact(blob_ref)
    if not resolved:
        return set()

    try:
        raw = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    return {line.strip() for line in raw.splitlines() if line.strip()}


def _read_naabu_ports(blob_ref: str) -> set[int]:
    """Read naabu artifact and return validated open TCP port numbers."""
    resolved = resolve_local_artifact(blob_ref)
    if not resolved:
        return set()

    try:
        raw = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()

    ports: set[int] = set()
    for line in raw.splitlines():
        text = line.strip()
        if not text or text.lower().startswith("naabu execution failed"):
            continue
        for pattern in (NAABU_TCP_PORT_RE, NAABU_COLON_PORT_RE):
            for match in pattern.finditer(text):
                try:
                    port = int(match.group("port"))
                except (TypeError, ValueError):
                    continue
                if 1 <= port <= 65535:
                    ports.add(port)
    return ports


def _read_httpx_scan_target(blob_ref: str, port: int) -> str | None:
    """Read one httpx artifact and return the best launch URL for the scanned port."""
    resolved = resolve_local_artifact(blob_ref)
    if not resolved:
        return None

    try:
        raw = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    for line in raw.splitlines():
        text = line.strip()
        if not text or text.lower().startswith("httpx execution failed"):
            continue
        first_token = text.split(maxsplit=1)[0]
        return _normalize_endpoint_url(first_token, fallback_port=port)
    return None


def _read_nerva_scan_target(blob_ref: str) -> str | None:
    """Read one nerva artifact and return the probed endpoint URL when available."""
    resolved = resolve_local_artifact(blob_ref)
    if not resolved:
        return None

    try:
        payload = json.loads(resolved.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None

    if not isinstance(payload, dict):
        return None
    host = str(payload.get("host") or "").strip()
    protocol = str(payload.get("protocol") or "").strip().lower()
    try:
        port = int(payload.get("port")) if payload.get("port") is not None else None
    except (TypeError, ValueError):
        port = None
    if not protocol and isinstance(payload.get("tls"), bool):
        protocol = "https" if payload["tls"] else "http"
    return _compose_endpoint_url(protocol or "http", host, port=port)


def _evidence_has_visible_raw_content(evidence: Evidence) -> bool:
    """Return True when one evidence row has raw content that can be rendered in the detail view."""
    artifact_path = resolve_local_artifact(evidence.blob_ref)
    raw_evidence, _ = safe_read_raw_evidence(str(artifact_path) if artifact_path else evidence.blob_ref)
    return bool(raw_evidence and raw_evidence.strip())


def _add_bytes_to_tar(tar: tarfile.TarFile, arcname: str, payload: bytes) -> None:
    """Add one in-memory payload as a regular file into tar archive."""
    info = tarfile.TarInfo(name=arcname)
    info.size = len(payload)
    tar.addfile(info, BytesIO(payload))


def _evidence_to_manifest_record(evidence: Evidence, archive_artifact: str | None) -> dict[str, str | None]:
    """Convert evidence row to a JSON-serializable manifest record."""
    return {
        "evidence_id": evidence.evidence_id,
        "job_id": evidence.job_id,
        "task_id": evidence.task_id,
        "kind": evidence.kind,
        "source": evidence.source,
        "collector_version": evidence.collector_version,
        "collected_at": evidence.collected_at.isoformat(),
        "content_hash": evidence.content_hash,
        "blob_ref": evidence.blob_ref,
        "schema_version": evidence.schema_version,
        "archive_artifact": archive_artifact,
    }


def _cleanup_temp_file(path: str) -> None:
    """Delete one temporary archive file after response is sent."""
    try:
        os.unlink(path)
    except OSError:
        pass


@router.get("/jobs/{job_id}/evidence", response_class=HTMLResponse)
def view_job_evidence(
    request: Request,
    job_id: str = Path(..., pattern=JOB_ID_PATTERN),
    source: str | None = Query(default=None, max_length=64, pattern=SAFE_OPTIONAL_FILTER_PATTERN),
    kind: str | None = Query(default=None, max_length=64, pattern=SAFE_OPTIONAL_FILTER_PATTERN),
    task_id: str | None = Query(default=None, pattern=TASK_ID_OPTIONAL_PATTERN),
    page: int = Query(default=1, ge=1, le=100_000),
) -> HTMLResponse:
    """Render paginated evidence exploration view (10 items per page)."""
    per_page = 10
    page = max(1, page)
    with get_session() as session:
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        conditions = [Evidence.job_id == job_id]
        if source:
            conditions.append(Evidence.source == source)
        if kind:
            conditions.append(Evidence.kind == kind)
        if task_id:
            conditions.append(Evidence.task_id == task_id)

        total_items = session.exec(select(func.count()).select_from(Evidence).where(*conditions)).one()
        total_pages = max(1, math.ceil(total_items / per_page))
        page = min(page, total_pages)
        offset = (page - 1) * per_page

        stmt = (
            select(Evidence)
            .where(*conditions)
            .order_by(col(Evidence.collected_at).desc())
            .offset(offset)
            .limit(per_page)
        )
        evidences = session.exec(stmt).all()

        sources = session.exec(select(Evidence.source).where(Evidence.job_id == job_id).distinct()).all()
        kinds = session.exec(select(Evidence.kind).where(Evidence.job_id == job_id).distinct()).all()
        tasks = session.exec(select(Task).where(Task.job_id == job_id).order_by(Task.created_at)).all()

    return templates.TemplateResponse(
        "evidence_list.html",
        {
            "request": request,
            "job": job,
            "evidences": evidences,
            "sources": [s for s in sources if s],
            "kinds": [k for k in kinds if k],
            "tasks": tasks,
            "filters": {"source": source or "", "kind": kind or "", "task_id": task_id or ""},
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total_items": int(total_items),
                "total_pages": total_pages,
                "has_prev": page > 1,
                "has_next": page < total_pages,
            },
        },
    )


@router.get("/jobs/{job_id}/entities", response_class=HTMLResponse)
def view_job_entities(
    request: Request,
    job_id: str = Path(..., pattern=JOB_ID_PATTERN),
) -> HTMLResponse:
    """Render identified domains/subdomains for one job (no filters, full tree)."""
    with get_session() as session:
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        entities = session.exec(
            select(Entity)
            .where(Entity.scope_id == job.scope_id, col(Entity.entity_type).in_(["DOMAIN", "HOSTNAME"]))
            .order_by(col(Entity.canonical_name))
        ).all()

        dnsx_evidence_ids = {
            row.evidence_id
            for row in session.exec(
                select(Evidence)
                .where(Evidence.job_id == job.job_id, Evidence.source == "dnsx")
                .order_by(col(Evidence.collected_at).desc())
            ).all()
        }
        resolved_evidence_by_entity: dict[str, str] = {}
        resolve_assertions = session.exec(
            select(Assertion)
            .where(Assertion.scope_id == job.scope_id, Assertion.predicate == "resolves", Assertion.value == "true")
            .order_by(col(Assertion.created_at).desc())
        ).all()
        for assertion in resolve_assertions:
            if assertion.subject_entity_id in resolved_evidence_by_entity:
                continue
            try:
                evidence_refs = json.loads(assertion.evidence_refs or "[]")
            except json.JSONDecodeError:
                continue
            for evidence_id in evidence_refs:
                if evidence_id in dnsx_evidence_ids:
                    resolved_evidence_by_entity[assertion.subject_entity_id] = evidence_id
                    break

        gau_evidence_by_id = {
            row.evidence_id: row
            for row in session.exec(
                select(Evidence).where(Evidence.job_id == job.job_id, Evidence.source == "gau", Evidence.kind == "URL_ENUMERATION")
            ).all()
        }
        # Cache parsed URL sets by evidence ID to avoid repeated file reads.
        gau_urls_cache_by_evidence_id: dict[str, set[str]] = {}
        gau_urls_by_entity: dict[str, set[str]] = {}
        gau_evidence_link_by_entity: dict[str, str] = {}
        gau_assertions = session.exec(
            select(Assertion)
            .where(Assertion.scope_id == job.scope_id, Assertion.predicate == "urls_collected_by", Assertion.value == "true")
            .order_by(col(Assertion.created_at).desc())
        ).all()
        for assertion in gau_assertions:
            entity_urls = gau_urls_by_entity.setdefault(assertion.subject_entity_id, set())
            try:
                evidence_refs = json.loads(assertion.evidence_refs or "[]")
            except json.JSONDecodeError:
                continue
            for evidence_id in evidence_refs:
                gau_evidence = gau_evidence_by_id.get(evidence_id)
                if not gau_evidence:
                    continue
                gau_evidence_link_by_entity.setdefault(assertion.subject_entity_id, gau_evidence.evidence_id)
                if evidence_id not in gau_urls_cache_by_evidence_id:
                    gau_urls_cache_by_evidence_id[evidence_id] = _read_gau_urls(gau_evidence.blob_ref)
                entity_urls.update(gau_urls_cache_by_evidence_id[evidence_id])
        gau_url_count_by_entity = {entity_id: len(urls) for entity_id, urls in gau_urls_by_entity.items()}

        naabu_evidence_by_id = {
            row.evidence_id: row
            for row in session.exec(
                select(Evidence).where(Evidence.job_id == job.job_id, Evidence.source == "naabu", Evidence.kind == "PORT_SCAN")
            ).all()
        }
        # Cache parsed open ports by evidence ID to avoid repeated file reads.
        naabu_ports_cache_by_evidence_id: dict[str, set[int]] = {}
        naabu_ports_by_entity: dict[str, set[int]] = {}
        naabu_evidence_link_by_entity: dict[str, str] = {}
        naabu_assertions = session.exec(
            select(Assertion)
            .where(Assertion.scope_id == job.scope_id, Assertion.predicate == "ports_scanned_by", Assertion.value == "true")
            .order_by(col(Assertion.created_at).desc())
        ).all()
        for assertion in naabu_assertions:
            entity_ports = naabu_ports_by_entity.setdefault(assertion.subject_entity_id, set())
            try:
                evidence_refs = json.loads(assertion.evidence_refs or "[]")
            except json.JSONDecodeError:
                continue
            for evidence_id in evidence_refs:
                naabu_evidence = naabu_evidence_by_id.get(evidence_id)
                if not naabu_evidence:
                    continue
                naabu_evidence_link_by_entity.setdefault(assertion.subject_entity_id, naabu_evidence.evidence_id)
                if evidence_id not in naabu_ports_cache_by_evidence_id:
                    naabu_ports_cache_by_evidence_id[evidence_id] = _read_naabu_ports(naabu_evidence.blob_ref)
                entity_ports.update(naabu_ports_cache_by_evidence_id[evidence_id])
        naabu_port_count_by_entity = {entity_id: len(ports) for entity_id, ports in naabu_ports_by_entity.items()}
        naabu_open_ports_by_entity = {
            entity_id: sorted(ports)
            for entity_id, ports in naabu_ports_by_entity.items()
        }
        httpx_evidence_by_id = {
            row.evidence_id: row
            for row in session.exec(
                select(Evidence).where(Evidence.job_id == job.job_id, Evidence.source == "httpx", Evidence.kind == "HTTP_PROBE")
            ).all()
            if _evidence_has_visible_raw_content(row)
        }
        nerva_evidence_by_id = {
            row.evidence_id: row
            for row in session.exec(
                select(Evidence).where(Evidence.job_id == job.job_id, Evidence.source == "nerva", Evidence.kind == "SERVICE_PROBE")
            ).all()
            if _evidence_has_visible_raw_content(row)
        }
        httpx_evidence_by_entity_port: dict[str, dict[int, str]] = {}
        nerva_evidence_by_entity_port: dict[str, dict[int, str]] = {}
        scan_targets_by_entity_port: dict[str, dict[int, str]] = {}
        httpx_scan_target_cache_by_evidence_id: dict[str, str | None] = {}
        nerva_scan_target_cache_by_evidence_id: dict[str, str | None] = {}
        httpx_assertions = session.exec(
            select(Assertion)
            .where(Assertion.scope_id == job.scope_id, Assertion.predicate == "port_http_profiled")
            .order_by(col(Assertion.created_at).desc())
        ).all()
        for assertion in httpx_assertions:
            raw_port = str(assertion.value or "").strip()
            if not raw_port.isdigit():
                continue
            port = int(raw_port)
            if not (1 <= port <= 65535):
                continue
            try:
                evidence_refs = json.loads(assertion.evidence_refs or "[]")
            except json.JSONDecodeError:
                continue
            for evidence_id in evidence_refs:
                if evidence_id not in httpx_evidence_by_id:
                    continue
                # Keep first (newest) mapping per entity+port due descending created_at order.
                port_map = httpx_evidence_by_entity_port.setdefault(assertion.subject_entity_id, {})
                port_map.setdefault(port, evidence_id)
                if evidence_id not in httpx_scan_target_cache_by_evidence_id:
                    httpx_scan_target_cache_by_evidence_id[evidence_id] = _read_httpx_scan_target(
                        httpx_evidence_by_id[evidence_id].blob_ref,
                        port,
                    )
                scan_target = httpx_scan_target_cache_by_evidence_id.get(evidence_id)
                if scan_target:
                    scan_target_map = scan_targets_by_entity_port.setdefault(assertion.subject_entity_id, {})
                    scan_target_map.setdefault(port, scan_target)
                break
        nerva_assertions = session.exec(
            select(Assertion)
            .where(Assertion.scope_id == job.scope_id, Assertion.predicate == "port_service_profiled")
            .order_by(col(Assertion.created_at).desc())
        ).all()
        for assertion in nerva_assertions:
            raw_port = str(assertion.value or "").strip()
            if not raw_port.isdigit():
                continue
            port = int(raw_port)
            if not (1 <= port <= 65535):
                continue
            try:
                evidence_refs = json.loads(assertion.evidence_refs or "[]")
            except json.JSONDecodeError:
                continue
            for evidence_id in evidence_refs:
                if evidence_id not in nerva_evidence_by_id:
                    continue
                port_map = nerva_evidence_by_entity_port.setdefault(assertion.subject_entity_id, {})
                port_map.setdefault(port, evidence_id)
                if evidence_id not in nerva_scan_target_cache_by_evidence_id:
                    nerva_scan_target_cache_by_evidence_id[evidence_id] = _read_nerva_scan_target(
                        nerva_evidence_by_id[evidence_id].blob_ref
                    )
                scan_target = nerva_scan_target_cache_by_evidence_id.get(evidence_id)
                if scan_target:
                    scan_target_map = scan_targets_by_entity_port.setdefault(assertion.subject_entity_id, {})
                    scan_target_map.setdefault(port, scan_target)
                break

        domain_count = int(
            session.exec(
                select(func.count()).select_from(Entity).where(Entity.scope_id == job.scope_id, Entity.entity_type == "DOMAIN")
            ).one()
        )
        subdomain_count = int(
            session.exec(select(func.count()).select_from(Entity).where(Entity.scope_id == job.scope_id, Entity.entity_type == "HOSTNAME")).one()
        )

    return templates.TemplateResponse(
        "entity_list.html",
        {
            "request": request,
            "job": job,
            "entities": entities,
            "entity_tree_payload": [
                {
                    "name": e.canonical_name,
                    "resolution_status": e.resolution_status or "UNRESOLVED",
                    "resolution_source": e.resolution_source or "",
                    "resolved_evidence_id": resolved_evidence_by_entity.get(e.entity_id, ""),
                    "gau_url_count": gau_url_count_by_entity.get(e.entity_id, 0),
                    "gau_evidence_id": gau_evidence_link_by_entity.get(e.entity_id, ""),
                    "naabu_port_count": naabu_port_count_by_entity.get(e.entity_id, 0),
                    "naabu_open_ports": naabu_open_ports_by_entity.get(e.entity_id, []),
                    "naabu_evidence_id": naabu_evidence_link_by_entity.get(e.entity_id, ""),
                    "httpx_evidence_by_port": {
                        str(port): evidence_id
                        for port, evidence_id in httpx_evidence_by_entity_port.get(e.entity_id, {}).items()
                    },
                    "nerva_evidence_by_port": {
                        str(port): evidence_id
                        for port, evidence_id in nerva_evidence_by_entity_port.get(e.entity_id, {}).items()
                    },
                    "scan_targets_by_port": {
                        str(port): target_url
                        for port, target_url in scan_targets_by_entity_port.get(e.entity_id, {}).items()
                    },
                    "is_identified_target": True,
                }
                for e in entities
            ],
            "domain_count": domain_count,
            "subdomain_count": subdomain_count,
        },
    )


@router.get("/jobs/{job_id}/dast/tools", response_class=JSONResponse)
def list_job_dast_tools(job_id: str = Path(..., pattern=JOB_ID_PATTERN)) -> JSONResponse:
    """Return available DAST integrations for the current operator environment."""
    with get_session() as session:
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

    return JSONResponse(discover_available_dast_tools())


@router.get("/jobs/{job_id}/dast", response_class=HTMLResponse)
def view_job_dast(
    request: Request,
    job_id: str = Path(..., pattern=JOB_ID_PATTERN),
) -> HTMLResponse:
    """Render the job-level DAST page with the Acunetix pane."""
    with get_session() as session:
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

    dast_tools = discover_available_dast_tools()
    acunetix_entry = next(
        (tool for tool in dast_tools.get("tools", []) if isinstance(tool, dict) and tool.get("id") == "mcp:acunetix"),
        None,
    )
    workflows = list_acunetix_scan_workflows(job_id)
    active_workflow_count = sum(1 for workflow in workflows if workflow.get("status") in {"PENDING", "RUNNING"})
    completed_workflow_count = sum(1 for workflow in workflows if workflow.get("status") == "COMPLETED")

    return templates.TemplateResponse(
        "dast_view.html",
        {
            "request": request,
            "job": job,
            "acunetix_entry": acunetix_entry,
            "dast_warnings": dast_tools.get("warnings", []),
            "workflow_count": len(workflows),
            "active_workflow_count": active_workflow_count,
            "completed_workflow_count": completed_workflow_count,
            "workflows": workflows,
        },
    )


@router.get("/jobs/{job_id}/dast/acunetix/workflows", response_class=JSONResponse)
def list_job_acunetix_workflows(job_id: str = Path(..., pattern=JOB_ID_PATTERN)) -> JSONResponse:
    """Return all Acunetix workflows for the specified job."""
    with get_session() as session:
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

    return JSONResponse({"ok": True, "workflows": list_acunetix_scan_workflows(job_id)})


@router.post("/jobs/{job_id}/dast/acunetix/import-scan", response_class=JSONResponse)
def import_job_acunetix_scan(
    job_id: str = Path(..., pattern=JOB_ID_PATTERN),
    payload: dict[str, str] = Body(...),
) -> JSONResponse:
    """Import an existing Acunetix scan into the current job evidence set."""
    scan_id = str(payload.get("scan_id") or "").strip()
    if not scan_id:
        raise HTTPException(status_code=400, detail="scan_id is required")
    try:
        normalized_scan_id = str(UUID(scan_id))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="scan_id must be a valid UUID") from exc

    with get_session() as session:
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

    try:
        result = import_acunetix_scan_to_job(job.job_id, job.scope_id, scan_id=normalized_scan_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return JSONResponse(result)


@router.post("/jobs/{job_id}/dast/acunetix/workflows", response_class=JSONResponse)
def start_job_acunetix_workflow(
    job_id: str = Path(..., pattern=JOB_ID_PATTERN),
    payload: dict[str, str] = Body(...),
) -> JSONResponse:
    """Launch one Acunetix workflow for a validated in-scope target."""
    target_name_raw = str(payload.get("target_name") or "").strip()
    target_url_raw = str(payload.get("target_url") or "").strip()
    target_label = str(payload.get("target_label") or target_url_raw or target_name_raw).strip()
    target_url = ""
    target_url_host = ""
    if target_url_raw:
        parsed_target = urlsplit(target_url_raw)
        if parsed_target.scheme.lower() not in {"http", "https"} or not parsed_target.hostname:
            raise HTTPException(status_code=400, detail="target_url must be a valid http or https URL")
        try:
            target_url_host = canonicalize_hostname(parsed_target.hostname)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid target_url host: {exc}") from exc
        try:
            target_port = parsed_target.port
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid target_url port: {exc}") from exc
        target_url = urlunsplit(
            (
                parsed_target.scheme.lower(),
                _format_endpoint_netloc(target_url_host, target_port),
                parsed_target.path or "/",
                parsed_target.query,
                "",
            )
        )

    if not target_name_raw and not target_url_host:
        raise HTTPException(status_code=400, detail="target_name or target_url is required")
    try:
        target_name = canonicalize_hostname(target_name_raw or target_url_host)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid target_name: {exc}") from exc

    with get_session() as session:
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        entity = session.exec(
            select(Entity).where(
                Entity.scope_id == job.scope_id,
                col(Entity.entity_type).in_(["DOMAIN", "HOSTNAME"]),
                Entity.canonical_name == target_name,
            )
        ).first()
        if not entity:
            raise HTTPException(status_code=404, detail="Target not found in this job scope")

    workflow = start_acunetix_scan_workflow(
        job.job_id,
        job.scope_id,
        target_name=target_name,
        target_address=target_url or f"https://{target_name}",
        target_label=target_label or target_url or target_name,
    )
    return JSONResponse(workflow)


@router.get("/jobs/{job_id}/dast/acunetix/workflows/{workflow_id}", response_class=JSONResponse)
def get_job_acunetix_workflow(
    job_id: str = Path(..., pattern=JOB_ID_PATTERN),
    workflow_id: str = Path(..., pattern=WORKFLOW_ID_PATTERN),
) -> JSONResponse:
    """Return status for one Acunetix workflow."""
    try:
        workflow = get_acunetix_scan_workflow(job_id, workflow_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Acunetix workflow not found") from exc
    return JSONResponse(workflow)


@router.get("/jobs/{job_id}/dast/acunetix/workflows/{workflow_id}/report")
def download_job_acunetix_report(
    job_id: str = Path(..., pattern=JOB_ID_PATTERN),
    workflow_id: str = Path(..., pattern=WORKFLOW_ID_PATTERN),
) -> FileResponse:
    """Download the saved Acunetix report for one completed workflow."""
    try:
        report_path = get_acunetix_scan_report_path(job_id, workflow_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Acunetix workflow not found") from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Acunetix report not available") from exc
    return FileResponse(report_path, filename=report_path.name)


@router.get("/jobs/{job_id}/entities.txt")
def download_job_entities_txt(
    job_id: str = Path(..., pattern=JOB_ID_PATTERN),
) -> Response:
    """Download identified domains/subdomains for one job as plain text."""
    with get_session() as session:
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        stmt = select(Entity).where(
            Entity.scope_id == job.scope_id,
            col(Entity.entity_type).in_(["DOMAIN", "HOSTNAME"]),
        )
        entities = session.exec(stmt.order_by(col(Entity.canonical_name))).all()

    names = sorted({e.canonical_name for e in entities})
    payload = "\n".join(names) + ("\n" if names else "")
    headers = {"Content-Disposition": f'attachment; filename="{job_id}_domains_subdomains.txt"'}
    return Response(content=payload, media_type="text/plain; charset=utf-8", headers=headers)


@router.get("/jobs/{job_id}/evidence/archive.tar.gz")
def download_job_evidence_archive(
    job_id: str = Path(..., pattern=JOB_ID_PATTERN),
) -> FileResponse:
    """Download all job evidence records and local artifacts as one tar.gz archive."""
    with get_session() as session:
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        evidences = session.exec(
            select(Evidence).where(Evidence.job_id == job_id).order_by(col(Evidence.collected_at), col(Evidence.evidence_id))
        ).all()

    # Use a temporary on-disk archive to keep memory stable for large evidence sets.
    tmp = NamedTemporaryFile(prefix=f"{job_id}_evidence_", suffix=".tar.gz", delete=False)
    tmp_path = tmp.name
    tmp.close()
    manifest_rows: list[dict[str, str | None]] = []

    with tarfile.open(tmp_path, mode="w:gz") as tar:
        for evidence in evidences:
            artifact_path = resolve_local_artifact(evidence.blob_ref)
            archive_artifact: str | None = None
            if artifact_path:
                safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", artifact_path.name) or f"{evidence.evidence_id}.txt"
                archive_artifact = f"artifacts/{evidence.evidence_id}_{safe_name}"
                try:
                    _add_bytes_to_tar(tar, archive_artifact, artifact_path.read_bytes())
                except OSError:
                    archive_artifact = None
            manifest_rows.append(_evidence_to_manifest_record(evidence, archive_artifact))

        manifest_payload = {
            "job_id": job_id,
            "total_evidence": len(evidences),
            "records": manifest_rows,
        }
        _add_bytes_to_tar(
            tar,
            "manifest/evidence_manifest.json",
            json.dumps(manifest_payload, indent=2, sort_keys=True).encode("utf-8"),
        )

    archive_name = f"{job_id}_evidence_bundle.tar.gz"
    return FileResponse(
        path=tmp_path,
        filename=archive_name,
        media_type="application/gzip",
        background=BackgroundTask(_cleanup_temp_file, tmp_path),
    )


@router.get("/jobs/{job_id}/evidence/{evidence_id}", response_class=HTMLResponse)
def view_evidence_detail(
    request: Request,
    job_id: str = Path(..., pattern=JOB_ID_PATTERN),
    evidence_id: str = Path(..., pattern=EVIDENCE_ID_PATTERN),
) -> HTMLResponse:
    """Render evidence detail page with linked task and assertion references."""
    with get_session() as session:
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        evidence = session.exec(
            select(Evidence).where(Evidence.job_id == job_id, Evidence.evidence_id == evidence_id)
        ).first()
        if not evidence:
            raise HTTPException(status_code=404, detail="Evidence not found")

        task = session.exec(select(Task).where(Task.task_id == evidence.task_id)).first()
        assertions = session.exec(
            select(Assertion)
            .where(Assertion.scope_id == job.scope_id)
            .where(col(Assertion.evidence_refs).contains(evidence.evidence_id))
            .order_by(col(Assertion.created_at).desc())
        ).all()
        entity = resolve_linked_entity(session, job.scope_id, evidence, assertions)
        artifact_path = resolve_local_artifact(evidence.blob_ref)
        raw_evidence, raw_evidence_note = safe_read_raw_evidence(str(artifact_path) if artifact_path else evidence.blob_ref)

    return templates.TemplateResponse(
        "evidence_detail.html",
        {
            "request": request,
            "job": job,
            "evidence": evidence,
            "task": task,
            "assertions": assertions,
            "entity": entity,
            "raw_evidence": raw_evidence,
            "raw_evidence_note": raw_evidence_note,
            "download_available": bool(artifact_path or raw_evidence),
        },
    )


@router.get("/jobs/{job_id}/evidence/{evidence_id}/download")
def download_evidence(
    job_id: str = Path(..., pattern=JOB_ID_PATTERN),
    evidence_id: str = Path(..., pattern=EVIDENCE_ID_PATTERN),
) -> Response:
    """Download raw evidence as a file when local artifact or rendered text is available."""
    with get_session() as session:
        evidence = session.exec(select(Evidence).where(Evidence.job_id == job_id, Evidence.evidence_id == evidence_id)).first()
        if not evidence:
            raise HTTPException(status_code=404, detail="Evidence not found")

    artifact_path = resolve_local_artifact(evidence.blob_ref)
    if artifact_path:
        filename = re.sub(r"[^A-Za-z0-9._-]", "_", artifact_path.name) or f"{evidence.evidence_id}.txt"
        return FileResponse(path=str(artifact_path), filename=filename, media_type="application/octet-stream")

    raw_evidence, _ = safe_read_raw_evidence(str(artifact_path) if artifact_path else evidence.blob_ref)
    if raw_evidence is None:
        raise HTTPException(status_code=404, detail="Download unavailable for this evidence")

    filename = f"{evidence.evidence_id}.txt"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=raw_evidence, media_type="text/plain; charset=utf-8", headers=headers)
