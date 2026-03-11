from __future__ import annotations

"""Background Acunetix scan workflow orchestration for the DAST modal."""

import base64
import binascii
import copy
import hashlib
import json
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sqlmodel import select

from ..config import (
    ACUNETIX_DEFAULT_PROFILE_ID,
    ACUNETIX_DEFAULT_REPORT_TEMPLATE_ID,
    ACUNETIX_REPORT_POLL_INTERVAL,
    ACUNETIX_REPORT_TIMEOUT,
    ACUNETIX_RESULT_HISTORY_LIMIT,
    ACUNETIX_SCAN_MAX_RUNTIME,
    ACUNETIX_SCAN_POLL_INTERVAL,
    COLLECTOR_ARTIFACTS_DIR,
    ACUNETIX_TARGET_CASE_SENSITIVE,
    ACUNETIX_TARGET_CRITICALITY,
    ACUNETIX_TARGET_PROXY_ADDRESS,
    ACUNETIX_TARGET_PROXY_ENABLED,
    ACUNETIX_TARGET_PROXY_PORT,
    ACUNETIX_TARGET_PROXY_PROTOCOL,
    ACUNETIX_TARGET_SCAN_SPEED,
    ACUNETIX_TARGET_USER_AGENT,
    ACUNETIX_VULNERABILITIES_PAGE_LIMIT,
    REPORTS_DIR,
)
from ..db import Evidence, Job, Stage, Task, get_session
from ..orchestration.common import make_id
from ..web.deps import orchestrator
from .dast_service import call_acunetix_mcp_tool, initialize_acunetix_mcp, resolve_acunetix_mcp_tool_name

WORKFLOW_ID_PREFIX = "acx_"
WORKFLOW_ID_HEX_LEN = 12
DAST_STAGE_NAME = "DAST"
ACUNETIX_TASK_TYPE = "run_acunetix_scan"
ACUNETIX_IMPORT_TASK_TYPE = "import_acunetix_scan"
ACUNETIX_EVIDENCE_KIND = "DAST_VULNERABILITIES"
ACUNETIX_EVIDENCE_SOURCE = "acunetix"
TERMINAL_SCAN_STATUSES = {"completed", "failed", "aborted"}
FAILED_SCAN_STATUSES = {"failed", "aborted"}
SUCCESSFUL_REPORT_STATUSES = {"completed", "generated", "ready", "done"}
FAILED_REPORT_STATUSES = {"failed", "error", "aborted"}
_WORKFLOWS: dict[str, dict[str, Any]] = {}
_WORKFLOWS_LOCK = threading.Lock()
WORKFLOW_REQUIRED_TOOLS = (
    "add_target",
    "configure_target",
    "schedule_scan",
    "get_scan",
    "get_scan_result_history",
    "get_scan_vulnerabilities",
    "get_scan_vulnerability_detail",
    "generate_new_report",
    "get_report",
    "download_report",
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utcnow_iso() -> str:
    return _utcnow().isoformat()


def _new_workflow_id() -> str:
    return f"{WORKFLOW_ID_PREFIX}{secrets.token_hex(WORKFLOW_ID_HEX_LEN // 2)}"


def _sanitize_file_component(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "-" for ch in value.strip().lower())
    return cleaned.strip("-._") or "artifact"


def _workflow_snapshot(workflow: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(workflow)


def _update_workflow(workflow_id: str, **changes: Any) -> dict[str, Any]:
    with _WORKFLOWS_LOCK:
        workflow = _WORKFLOWS[workflow_id]
        workflow.update(changes)
        workflow["updated_at"] = _utcnow_iso()
        return _workflow_snapshot(workflow)


def _append_step(workflow_id: str, phase: str, message: str, *, step_status: str = "INFO", **extra: Any) -> None:
    with _WORKFLOWS_LOCK:
        workflow = _WORKFLOWS[workflow_id]
        steps = workflow.setdefault("steps", [])
        steps.append(
            {
                "at": _utcnow_iso(),
                "phase": phase,
                "status": step_status,
                "message": message,
                **extra,
            }
        )
        if len(steps) > 40:
            del steps[:-40]
        workflow["updated_at"] = _utcnow_iso()


def _find_existing_active_workflow(job_id: str, target_address: str) -> dict[str, Any] | None:
    with _WORKFLOWS_LOCK:
        for workflow in _WORKFLOWS.values():
            if workflow["job_id"] != job_id:
                continue
            if workflow["target_address"] != target_address:
                continue
            if workflow["status"] in {"RUNNING", "PENDING"}:
                return _workflow_snapshot(workflow)
    return None


def _find_first_by_key(value: Any, *keys: str) -> Any:
    if isinstance(value, dict):
        for key in keys:
            candidate = value.get(key)
            if candidate not in (None, "", [], {}):
                return candidate
        for child in value.values():
            found = _find_first_by_key(child, *keys)
            if found not in (None, "", [], {}):
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_first_by_key(child, *keys)
            if found not in (None, "", [], {}):
                return found
    return None


def _extract_tool_data(payload: dict[str, Any]) -> dict[str, Any]:
    data = payload.get("data")
    return data if isinstance(data, dict) else {}


def _extract_scan_status(scan_payload: dict[str, Any]) -> tuple[str, int | None]:
    data = _extract_tool_data(scan_payload)
    current_session = data.get("current_session") if isinstance(data.get("current_session"), dict) else {}
    status = str(current_session.get("status") or data.get("status") or "").strip().lower()
    progress_raw = current_session.get("progress")
    try:
        progress = int(progress_raw) if progress_raw is not None else None
    except (TypeError, ValueError):
        progress = None
    return status, progress


def _extract_result_id(history_payload: dict[str, Any]) -> str:
    data = _extract_tool_data(history_payload)
    results = data.get("results")
    if isinstance(results, list):
        dated_results: list[tuple[str, str]] = []
        for row in results:
            if isinstance(row, dict):
                result_id = str(row.get("result_id") or "").strip()
                if result_id:
                    sort_key = str(row.get("end_date") or row.get("start_date") or "").strip()
                    dated_results.append((sort_key, result_id))
        if dated_results:
            dated_results.sort(reverse=True)
            return dated_results[0][1]
    result_id = _find_first_by_key(data, "result_id")
    return str(result_id or "").strip()


def _extract_vulnerability_summary(vulns_payload: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    data = _extract_tool_data(vulns_payload)
    rows = data.get("vulnerabilities")
    vulnerabilities = rows if isinstance(rows, list) else []
    pagination = data.get("pagination") if isinstance(data.get("pagination"), dict) else {}
    total = pagination.get("count")
    try:
        total_count = int(total)
    except (TypeError, ValueError):
        total_count = len(vulnerabilities)

    preview: list[dict[str, Any]] = []
    for row in vulnerabilities[:10]:
        if not isinstance(row, dict):
            continue
        preview.append(
            {
                "vuln_id": str(row.get("vuln_id") or "").strip(),
                "name": str(row.get("vt_name") or row.get("affects_url") or "Unnamed vulnerability").strip(),
                "severity": row.get("severity"),
                "criticality": row.get("criticality"),
                "status": str(row.get("status") or "").strip(),
                "url": str(row.get("affects_url") or "").strip(),
            }
        )
    return total_count, preview


def _extract_vulnerability_rows(vulns_payload: dict[str, Any]) -> list[dict[str, Any]]:
    data = _extract_tool_data(vulns_payload)
    rows = data.get("vulnerabilities")
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def _build_vulnerability_evidence_content(
    *,
    scan_id: str,
    result_id: str,
    vulnerability_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    detailed_vulnerabilities: list[dict[str, Any]] = []
    for row in vulnerability_rows:
        vuln_id = str(row.get("vuln_id") or "").strip()
        if not vuln_id:
            detailed_vulnerabilities.append(row)
            continue
        try:
            detail_payload = call_acunetix_mcp_tool(
                "get_scan_vulnerability_detail",
                {"scan_id": scan_id, "result_id": result_id, "vuln_id": vuln_id},
            )
        except Exception:
            detailed_vulnerabilities.append(row)
            continue

        detail_data = _extract_tool_data(detail_payload)
        if detail_data:
            detailed_vulnerabilities.append(detail_data)
        else:
            detailed_vulnerabilities.append(row)
    return detailed_vulnerabilities


def _extract_download_descriptor(report_payload: dict[str, Any]) -> str:
    data = _extract_tool_data(report_payload)
    download_urls = data.get("download")
    if not isinstance(download_urls, list):
        return ""
    for item in download_urls:
        raw = str(item or "").strip()
        if not raw:
            continue
        path = urlsplit(raw).path.strip("/")
        descriptor = path.rsplit("/", 1)[-1].strip()
        if descriptor:
            return descriptor
    return ""


def _refresh_vulnerabilities(
    workflow_id: str,
    *,
    job_id: str,
    scope_id: str,
    task_id: str,
    target_name: str,
    scan_id: str,
    scan_status: str,
) -> str:
    history_payload = call_acunetix_mcp_tool(
        "get_scan_result_history",
        {"scan_id": scan_id, "limit": ACUNETIX_RESULT_HISTORY_LIMIT},
    )
    result_id = _extract_result_id(history_payload)
    if not result_id:
        return ""

    vulnerabilities_payload = call_acunetix_mcp_tool(
        "get_scan_vulnerabilities",
        {"scan_id": scan_id, "result_id": result_id, "limit": ACUNETIX_VULNERABILITIES_PAGE_LIMIT},
    )
    vulnerability_count, vulnerabilities_preview = _extract_vulnerability_summary(vulnerabilities_payload)
    _update_workflow(
        workflow_id,
        result_id=result_id,
        vulnerability_count=vulnerability_count,
        vulnerabilities_preview=vulnerabilities_preview,
        message=f"Retrieved {vulnerability_count} vulnerabilities",
    )
    _record_vulnerability_evidence(
        workflow_id,
        job_id=job_id,
        scope_id=scope_id,
        task_id=task_id,
        target_name=target_name,
        scan_id=scan_id,
        result_id=result_id,
        scan_status=scan_status,
        vulnerabilities_payload=vulnerabilities_payload,
    )
    return result_id


def _report_download_extension(filename: str | None, content_type: str | None) -> str:
    if filename and "." in filename:
        return "." + filename.rsplit(".", 1)[-1]
    normalized_type = (content_type or "").lower()
    if "pdf" in normalized_type:
        return ".pdf"
    if "html" in normalized_type:
        return ".html"
    if "json" in normalized_type:
        return ".json"
    if "xml" in normalized_type:
        return ".xml"
    return ".bin"


def _write_report_artifact(job_id: str, workflow_id: str, target_name: str, download_payload: dict[str, Any]) -> Path:
    data = _extract_tool_data(download_payload)
    content_base64 = str(data.get("content_base64") or "").strip()
    if not content_base64:
        raise RuntimeError("Acunetix report download returned no binary content")
    try:
        binary = base64.b64decode(content_base64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RuntimeError("Acunetix report download returned invalid base64 content") from exc

    filename = str(data.get("filename") or "").strip() or None
    extension = _report_download_extension(filename, str(data.get("content_type") or "").strip())
    artifact_name = (
        f"{job_id}_{workflow_id}_{_sanitize_file_component(target_name)}_acunetix_report{extension}"
    )
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    artifact_path = REPORTS_DIR / artifact_name
    artifact_path.write_bytes(binary)
    return artifact_path


def _validate_workflow_tool_names(available_tool_names: list[str]) -> None:
    """Verify that the Acunetix workflow tool set can be resolved from the runtime MCP inventory."""
    missing: list[str] = []
    for tool_name in WORKFLOW_REQUIRED_TOOLS:
        if not resolve_acunetix_mcp_tool_name(tool_name, available_tool_names):
            missing.append(tool_name)
    if missing:
        raise RuntimeError(f"Acunetix MCP is missing required tools: {', '.join(sorted(missing))}")


def _validate_required_tool_names(available_tool_names: list[str], required_tool_names: tuple[str, ...]) -> None:
    missing: list[str] = []
    for tool_name in required_tool_names:
        if not resolve_acunetix_mcp_tool_name(tool_name, available_tool_names):
            missing.append(tool_name)
    if missing:
        raise RuntimeError(f"Acunetix MCP is missing required tools: {', '.join(sorted(missing))}")


def _ensure_dast_stage(session, job_id: str, scope_id: str) -> Stage:
    stage = session.exec(select(Stage).where(Stage.job_id == job_id, Stage.name == DAST_STAGE_NAME)).first()
    if stage:
        return stage

    last_stage = session.exec(select(Stage).where(Stage.job_id == job_id).order_by(Stage.order_idx.desc())).first()
    stage = Stage(
        stage_id=make_id("stg"),
        job_id=job_id,
        scope_id=scope_id,
        name=DAST_STAGE_NAME,
        order_idx=(last_stage.order_idx + 1) if last_stage else 0,
        tier="ACTIVE",
        status="READY",
    )
    session.add(stage)
    session.flush()
    return stage


def _create_workflow_task(
    workflow_id: str,
    job_id: str,
    scope_id: str,
    *,
    target_name: str,
    target_label: str,
    target_address: str,
) -> tuple[str, str, bool]:
    with get_session() as session:
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not job:
            raise RuntimeError(f"Job not found: {job_id}")

        stage = _ensure_dast_stage(session, job_id, scope_id)
        was_done = job.current_stage == "DONE" or job.status in {"COMPLETED", "FAILED"}
        task = Task(
            task_id=make_id("tsk"),
            job_id=job_id,
            stage_id=stage.stage_id,
            scope_id=scope_id,
            task_type=ACUNETIX_TASK_TYPE,
            status="RUNNING",
            tier="ACTIVE",
            planner_source="ACUNETIX_DAST",
            approval_level="NONE",
            input_payload=json.dumps(
                {
                    "workflow_id": workflow_id,
                    "target_name": target_name,
                    "target_label": target_label,
                    "target_address": target_address,
                },
                sort_keys=True,
            ),
        )
        stage.status = "RUNNING"
        stage.ended_at = None
        job.status = "RERUNNING" if was_done else "RUNNING"
        job.current_stage = DAST_STAGE_NAME
        job.updated_at = _utcnow()
        session.add(task)
        session.add(stage)
        session.add(job)
        session.commit()
        session.refresh(stage)
        session.refresh(task)

    orchestrator.log_event(
        job_id,
        scope_id,
        "JOB_STATUS",
        "Job rerunning for Acunetix DAST" if was_done else "Job running Acunetix DAST",
        actor="ACUNETIX_DAST",
    )
    orchestrator.log_event(
        job_id,
        scope_id,
        "TASK_STATUS",
        f"Task {ACUNETIX_TASK_TYPE} running",
        actor="ACUNETIX_DAST",
        stage_id=stage.stage_id,
        task_id=task.task_id,
        details={"workflow_id": workflow_id, "target_label": target_label, "target_address": target_address},
    )
    return stage.stage_id, task.task_id, was_done


def _create_import_task(
    job_id: str,
    scope_id: str,
    *,
    scan_id: str,
    target_label: str,
) -> tuple[str, str]:
    with get_session() as session:
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not job:
            raise RuntimeError(f"Job not found: {job_id}")

        stage = _ensure_dast_stage(session, job_id, scope_id)
        task = Task(
            task_id=make_id("tsk"),
            job_id=job_id,
            stage_id=stage.stage_id,
            scope_id=scope_id,
            task_type=ACUNETIX_IMPORT_TASK_TYPE,
            status="RUNNING",
            tier="ACTIVE",
            planner_source="ACUNETIX_IMPORT",
            approval_level="NONE",
            input_payload=json.dumps(
                {
                    "scan_id": scan_id,
                    "target_label": target_label,
                },
                sort_keys=True,
            ),
        )
        stage.status = "RUNNING"
        stage.ended_at = None
        job.updated_at = _utcnow()
        session.add(task)
        session.add(stage)
        session.add(job)
        session.commit()
        session.refresh(stage)
        session.refresh(task)

    orchestrator.log_event(
        job_id,
        scope_id,
        "TASK_STATUS",
        f"Task {ACUNETIX_IMPORT_TASK_TYPE} running",
        actor="ACUNETIX_DAST",
        stage_id=stage.stage_id,
        task_id=task.task_id,
        details={"scan_id": scan_id, "target_label": target_label},
    )
    return stage.stage_id, task.task_id


def _write_vulnerability_artifact(
    *,
    task_id: str,
    target_name: str,
    scan_id: str,
    result_id: str,
    content_hash: str,
    content: str,
) -> Path:
    COLLECTOR_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    artifact_name = (
        f"{task_id}_acunetix_{_sanitize_file_component(target_name)}_"
        f"{_sanitize_file_component(scan_id or 'scan')}_{_sanitize_file_component(result_id or 'live')}_"
        f"{content_hash[:12]}.json"
    )
    artifact_path = COLLECTOR_ARTIFACTS_DIR / artifact_name
    artifact_path.write_text(content, encoding="utf-8")
    return artifact_path


def _record_vulnerability_evidence(
    workflow_id: str,
    *,
    job_id: str,
    scope_id: str,
    task_id: str,
    target_name: str,
    scan_id: str,
    result_id: str,
    scan_status: str,
    vulnerabilities_payload: dict[str, Any],
) -> str | None:
    vulnerability_rows = _extract_vulnerability_rows(vulnerabilities_payload)
    return _record_vulnerability_rows_evidence(
        workflow_id=workflow_id,
        job_id=job_id,
        scope_id=scope_id,
        task_id=task_id,
        target_name=target_name,
        scan_id=scan_id,
        result_id=result_id,
        scan_status=scan_status,
        vulnerability_rows=vulnerability_rows,
    )


def _record_vulnerability_rows_evidence(
    workflow_id: str | None,
    *,
    job_id: str,
    scope_id: str,
    task_id: str,
    target_name: str,
    scan_id: str,
    result_id: str,
    scan_status: str,
    vulnerability_rows: list[dict[str, Any]],
) -> str | None:
    if not vulnerability_rows:
        return None

    vulnerability_content = _build_vulnerability_evidence_content(
        scan_id=scan_id,
        result_id=result_id,
        vulnerability_rows=vulnerability_rows,
    )
    if not vulnerability_content:
        return None

    serialized = json.dumps(vulnerability_content, indent=2, sort_keys=True)
    content_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    if workflow_id:
        with _WORKFLOWS_LOCK:
            workflow = _WORKFLOWS[workflow_id]
            if workflow.get("latest_vulnerability_hash") == content_hash:
                return None

    with get_session() as session:
        existing = session.exec(
            select(Evidence).where(
                Evidence.job_id == job_id,
                Evidence.task_id == task_id,
                Evidence.source == ACUNETIX_EVIDENCE_SOURCE,
                Evidence.kind == ACUNETIX_EVIDENCE_KIND,
                Evidence.content_hash == content_hash,
            )
        ).first()
        if existing:
            evidence_id = existing.evidence_id
        else:
            artifact_path = _write_vulnerability_artifact(
                task_id=task_id,
                target_name=target_name,
                scan_id=scan_id,
                result_id=result_id,
                content_hash=content_hash,
                content=serialized,
            )
            evidence = Evidence(
                evidence_id=make_id("evd"),
                scope_id=scope_id,
                job_id=job_id,
                task_id=task_id,
                kind=ACUNETIX_EVIDENCE_KIND,
                source=ACUNETIX_EVIDENCE_SOURCE,
                content_hash=content_hash,
                blob_ref=str(artifact_path),
            )
            task = session.exec(select(Task).where(Task.task_id == task_id)).first()
            job = session.exec(select(Job).where(Job.job_id == job_id)).first()
            if not task or not job:
                raise RuntimeError("Acunetix workflow task context disappeared while writing evidence")

            try:
                evidence_refs = json.loads(task.evidence_refs or "[]")
            except json.JSONDecodeError:
                evidence_refs = []
            if evidence.evidence_id not in evidence_refs:
                evidence_refs.append(evidence.evidence_id)
            task.evidence_refs = json.dumps(evidence_refs)
            job.evidence_total += 1
            job.updated_at = _utcnow()
            session.add(evidence)
            session.add(task)
            session.add(job)
            session.commit()
            evidence_id = evidence.evidence_id

    if workflow_id:
        _update_workflow(workflow_id, latest_vulnerability_hash=content_hash)
    orchestrator.log_event(
        job_id,
        scope_id,
        "EVIDENCE_INGESTED",
        "Acunetix vulnerability content recorded",
        actor="ACUNETIX_DAST",
        task_id=task_id,
        details={
            "workflow_id": workflow_id or "",
            "scan_id": scan_id,
            "result_id": result_id,
            "scan_status": scan_status,
            "evidence_id": evidence_id,
        },
    )
    return evidence_id


def _extract_pagination_cursor(vulns_payload: dict[str, Any], seen_cursors: set[str]) -> str:
    data = _extract_tool_data(vulns_payload)
    pagination = data.get("pagination") if isinstance(data.get("pagination"), dict) else {}
    cursors = pagination.get("cursors")
    if not isinstance(cursors, list):
        return ""
    for cursor in cursors:
        candidate = str(cursor or "").strip()
        if candidate and candidate not in seen_cursors:
            return candidate
    return ""


def _collect_all_vulnerability_rows(scan_id: str, result_id: str) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    seen_cursors: set[str] = set()
    cursor = ""

    for _ in range(200):
        arguments: dict[str, Any] = {
            "scan_id": scan_id,
            "result_id": result_id,
            "limit": ACUNETIX_VULNERABILITIES_PAGE_LIMIT,
        }
        if cursor:
            arguments["cursor"] = cursor
        vulnerabilities_payload = call_acunetix_mcp_tool("get_scan_vulnerabilities", arguments)
        rows = _extract_vulnerability_rows(vulnerabilities_payload)
        if rows:
            collected.extend(rows)
        next_cursor = _extract_pagination_cursor(vulnerabilities_payload, seen_cursors)
        if not next_cursor:
            break
        seen_cursors.add(next_cursor)
        cursor = next_cursor

    return collected


def _extract_scan_target_label(scan_id: str, scan_payload: dict[str, Any]) -> str:
    data = _extract_tool_data(scan_payload)
    target = data.get("target") if isinstance(data.get("target"), dict) else {}
    for candidate in (
        target.get("address"),
        target.get("description"),
        target.get("criticality"),
        data.get("target_url"),
        data.get("address"),
        data.get("description"),
        data.get("target_id"),
    ):
        text = str(candidate or "").strip()
        if text:
            return text
    return scan_id


def _finalize_import_task(job_id: str, scope_id: str, stage_id: str, task_id: str, *, succeeded: bool, error_message: str = "") -> None:
    with get_session() as session:
        task = session.exec(select(Task).where(Task.task_id == task_id)).first()
        stage = session.exec(select(Stage).where(Stage.stage_id == stage_id)).first()
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not task or not stage or not job:
            raise RuntimeError("Acunetix import task context missing")

        task.status = "SUCCEEDED" if succeeded else "FAILED"
        stage_tasks = session.exec(select(Task).where(Task.stage_id == stage_id)).all()
        if any(row.task_id != task_id and row.status == "RUNNING" for row in stage_tasks):
            stage.status = "RUNNING"
            stage.ended_at = None
        elif any((row.task_id != task_id and row.status == "FAILED") for row in stage_tasks) or not succeeded:
            stage.status = "FAILED"
            stage.ended_at = _utcnow()
        else:
            stage.status = "COMPLETED"
            stage.ended_at = _utcnow()
        job.updated_at = _utcnow()
        session.add(task)
        session.add(stage)
        session.add(job)
        session.commit()

    orchestrator.log_event(
        job_id,
        scope_id,
        "TASK_STATUS",
        f"Task {ACUNETIX_IMPORT_TASK_TYPE} {'succeeded' if succeeded else 'failed'}",
        actor="ACUNETIX_DAST",
        severity="INFO" if succeeded else "ERROR",
        stage_id=stage_id,
        task_id=task_id,
        details={"error": error_message} if error_message else {},
    )


def _recompute_stage_and_job_status(job_id: str, scope_id: str, stage_id: str, *, running_status: str | None = None) -> str:
    with get_session() as session:
        stage = session.exec(select(Stage).where(Stage.stage_id == stage_id)).first()
        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if not stage or not job:
            raise RuntimeError("Acunetix workflow stage or job context missing")

        stage_tasks = session.exec(select(Task).where(Task.stage_id == stage_id)).all()
        if any(task.status == "RUNNING" for task in stage_tasks):
            stage.status = "RUNNING"
            stage.ended_at = None
        elif any(task.status == "FAILED" for task in stage_tasks):
            stage.status = "FAILED"
            stage.ended_at = _utcnow()
        else:
            stage.status = "COMPLETED"
            stage.ended_at = _utcnow()

        job_tasks = session.exec(select(Task).where(Task.job_id == job_id)).all()
        if any(task.status == "RUNNING" for task in job_tasks):
            job.status = running_status or "RUNNING"
            job.current_stage = DAST_STAGE_NAME
        else:
            job.status = "FAILED" if any(task.status == "FAILED" for task in job_tasks) else "COMPLETED"
            job.current_stage = "DONE"
        job.updated_at = _utcnow()
        session.add(stage)
        session.add(job)
        session.commit()
        return job.status


def _finalize_workflow_task(
    workflow_id: str,
    *,
    job_id: str,
    scope_id: str,
    stage_id: str,
    task_id: str,
    succeeded: bool,
    rerun_job: bool,
    error_message: str = "",
) -> None:
    with get_session() as session:
        task = session.exec(select(Task).where(Task.task_id == task_id)).first()
        if not task:
            raise RuntimeError(f"Acunetix workflow task not found: {task_id}")
        task.status = "SUCCEEDED" if succeeded else "FAILED"
        session.add(task)
        session.commit()

    job_status = _recompute_stage_and_job_status(
        job_id,
        scope_id,
        stage_id,
        running_status="RERUNNING" if rerun_job else "RUNNING",
    )
    orchestrator.log_event(
        job_id,
        scope_id,
        "TASK_STATUS",
        f"Task {ACUNETIX_TASK_TYPE} {'succeeded' if succeeded else 'failed'}",
        actor="ACUNETIX_DAST",
        severity="INFO" if succeeded else "ERROR",
        stage_id=stage_id,
        task_id=task_id,
        details={"workflow_id": workflow_id, "error": error_message} if error_message else {"workflow_id": workflow_id},
    )
    orchestrator.log_event(
        job_id,
        scope_id,
        "JOB_STATUS",
        (
            "Job completed after Acunetix DAST"
            if job_status == "COMPLETED"
            else "Job failed during Acunetix DAST"
            if job_status == "FAILED"
            else "Job still running Acunetix DAST"
        ),
        actor="ACUNETIX_DAST",
        severity="INFO" if job_status != "FAILED" else "ERROR",
    )


def start_acunetix_scan_workflow(
    job_id: str,
    scope_id: str,
    *,
    target_name: str,
    target_address: str,
    target_label: str = "",
) -> dict[str, Any]:
    """Start one background Acunetix workflow or reconnect to the active one."""
    normalized_target_address = target_address.strip()
    if not normalized_target_address:
        normalized_target_address = f"https://{target_name}"
    normalized_target_label = target_label.strip() or normalized_target_address
    existing = _find_existing_active_workflow(job_id, normalized_target_address)
    if existing:
        return existing

    workflow_id = _new_workflow_id()
    stage_id, task_id, rerun_job = _create_workflow_task(
        workflow_id,
        job_id,
        scope_id,
        target_name=target_name,
        target_label=normalized_target_label,
        target_address=normalized_target_address,
    )
    now = _utcnow_iso()
    workflow = {
        "workflow_id": workflow_id,
        "job_id": job_id,
        "scope_id": scope_id,
        "stage_id": stage_id,
        "task_id": task_id,
        "rerun_job": rerun_job,
        "target_name": target_name,
        "target_label": normalized_target_label,
        "target_address": normalized_target_address,
        "status": "PENDING",
        "phase": "QUEUED",
        "message": "Acunetix workflow queued",
        "started_at": now,
        "updated_at": now,
        "completed_at": "",
        "target_id": "",
        "scan_id": "",
        "scan_status": "",
        "scan_progress": None,
        "result_id": "",
        "vulnerability_count": 0,
        "vulnerabilities_preview": [],
        "report_id": "",
        "report_status": "",
        "report_filename": "",
        "report_download_url": "",
        "report_artifact": "",
        "error": "",
        "latest_vulnerability_hash": "",
        "steps": [],
    }
    with _WORKFLOWS_LOCK:
        _WORKFLOWS[workflow_id] = workflow

    thread = threading.Thread(
        target=_run_acunetix_scan_workflow,
        args=(workflow_id,),
        name=f"acunetix-workflow-{workflow_id}",
        daemon=True,
    )
    thread.start()
    return _workflow_snapshot(workflow)


def get_acunetix_scan_workflow(job_id: str, workflow_id: str) -> dict[str, Any]:
    """Return one workflow snapshot scoped to the current job."""
    with _WORKFLOWS_LOCK:
        workflow = _WORKFLOWS.get(workflow_id)
        if not workflow or workflow["job_id"] != job_id:
            raise KeyError(workflow_id)
        return _workflow_snapshot(workflow)


def list_acunetix_scan_workflows(job_id: str) -> list[dict[str, Any]]:
    """Return all Acunetix workflows for one job ordered newest-first."""
    with _WORKFLOWS_LOCK:
        workflows = [
            _workflow_snapshot(workflow)
            for workflow in _WORKFLOWS.values()
            if workflow.get("job_id") == job_id
        ]
    workflows.sort(
        key=lambda workflow: (
            str(workflow.get("started_at") or ""),
            str(workflow.get("workflow_id") or ""),
        ),
        reverse=True,
    )
    return workflows


def import_acunetix_scan_to_job(job_id: str, scope_id: str, *, scan_id: str) -> dict[str, Any]:
    """Import vulnerability data from one existing Acunetix scan into the current job."""
    normalized_scan_id = scan_id.strip()
    if not normalized_scan_id:
        raise RuntimeError("scan_id is required")

    scan_payload = call_acunetix_mcp_tool("get_scan", {"scan_id": normalized_scan_id})
    target_label = _extract_scan_target_label(normalized_scan_id, scan_payload)
    stage_id, task_id = _create_import_task(
        job_id,
        scope_id,
        scan_id=normalized_scan_id,
        target_label=target_label,
    )

    try:
        handshake = initialize_acunetix_mcp()
        _validate_required_tool_names(
            handshake["tool_names"],
            (
                "get_scan",
                "get_scan_result_history",
                "get_scan_vulnerabilities",
                "get_scan_vulnerability_detail",
            ),
        )
        history_payload = call_acunetix_mcp_tool(
            "get_scan_result_history",
            {"scan_id": normalized_scan_id, "limit": ACUNETIX_RESULT_HISTORY_LIMIT},
        )
        result_id = _extract_result_id(history_payload)
        if not result_id:
            raise RuntimeError("Acunetix returned no scan result ID")

        vulnerability_rows = _collect_all_vulnerability_rows(normalized_scan_id, result_id)
        evidence_id = _record_vulnerability_rows_evidence(
            None,
            job_id=job_id,
            scope_id=scope_id,
            task_id=task_id,
            target_name=target_label,
            scan_id=normalized_scan_id,
            result_id=result_id,
            scan_status="imported",
            vulnerability_rows=vulnerability_rows,
        )
        _finalize_import_task(job_id, scope_id, stage_id, task_id, succeeded=True)
        return {
            "ok": True,
            "job_id": job_id,
            "task_id": task_id,
            "scan_id": normalized_scan_id,
            "result_id": result_id,
            "target_label": target_label,
            "vulnerability_count": len(vulnerability_rows),
            "evidence_id": evidence_id or "",
            "evidence_url": f"/jobs/{job_id}/evidence/{evidence_id}" if evidence_id else "",
            "task_evidence_url": f"/jobs/{job_id}/evidence?task_id={task_id}",
            "message": (
                f"Imported {len(vulnerability_rows)} vulnerabilities from scan {normalized_scan_id}"
                if vulnerability_rows
                else f"No vulnerabilities found for scan {normalized_scan_id}"
            ),
        }
    except Exception as exc:
        _finalize_import_task(job_id, scope_id, stage_id, task_id, succeeded=False, error_message=str(exc))
        raise


def get_acunetix_scan_report_path(job_id: str, workflow_id: str) -> Path:
    """Resolve the downloaded report artifact for one finished workflow."""
    workflow = get_acunetix_scan_workflow(job_id, workflow_id)
    raw_path = str(workflow.get("report_artifact") or "").strip()
    if not raw_path:
        raise FileNotFoundError(workflow_id)
    path = Path(raw_path)
    try:
        resolved = path.resolve()
        resolved.relative_to(REPORTS_DIR)
    except (OSError, ValueError) as exc:
        raise FileNotFoundError(workflow_id) from exc
    if not resolved.exists() or not resolved.is_file():
        raise FileNotFoundError(workflow_id)
    return resolved


def _run_acunetix_scan_workflow(workflow_id: str) -> None:
    with _WORKFLOWS_LOCK:
        workflow = _workflow_snapshot(_WORKFLOWS[workflow_id])
    job_id = workflow["job_id"]
    scope_id = workflow["scope_id"]
    stage_id = workflow["stage_id"]
    task_id = workflow["task_id"]
    rerun_job = bool(workflow.get("rerun_job"))
    target_name = workflow["target_name"]
    target_address = workflow["target_address"]

    try:
        _update_workflow(workflow_id, status="RUNNING", phase="INITIALIZING", message="Initializing Acunetix MCP")
        _append_step(workflow_id, "INITIALIZING", "Initializing Acunetix MCP", step_status="RUNNING")
        handshake = initialize_acunetix_mcp()
        available_tools = handshake["tool_names"]
        _validate_workflow_tool_names(available_tools)
        _append_step(
            workflow_id,
            "INITIALIZING",
            f"Acunetix MCP ready with {len(available_tools)} tools",
            step_status="COMPLETED",
        )

        _update_workflow(workflow_id, phase="ADD_TARGET", message=f"Creating target for {target_address}")
        _append_step(workflow_id, "ADD_TARGET", f"Creating target {target_address}", step_status="RUNNING")
        add_target_payload = call_acunetix_mcp_tool(
            "add_target",
            {
                "body": {
                    "address": target_address,
                    "description": f"GhostReconRev {job_id} / {target_name}",
                    "criticality": ACUNETIX_TARGET_CRITICALITY,
                }
            },
        )
        target_id = str(_find_first_by_key(_extract_tool_data(add_target_payload), "target_id") or "").strip()
        if not target_id:
            raise RuntimeError("Acunetix add_target returned no target_id")
        _update_workflow(workflow_id, target_id=target_id)
        _append_step(workflow_id, "ADD_TARGET", f"Target created ({target_id})", step_status="COMPLETED")

        _update_workflow(workflow_id, phase="CONFIGURE_TARGET", message="Applying Acunetix target configuration")
        _append_step(workflow_id, "CONFIGURE_TARGET", "Applying target configuration", step_status="RUNNING")
        call_acunetix_mcp_tool(
            "configure_target",
            {
                "target_id": target_id,
                "body": {
                    "scan_speed": ACUNETIX_TARGET_SCAN_SPEED,
                    # Keep the target default profile aligned with the scan profile to avoid split configuration.
                    "default_scanning_profile_id": ACUNETIX_DEFAULT_PROFILE_ID,
                    "user_agent": ACUNETIX_TARGET_USER_AGENT,
                    "case_sensitive": ACUNETIX_TARGET_CASE_SENSITIVE,
                    "proxy": {
                        "enabled": ACUNETIX_TARGET_PROXY_ENABLED,
                        "protocol": ACUNETIX_TARGET_PROXY_PROTOCOL,
                        "address": ACUNETIX_TARGET_PROXY_ADDRESS,
                        "port": ACUNETIX_TARGET_PROXY_PORT,
                    },
                },
            },
        )
        _append_step(workflow_id, "CONFIGURE_TARGET", "Target configuration applied", step_status="COMPLETED")

        _update_workflow(workflow_id, phase="LAUNCH_SCAN", message="Scheduling Acunetix scan")
        _append_step(workflow_id, "LAUNCH_SCAN", "Scheduling Full Scan", step_status="RUNNING")
        schedule_payload = call_acunetix_mcp_tool(
            "schedule_scan",
            {
                "body": {
                    "target_id": target_id,
                    "profile_id": ACUNETIX_DEFAULT_PROFILE_ID,
                    "report_template_id": ACUNETIX_DEFAULT_REPORT_TEMPLATE_ID,
                    "schedule": {
                        "disable": False,
                        "start_date": None,
                        "time_sensitive": False,
                    },
                }
            },
        )
        scan_id = str(_find_first_by_key(_extract_tool_data(schedule_payload), "scan_id") or "").strip()
        if not scan_id:
            raise RuntimeError("Acunetix schedule_scan returned no scan_id")
        _update_workflow(workflow_id, scan_id=scan_id, scan_status="scheduled")
        _append_step(workflow_id, "LAUNCH_SCAN", f"Scan scheduled ({scan_id})", step_status="COMPLETED")

        _update_workflow(workflow_id, phase="POLL_SCAN", message="Waiting for scan to complete")
        scan_deadline = time.monotonic() + max(ACUNETIX_SCAN_MAX_RUNTIME, 30)
        last_status = ""
        last_progress: int | None = None
        last_result_id = ""
        while True:
            scan_payload = call_acunetix_mcp_tool("get_scan", {"scan_id": scan_id})
            scan_status, scan_progress = _extract_scan_status(scan_payload)
            _update_workflow(
                workflow_id,
                scan_status=scan_status or "unknown",
                scan_progress=scan_progress,
                message=f"Scan status: {scan_status or 'unknown'}",
            )
            if scan_status != last_status or scan_progress != last_progress:
                progress_suffix = f" ({scan_progress}%)" if scan_progress is not None else ""
                _append_step(
                    workflow_id,
                    "POLL_SCAN",
                    f"Scan status: {scan_status or 'unknown'}{progress_suffix}",
                    step_status="INFO",
                )
                last_status = scan_status
                last_progress = scan_progress
            if scan_status and scan_status not in {"scheduled", "queued"}:
                try:
                    current_result_id = _refresh_vulnerabilities(
                        workflow_id,
                        job_id=job_id,
                        scope_id=scope_id,
                        task_id=task_id,
                        target_name=target_name,
                        scan_id=scan_id,
                        scan_status=scan_status,
                    )
                    if current_result_id and current_result_id != last_result_id:
                        _append_step(
                            workflow_id,
                            "FETCH_RESULTS",
                            f"Live vulnerabilities synced ({current_result_id})",
                            step_status="INFO",
                        )
                        last_result_id = current_result_id
                except Exception as exc:
                    _append_step(
                        workflow_id,
                        "FETCH_RESULTS",
                        f"Live vulnerability sync skipped: {exc}",
                        step_status="INFO",
                    )
            if scan_status in TERMINAL_SCAN_STATUSES:
                break
            if time.monotonic() >= scan_deadline:
                raise RuntimeError("Acunetix scan did not complete within 4 hours")
            time.sleep(max(ACUNETIX_SCAN_POLL_INTERVAL, 1))
        if scan_status in FAILED_SCAN_STATUSES:
            raise RuntimeError(f"Acunetix scan ended with status {scan_status}")
        _append_step(workflow_id, "POLL_SCAN", "Scan completed", step_status="COMPLETED")

        _update_workflow(workflow_id, phase="FETCH_RESULTS", message="Retrieving scan results")
        result_id = _refresh_vulnerabilities(
            workflow_id,
            job_id=job_id,
            scope_id=scope_id,
            task_id=task_id,
            target_name=target_name,
            scan_id=scan_id,
            scan_status=scan_status or "completed",
        )
        if not result_id:
            raise RuntimeError("Acunetix returned no scan result ID")
        _append_step(workflow_id, "FETCH_RESULTS", f"Latest result resolved ({result_id})", step_status="COMPLETED")
        workflow_snapshot = get_acunetix_scan_workflow(job_id, workflow_id)
        _append_step(
            workflow_id,
            "FETCH_RESULTS",
            f"Retrieved {workflow_snapshot.get('vulnerability_count', 0)} vulnerabilities",
            step_status="COMPLETED",
        )

        _update_workflow(workflow_id, phase="GENERATE_REPORT", message="Generating Acunetix report")
        _append_step(workflow_id, "GENERATE_REPORT", "Generating Developer report", step_status="RUNNING")
        report_payload = call_acunetix_mcp_tool(
            "generate_new_report",
            {
                "body": {
                    "template_id": ACUNETIX_DEFAULT_REPORT_TEMPLATE_ID,
                    "source": {
                        "list_type": "scans",
                        "id_list": [scan_id],
                    },
                }
            },
        )
        report_id = str(_find_first_by_key(_extract_tool_data(report_payload), "report_id") or "").strip()
        if not report_id:
            raise RuntimeError("Acunetix generate_new_report returned no report_id")
        _update_workflow(workflow_id, report_id=report_id, report_status="queued")
        _append_step(workflow_id, "GENERATE_REPORT", f"Report requested ({report_id})", step_status="COMPLETED")

        report_deadline = time.monotonic() + max(ACUNETIX_REPORT_TIMEOUT, 30)
        descriptor = ""
        while True:
            report_status_payload = call_acunetix_mcp_tool(
                "get_report",
                {"report_id": report_id},
            )
            report_data = _extract_tool_data(report_status_payload)
            report_status = str(report_data.get("status") or "").strip().lower()
            descriptor = _extract_download_descriptor(report_status_payload)
            _update_workflow(
                workflow_id,
                report_status=report_status or "unknown",
                message=f"Report status: {report_status or 'unknown'}",
            )
            if descriptor and report_status not in FAILED_REPORT_STATUSES:
                break
            if report_status in FAILED_REPORT_STATUSES:
                raise RuntimeError(f"Acunetix report generation failed with status {report_status}")
            if report_status in SUCCESSFUL_REPORT_STATUSES and descriptor:
                break
            if time.monotonic() >= report_deadline:
                raise RuntimeError("Timed out waiting for Acunetix report generation")
            time.sleep(max(ACUNETIX_REPORT_POLL_INTERVAL, 1))

        download_payload = call_acunetix_mcp_tool(
            "download_report",
            {"descriptor": descriptor},
        )
        report_path = _write_report_artifact(job_id, workflow_id, target_name, download_payload)
        _update_workflow(
            workflow_id,
            status="COMPLETED",
            phase="COMPLETED",
            completed_at=_utcnow_iso(),
            message="Acunetix scan workflow completed",
            report_artifact=str(report_path),
            report_filename=report_path.name,
            report_download_url=f"/jobs/{job_id}/dast/acunetix/workflows/{workflow_id}/report",
        )
        _append_step(workflow_id, "COMPLETED", f"Report downloaded ({report_path.name})", step_status="COMPLETED")
        try:
            _finalize_workflow_task(
                workflow_id,
                job_id=job_id,
                scope_id=scope_id,
                stage_id=stage_id,
                task_id=task_id,
                succeeded=True,
                rerun_job=rerun_job,
            )
        except Exception as finalize_exc:
            _append_step(workflow_id, "COMPLETED", f"Job/task finalization warning: {finalize_exc}", step_status="INFO")
    except Exception as exc:
        _update_workflow(
            workflow_id,
            status="FAILED",
            phase="FAILED",
            completed_at=_utcnow_iso(),
            message=str(exc),
            error=str(exc),
        )
        _append_step(workflow_id, "FAILED", str(exc), step_status="FAILED")
        try:
            _finalize_workflow_task(
                workflow_id,
                job_id=job_id,
                scope_id=scope_id,
                stage_id=stage_id,
                task_id=task_id,
                succeeded=False,
                rerun_job=rerun_job,
                error_message=str(exc),
            )
        except Exception as finalize_exc:
            _append_step(workflow_id, "FAILED", f"Job/task finalization warning: {finalize_exc}", step_status="INFO")
