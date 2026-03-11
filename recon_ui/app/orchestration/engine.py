from __future__ import annotations

"""Planner/executor orchestration with deterministic policy and audit logging."""

import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from sqlmodel import select

from ..config import ACTIVE_ENRICHMENT_ENABLED, COLLECTOR_MAX_WORKERS
from ..db import EventLog, Job, ScopePolicy, Stage, Task, get_session
from ..services.telegram_service import TelegramTimelineNotifier
from ..scope import ScopeRules, evaluate_scope
from .common import make_id, utcnow
from .event_bus import EventBus
from .planning import PlannerOutput, build_default_plan
from .task_runner import TaskRunner


class Orchestrator:
    """Coordinates planning, policy checks, execution, and event emission."""

    def __init__(self, event_bus: EventBus, telegram_notifier: TelegramTimelineNotifier | None = None):
        self.event_bus = event_bus
        self.task_runner = TaskRunner()
        self.telegram_notifier = telegram_notifier or TelegramTimelineNotifier()
        # Cache last event hash per job to avoid one DB lookup per emitted event.
        self._last_event_hash_cache: dict[str, str] = {}
        self._last_event_hash_lock = threading.Lock()

    def _last_event_hash(self, job_id: str) -> str | None:
        """Fetch latest event hash to maintain append-only hash chaining."""
        with self._last_event_hash_lock:
            cached = self._last_event_hash_cache.get(job_id)
        if cached:
            return cached
        with get_session() as session:
            row = session.exec(
                select(EventLog).where(EventLog.job_id == job_id).order_by(EventLog.timestamp.desc())
            ).first()
            event_hash = row.event_hash if row else None
        if event_hash:
            with self._last_event_hash_lock:
                self._last_event_hash_cache[job_id] = event_hash
        return event_hash

    def log_event(
        self,
        job_id: str,
        scope_id: str,
        event_type: str,
        message: str,
        severity: str = "INFO",
        actor: str = "SYSTEM",
        stage_id: str | None = None,
        task_id: str | None = None,
        details: dict | None = None,
    ) -> None:
        """Persist one audit event and publish it to the live SSE stream."""
        details = details or {}
        prev_hash = self._last_event_hash(job_id)
        raw = json.dumps(
            {
                "job_id": job_id,
                "scope_id": scope_id,
                "event_type": event_type,
                "message": message,
                "details": details,
                "prev": prev_hash,
                "ts": utcnow().isoformat(),
            },
            sort_keys=True,
        )
        event_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        event = EventLog(
            event_id=make_id("evt"),
            job_id=job_id,
            scope_id=scope_id,
            stage_id=stage_id,
            task_id=task_id,
            actor=actor,
            event_type=event_type,
            severity=severity,
            message=message,
            details=json.dumps(details),
            event_hash=event_hash,
            prev_event_hash=prev_hash,
        )
        with get_session() as session:
            session.add(event)
            session.commit()
            session.refresh(event)
            event_id = event.event_id
            event_ts = event.timestamp.isoformat()
            persisted_hash = event.event_hash

        # Keep hash-chain cache in sync with just-persisted event.
        with self._last_event_hash_lock:
            self._last_event_hash_cache[job_id] = persisted_hash

        timeline_event = {
            "event_id": event_id,
            "timestamp": event_ts,
            "job_id": job_id,
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "payload": details,
            "stage_id": stage_id,
            "task_id": task_id,
        }
        self.event_bus.publish(job_id, timeline_event)
        self.telegram_notifier.notify(timeline_event)

    def _read_scope_rules(self, scope_id: str) -> ScopeRules:
        """Load stored scope policy and compile runtime rules."""
        with get_session() as session:
            scope = session.exec(select(ScopePolicy).where(ScopePolicy.scope_id == scope_id)).one()
        return ScopeRules.from_lists(
            allow_exact=json.loads(scope.allow_exact),
            allow_suffixes=json.loads(scope.allow_suffixes),
            deny_exact=json.loads(scope.deny_exact),
            deny_suffixes=json.loads(scope.deny_suffixes),
            regex_deny=json.loads(scope.regex_deny),
        )

    def _build_plan_stub(self, job_id: str, scope_id: str, include_active: bool = False) -> list[PlannerOutput]:
        """Planner stub that emits passive seed, collectors, and post stages."""
        return build_default_plan(job_id, scope_id, include_active=include_active)

    def _upsert_stage(self, job_id: str, scope_id: str, name: str, order_idx: int) -> Stage:
        """Create a stage once per job, or return the existing one."""
        with get_session() as session:
            existing = session.exec(select(Stage).where(Stage.job_id == job_id, Stage.name == name)).first()
            if existing:
                return existing
            stage = Stage(
                stage_id=make_id("stg"),
                job_id=job_id,
                scope_id=scope_id,
                name=name,
                order_idx=order_idx,
                status="READY",
            )
            session.add(stage)
            session.commit()
            session.refresh(stage)
            return stage

    def _get_scope_root(self, scope_id: str) -> str:
        """Return persisted root domain for the scope."""
        return self.task_runner.get_scope_root(scope_id)

    def _parse_dnsx_recon_output(self, raw_output: str, expected_host: str) -> list[dict[str, str]]:
        """Compatibility wrapper used by parser-focused tests."""
        return self.task_runner.parse_dnsx_recon_output(raw_output, expected_host)

    def _classify_dnsx_resolution(
        self,
        expected_host: str,
        raw_output: str,
        command_succeeded: bool,
    ) -> tuple[str, list[dict[str, str]], list[str]]:
        """Compatibility wrapper used by parser-focused tests."""
        return self.task_runner.classify_dnsx_resolution(expected_host, raw_output, command_succeeded)

    def plan_job(self, job_id: str) -> None:
        """Plan phase: propose tasks, enforce scope/policy, and schedule."""
        with get_session() as session:
            job = session.exec(select(Job).where(Job.job_id == job_id)).one()
            job.status = "PLANNING"
            job.updated_at = utcnow()
            session.add(job)
            session.commit()
            scope_id = job.scope_id
            include_active = bool(ACTIVE_ENRICHMENT_ENABLED and job.mode == "APPROVAL_GATED_ACTIVE")

        # Planning is deterministic and based on persisted job mode, not on free-form model output.
        self.log_event(job_id, scope_id, "JOB_STATUS", "Job entered planning", actor="ORCHESTRATOR")
        proposals = self._build_plan_stub(job_id, scope_id, include_active=include_active)
        rules = self._read_scope_rules(scope_id)
        sample_host = self._get_scope_root(scope_id)
        sample_allowed = evaluate_scope(sample_host, rules).allowed

        for idx, proposal in enumerate(proposals):
            stage = self._upsert_stage(job_id, scope_id, proposal.stage_name, idx)
            status = "VALIDATED"
            if not sample_allowed:
                status = "REJECTED_POLICY"

            with get_session() as session:
                # Persist every proposed task so reviewers can see what was considered, even if rejected.
                task = Task(
                    task_id=make_id("tsk"),
                    job_id=job_id,
                    stage_id=stage.stage_id,
                    scope_id=scope_id,
                    task_type=proposal.task_type,
                    status=status,
                    tier=proposal.tier,
                    approval_level=proposal.approval_level,
                    planner_source=proposal.planner_source,
                    input_payload=json.dumps(proposal.inputs or {}),
                )
                session.add(task)
                if status == "REJECTED_POLICY":
                    job_row = session.exec(select(Job).where(Job.job_id == job_id)).one()
                    job_row.policy_denials += 1
                    job_row.updated_at = utcnow()
                    session.add(job_row)
                session.commit()

            self.log_event(
                job_id,
                scope_id,
                "TASK_PROPOSED",
                f"Task {proposal.task_type} -> {status}",
                actor="PLANNER",
                stage_id=stage.stage_id,
                details={"tier": proposal.tier, "status": status, "approval_level": proposal.approval_level},
            )

        with get_session() as session:
            job = session.exec(select(Job).where(Job.job_id == job_id)).one()
            job.status = "SCHEDULED"
            job.updated_at = utcnow()
            session.add(job)
            session.commit()

        self.log_event(job_id, scope_id, "JOB_STATUS", "Job scheduled", actor="ORCHESTRATOR")

    def execute_job(self, job_id: str) -> None:
        """Execution phase: run validated tasks and finalize job state."""
        with get_session() as session:
            job = session.exec(select(Job).where(Job.job_id == job_id)).one()
            job.status = "RUNNING"
            job.updated_at = utcnow()
            session.add(job)
            session.commit()
            scope_id = job.scope_id

        self.log_event(job_id, scope_id, "JOB_STATUS", "Job running", actor="ORCHESTRATOR")
        scope_root = self._get_scope_root(scope_id)
        rules = self._read_scope_rules(scope_id)

        with get_session() as session:
            stages = session.exec(select(Stage).where(Stage.job_id == job_id).order_by(Stage.order_idx)).all()

        had_failures = False
        for stage in stages:
            with get_session() as session:
                stage_tasks = session.exec(
                    select(Task)
                    .where(Task.job_id == job_id, Task.stage_id == stage.stage_id, Task.status == "VALIDATED")
                    .order_by(Task.created_at)
                ).all()
            if not stage_tasks:
                continue

            # Only passive collection and lightweight enrichments run in parallel at the stage level.
            parallel_mode = stage.name in {"PASSIVE_COLLECT", "ENRICH"}

            def _run_single_task(task: Task) -> tuple[Task, tuple[int, int, int, int] | None, Exception | None]:
                with get_session() as session:
                    task_db = session.exec(select(Task).where(Task.task_id == task.task_id)).one()
                    task_db.status = "RUNNING"
                    session.add(task_db)
                    session.commit()

                self.log_event(
                    job_id,
                    scope_id,
                    "TASK_STATUS",
                    f"Task {task.task_type} running",
                    stage_id=task.stage_id,
                    task_id=task.task_id,
                )
                try:
                    result = self.task_runner.run_task(task, scope_root, rules)
                    return task, result, None
                except Exception as exc:
                    return task, None, exc

            outcomes: list[tuple[Task, tuple[int, int, int, int] | None, Exception | None]] = []
            if parallel_mode:
                # Bound worker count deterministically so one stage cannot exhaust local resources.
                workers = min(max(1, COLLECTOR_MAX_WORKERS), max(1, len(stage_tasks)))
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = [pool.submit(_run_single_task, task) for task in stage_tasks]
                    for future in as_completed(futures):
                        outcomes.append(future.result())
            else:
                for task in stage_tasks:
                    outcomes.append(_run_single_task(task))

            # Update counters only after each task settles so job metrics stay monotonic and auditable.
            for task, result, error in outcomes:
                if error is not None:
                    had_failures = True
                    with get_session() as session:
                        task_db = session.exec(select(Task).where(Task.task_id == task.task_id)).one()
                        task_db.status = "FAILED"
                        session.add(task_db)
                        session.commit()
                    self.log_event(
                        job_id,
                        scope_id,
                        "TASK_STATUS",
                        f"Task {task.task_type} failed",
                        severity="ERROR",
                        stage_id=task.stage_id,
                        task_id=task.task_id,
                        details={"error": f"{type(error).__name__}: {error}"},
                    )
                    continue

                entities_delta, evidence_delta, assertions_delta, blocked_out_of_scope = result
                with get_session() as session:
                    task_db = session.exec(select(Task).where(Task.task_id == task.task_id)).one()
                    job_db = session.exec(select(Job).where(Job.job_id == job_id)).one()
                    task_db.status = "SUCCEEDED"
                    job_db.entities_total += entities_delta
                    job_db.evidence_total += evidence_delta
                    job_db.assertions_total += assertions_delta
                    job_db.out_of_scope_blocked += blocked_out_of_scope
                    job_db.current_stage = task.task_type
                    job_db.updated_at = utcnow()
                    session.add(task_db)
                    session.add(job_db)
                    session.commit()

                self.log_event(
                    job_id,
                    scope_id,
                    "TASK_STATUS",
                    f"Task {task.task_type} succeeded",
                    stage_id=task.stage_id,
                    task_id=task.task_id,
                    details={
                        "entities_delta": entities_delta,
                        "evidence_delta": evidence_delta,
                        "assertions_delta": assertions_delta,
                        "out_of_scope_blocked_delta": blocked_out_of_scope,
                    },
                )

        with get_session() as session:
            failed_stage_ids = {
                row.stage_id
                for row in session.exec(select(Task).where(Task.job_id == job_id, Task.status == "FAILED")).all()
            }
            stages = session.exec(select(Stage).where(Stage.job_id == job_id)).all()
            for stg in stages:
                stg.status = "FAILED" if stg.stage_id in failed_stage_ids else "COMPLETED"
                stg.ended_at = utcnow()
                session.add(stg)

            job = session.exec(select(Job).where(Job.job_id == job_id)).one()
            job.status = "FAILED" if had_failures else "COMPLETED"
            job.current_stage = "DONE"
            job.updated_at = utcnow()
            session.add(job)
            session.commit()

        if had_failures:
            self.log_event(
                job_id,
                scope_id,
                "JOB_STATUS",
                "Job completed with failures",
                severity="ERROR",
                actor="ORCHESTRATOR",
            )
        else:
            self.log_event(job_id, scope_id, "JOB_STATUS", "Job completed", actor="ORCHESTRATOR")

    def start_job_async(self, job_id: str) -> None:
        """Run plan+execute in a daemon thread so HTTP request returns quickly."""

        def _runner() -> None:
            self.plan_job(job_id)
            self.execute_job(job_id)

        threading.Thread(target=_runner, daemon=True).start()
