from __future__ import annotations

"""Database models and session utilities for the local recon UI template."""

from contextlib import contextmanager
from datetime import datetime, timezone
import os
from typing import Optional

from sqlmodel import Field, Session, SQLModel, create_engine


def utcnow() -> datetime:
    """Return timezone-aware UTC timestamps for all persisted records."""
    return datetime.now(timezone.utc)


class ScopePolicy(SQLModel, table=True):
    """Deterministic scope policy with allow/deny lists for host evaluation."""

    # Surrogate integer key for SQLite performance and joins.
    id: Optional[int] = Field(default=None, primary_key=True)
    # Stable external identifier referenced by jobs/tasks/events.
    scope_id: str = Field(index=True, unique=True)
    # Root domain entered by the operator at run start.
    root_domain: str = Field(index=True)
    # JSON-encoded policy lists (kept as strings for lightweight MVP schema).
    allow_exact: str = Field(default="")
    allow_suffixes: str = Field(default="")
    deny_exact: str = Field(default="")
    deny_suffixes: str = Field(default="")
    regex_deny: str = Field(default="")
    created_at: datetime = Field(default_factory=utcnow)


class Job(SQLModel, table=True):
    """Top-level pipeline run metadata and aggregate counters."""

    id: Optional[int] = Field(default=None, primary_key=True)
    job_id: str = Field(index=True, unique=True)
    scope_id: str = Field(index=True)
    # High-level state machine status for UI and orchestration.
    status: str = Field(default="CREATED", index=True)
    # Safety mode: passive-only by default.
    mode: str = Field(default="PASSIVE_ONLY")
    # Approval requirement level (future active tier).
    approval_level: str = Field(default="NONE")
    current_stage: str = Field(default="SEED")
    # Counters used by the live metrics panel.
    entities_total: int = Field(default=0)
    evidence_total: int = Field(default=0)
    assertions_total: int = Field(default=0)
    policy_denials: int = Field(default=0)
    out_of_scope_blocked: int = Field(default=0)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class Stage(SQLModel, table=True):
    """Pipeline stage records (seed, collect, normalize, plan, etc.)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    stage_id: str = Field(index=True, unique=True)
    job_id: str = Field(index=True)
    scope_id: str = Field(index=True)
    name: str = Field(index=True)
    # Deterministic order in which stages are displayed/executed.
    order_idx: int = Field(index=True)
    tier: str = Field(default="PASSIVE")
    status: str = Field(default="PENDING", index=True)
    started_at: datetime = Field(default_factory=utcnow)
    ended_at: Optional[datetime] = None


class Task(SQLModel, table=True):
    """Concrete unit of work proposed by planner and executed by workers."""

    id: Optional[int] = Field(default=None, primary_key=True)
    task_id: str = Field(index=True, unique=True)
    job_id: str = Field(index=True)
    stage_id: str = Field(index=True)
    scope_id: str = Field(index=True)
    task_type: str = Field(index=True)
    status: str = Field(default="PROPOSED", index=True)
    tier: str = Field(default="PASSIVE")
    planner_source: str = Field(default="RULE_ENGINE")
    approval_level: str = Field(default="NONE")
    approval_ref: Optional[str] = None
    input_payload: str = Field(default="{}")
    evidence_refs: str = Field(default="[]")
    entity_refs: str = Field(default="[]")
    created_at: datetime = Field(default_factory=utcnow)


class EventLog(SQLModel, table=True):
    """Append-only audit/event stream for timeline and traceability."""

    id: Optional[int] = Field(default=None, primary_key=True)
    event_id: str = Field(index=True, unique=True)
    timestamp: datetime = Field(default_factory=utcnow, index=True)
    job_id: str = Field(index=True)
    scope_id: str = Field(index=True)
    stage_id: Optional[str] = Field(default=None, index=True)
    task_id: Optional[str] = Field(default=None, index=True)
    actor: str = Field(default="SYSTEM")
    event_type: str = Field(index=True)
    severity: str = Field(default="INFO")
    message: str
    details: str = Field(default="{}")
    event_hash: str
    prev_event_hash: Optional[str] = None


class Entity(SQLModel, table=True):
    """Asset graph node (domain/hostname/ip/url/service) discovered in run."""

    id: Optional[int] = Field(default=None, primary_key=True)
    entity_id: str = Field(index=True, unique=True)
    scope_id: str = Field(index=True)
    entity_type: str = Field(index=True)
    canonical_name: str = Field(index=True)
    display_name: str
    status: str = Field(default="NEW")
    tags: str = Field(default="[]")
    resolution_status: Optional[str] = Field(default="UNRESOLVED", index=True)
    resolution_checked_at: Optional[datetime] = None
    resolution_source: Optional[str] = None
    resolution_artifact: Optional[str] = None
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)


class Evidence(SQLModel, table=True):
    """Immutable evidence object with provenance to task and source."""

    id: Optional[int] = Field(default=None, primary_key=True)
    evidence_id: str = Field(index=True, unique=True)
    scope_id: str = Field(index=True)
    job_id: str = Field(index=True)
    task_id: str = Field(index=True)
    kind: str = Field(index=True)
    source: str
    collector_version: str = Field(default="0.1.0")
    collected_at: datetime = Field(default_factory=utcnow)
    content_hash: str
    blob_ref: str
    schema_version: str = Field(default="1.0")


class Assertion(SQLModel, table=True):
    """Claim derived from evidence and linked to one or more entities."""

    id: Optional[int] = Field(default=None, primary_key=True)
    assertion_id: str = Field(index=True, unique=True)
    scope_id: str = Field(index=True)
    subject_entity_id: str = Field(index=True)
    predicate: str = Field(index=True)
    object_entity_id: Optional[str] = Field(default=None, index=True)
    value: Optional[str] = None
    status: str = Field(default="PROPOSED")
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    evidence_refs: str = Field(default="[]")
    created_at: datetime = Field(default_factory=utcnow)


class OutOfScopeBlocked(SQLModel, table=True):
    """Hostnames rejected by deterministic scope policy during collection."""

    id: Optional[int] = Field(default=None, primary_key=True)
    block_id: str = Field(index=True, unique=True)
    job_id: str = Field(index=True)
    scope_id: str = Field(index=True)
    task_id: str = Field(index=True)
    source: str = Field(index=True)
    hostname: str = Field(index=True)
    reason: str = Field(index=True)
    created_at: datetime = Field(default_factory=utcnow, index=True)


DB_PATH = os.getenv("DATABASE_URL", "sqlite:///./recon_ui.db").strip() or "sqlite:///./recon_ui.db"
# Local SQLite engine for rapid prototyping and single-process execution.
engine = create_engine(DB_PATH, echo=False, connect_args={"check_same_thread": False})


def init_db() -> None:
    """Create all tables if they do not exist."""
    SQLModel.metadata.create_all(engine)
    _migrate_sqlite_schema()


def _migrate_sqlite_schema() -> None:
    """Apply lightweight additive migrations for existing local SQLite DBs."""
    with engine.begin() as conn:
        rows = conn.exec_driver_sql("PRAGMA table_info(entity)").fetchall()
        existing_cols = {row[1] for row in rows}
        add_columns = []
        if "resolution_status" not in existing_cols:
            add_columns.append("ALTER TABLE entity ADD COLUMN resolution_status TEXT")
        if "resolution_checked_at" not in existing_cols:
            add_columns.append("ALTER TABLE entity ADD COLUMN resolution_checked_at TIMESTAMP")
        if "resolution_source" not in existing_cols:
            add_columns.append("ALTER TABLE entity ADD COLUMN resolution_source TEXT")
        if "resolution_artifact" not in existing_cols:
            add_columns.append("ALTER TABLE entity ADD COLUMN resolution_artifact TEXT")
        for ddl in add_columns:
            conn.exec_driver_sql(ddl)

        # Remove legacy assertion.confidence column now that confidence scoring is deprecated.
        assertion_rows = conn.exec_driver_sql("PRAGMA table_info(assertion)").fetchall()
        assertion_cols = {row[1] for row in assertion_rows}
        if assertion_rows and "confidence" in assertion_cols:
            conn.exec_driver_sql(
                """
                CREATE TABLE assertion_new (
                    id INTEGER NOT NULL,
                    assertion_id VARCHAR NOT NULL,
                    scope_id VARCHAR NOT NULL,
                    subject_entity_id VARCHAR NOT NULL,
                    predicate VARCHAR NOT NULL,
                    object_entity_id VARCHAR,
                    value VARCHAR,
                    status VARCHAR NOT NULL,
                    valid_from DATETIME,
                    valid_to DATETIME,
                    evidence_refs VARCHAR NOT NULL,
                    created_at DATETIME NOT NULL,
                    PRIMARY KEY (id)
                )
                """
            )
            conn.exec_driver_sql(
                """
                INSERT INTO assertion_new (
                    id, assertion_id, scope_id, subject_entity_id, predicate, object_entity_id,
                    value, status, valid_from, valid_to, evidence_refs, created_at
                )
                SELECT
                    id, assertion_id, scope_id, subject_entity_id, predicate, object_entity_id,
                    value, status, valid_from, valid_to, evidence_refs, created_at
                FROM assertion
                """
            )
            conn.exec_driver_sql("DROP TABLE assertion")
            conn.exec_driver_sql("ALTER TABLE assertion_new RENAME TO assertion")
            conn.exec_driver_sql(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_assertion_assertion_id ON assertion (assertion_id)"
            )
            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_assertion_scope_id ON assertion (scope_id)"
            )
            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_assertion_subject_entity_id ON assertion (subject_entity_id)"
            )
            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_assertion_predicate ON assertion (predicate)"
            )
            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_assertion_object_entity_id ON assertion (object_entity_id)"
            )

        # Remove legacy job.created_by column (single-operator deployment).
        job_rows = conn.exec_driver_sql("PRAGMA table_info(job)").fetchall()
        job_cols = {row[1] for row in job_rows}
        if job_rows and "created_by" in job_cols:
            conn.exec_driver_sql(
                """
                CREATE TABLE job_new (
                    id INTEGER NOT NULL,
                    job_id VARCHAR NOT NULL,
                    scope_id VARCHAR NOT NULL,
                    status VARCHAR NOT NULL,
                    mode VARCHAR NOT NULL,
                    approval_level VARCHAR NOT NULL,
                    current_stage VARCHAR NOT NULL,
                    entities_total INTEGER NOT NULL,
                    evidence_total INTEGER NOT NULL,
                    assertions_total INTEGER NOT NULL,
                    policy_denials INTEGER NOT NULL,
                    out_of_scope_blocked INTEGER NOT NULL,
                    created_at DATETIME NOT NULL,
                    updated_at DATETIME NOT NULL,
                    PRIMARY KEY (id)
                )
                """
            )
            conn.exec_driver_sql(
                """
                INSERT INTO job_new (
                    id, job_id, scope_id, status, mode, approval_level, current_stage,
                    entities_total, evidence_total, assertions_total, policy_denials, out_of_scope_blocked,
                    created_at, updated_at
                )
                SELECT
                    id, job_id, scope_id, status, mode, approval_level, current_stage,
                    entities_total, evidence_total, assertions_total, policy_denials, out_of_scope_blocked,
                    created_at, updated_at
                FROM job
                """
            )
            conn.exec_driver_sql("DROP TABLE job")
            conn.exec_driver_sql("ALTER TABLE job_new RENAME TO job")
            conn.exec_driver_sql(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_job_job_id ON job (job_id)"
            )
            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_job_scope_id ON job (scope_id)"
            )
            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_job_status ON job (status)"
            )

        # Remove legacy evidence.trust_level column.
        evidence_rows = conn.exec_driver_sql("PRAGMA table_info(evidence)").fetchall()
        evidence_cols = {row[1] for row in evidence_rows}
        if evidence_rows and "trust_level" in evidence_cols:
            conn.exec_driver_sql(
                """
                CREATE TABLE evidence_new (
                    id INTEGER NOT NULL,
                    evidence_id VARCHAR NOT NULL,
                    scope_id VARCHAR NOT NULL,
                    job_id VARCHAR NOT NULL,
                    task_id VARCHAR NOT NULL,
                    kind VARCHAR NOT NULL,
                    source VARCHAR NOT NULL,
                    collector_version VARCHAR NOT NULL,
                    collected_at DATETIME NOT NULL,
                    content_hash VARCHAR NOT NULL,
                    blob_ref VARCHAR NOT NULL,
                    schema_version VARCHAR NOT NULL,
                    PRIMARY KEY (id)
                )
                """
            )
            conn.exec_driver_sql(
                """
                INSERT INTO evidence_new (
                    id, evidence_id, scope_id, job_id, task_id, kind, source,
                    collector_version, collected_at, content_hash, blob_ref, schema_version
                )
                SELECT
                    id, evidence_id, scope_id, job_id, task_id, kind, source,
                    collector_version, collected_at, content_hash, blob_ref, schema_version
                FROM evidence
                """
            )
            conn.exec_driver_sql("DROP TABLE evidence")
            conn.exec_driver_sql("ALTER TABLE evidence_new RENAME TO evidence")
            conn.exec_driver_sql(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_evidence_evidence_id ON evidence (evidence_id)"
            )
            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_evidence_scope_id ON evidence (scope_id)"
            )
            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_evidence_job_id ON evidence (job_id)"
            )
            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_evidence_task_id ON evidence (task_id)"
            )
            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_evidence_kind ON evidence (kind)"
            )

        # Normalize legacy planner/event labels to orchestration-centric terminology.
        conn.exec_driver_sql("UPDATE task SET planner_source = 'RULE_ENGINE' WHERE planner_source = 'AI'")
        conn.exec_driver_sql("UPDATE eventlog SET actor = 'PLANNER' WHERE actor = 'AI_PLANNER'")


@contextmanager
def get_session() -> Session:
    """Yield DB sessions with commit-safe object access after flush/commit."""
    with Session(engine, expire_on_commit=False) as session:
        yield session
