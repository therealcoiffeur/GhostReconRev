from __future__ import annotations

"""Pydantic request/response contracts used by API and planner boundaries."""

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    """Base schema that rejects undeclared fields for deterministic validation."""

    model_config = ConfigDict(extra="forbid")


class ScopePolicyCreate(StrictModel):
    """Payload for creating scope policy objects."""

    root_domain: str
    allow_exact: list[str] = Field(default_factory=list)
    allow_suffixes: list[str] = Field(default_factory=list)
    deny_exact: list[str] = Field(default_factory=list)
    deny_suffixes: list[str] = Field(default_factory=list)
    regex_deny: list[str] = Field(default_factory=list)


class JobCreate(StrictModel):
    """Payload for creating a new pipeline run."""

    root_domain: str
    mode: Literal["PASSIVE_ONLY", "APPROVAL_GATED_ACTIVE"] = "PASSIVE_ONLY"


class TaskProposal(StrictModel):
    """Schema-constrained planner output that orchestrator can validate."""

    task_id: str
    job_id: str
    stage_id: str
    scope_id: str
    type: str
    tier: Literal["PASSIVE", "ACTIVE"]
    approval_level: Literal["NONE", "HUMAN_REQUIRED", "DUAL_CONTROL"] = "NONE"
    planner_source: Literal["RULE_ENGINE", "HUMAN"]
    inputs: dict[str, Any] = Field(default_factory=dict)


class EventEnvelope(StrictModel):
    """SSE-safe event shape emitted to live clients."""

    event_id: str
    timestamp: datetime
    job_id: str
    event_type: str
    severity: str
    message: str
    payload: dict[str, Any] = Field(default_factory=dict)


class JobSummary(StrictModel):
    """Compact job summary used by list/history endpoints."""

    job_id: str
    scope_id: str
    status: str
    current_stage: str
    entities_total: int
    evidence_total: int
    assertions_total: int
    policy_denials: int
    out_of_scope_blocked: int
    created_at: datetime
    updated_at: datetime


class JobDetail(JobSummary):
    """Expanded job payload including mode and approval metadata."""

    mode: str
    approval_level: str


class StageView(StrictModel):
    """Presentation model for stage rows in job detail page."""

    stage_id: str
    name: str
    order_idx: int
    status: str
    tier: str
    started_at: datetime
    ended_at: Optional[datetime] = None


class TaskView(StrictModel):
    """Presentation model for task rows in job detail page."""

    task_id: str
    stage_id: str
    task_type: str
    status: str
    tier: str
    planner_source: str
    created_at: datetime
