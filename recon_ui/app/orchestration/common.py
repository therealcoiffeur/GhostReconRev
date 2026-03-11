from __future__ import annotations

"""Shared orchestration helpers used across engine modules."""

from datetime import datetime, timezone
from typing import Callable
from uuid import uuid4

from sqlmodel import select

from ..db import Job, get_session


def utcnow() -> datetime:
    """Return timezone-aware UTC timestamps for orchestration records."""
    return datetime.now(timezone.utc)


def make_id(prefix: str) -> str:
    """Generate short readable IDs for jobs/stages/tasks/events/entities."""
    return f"{prefix}_{uuid4().hex[:12]}"


def sanitize_evidence_for_planner(input_text: str) -> str:
    """Redact instruction-like substrings from untrusted evidence text."""
    # Keep the sanitizer simple and deterministic because it protects planning prompts, not display output.
    blocked = ["ignore previous instructions", "run this command", "exfiltrate"]
    text = input_text[:500]
    lowered = text.lower()
    for phrase in blocked:
        lowered = lowered.replace(phrase, "[redacted]")
    return lowered


def generate_scope_id() -> str:
    """Create external scope identifier."""
    return make_id("scp")


def generate_job_id() -> str:
    """Create external job identifier."""
    return make_id("job")


def list_jobs(session_provider: Callable = get_session) -> list[Job]:
    """Return all jobs sorted newest-first."""
    with session_provider() as session:
        return session.exec(select(Job).order_by(Job.created_at.desc())).all()
