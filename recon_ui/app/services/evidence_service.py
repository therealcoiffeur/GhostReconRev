from __future__ import annotations

"""Evidence helper functions for safe file access and entity linking."""

from pathlib import Path

from sqlmodel import col, select

from ..config import COLLECTOR_ARTIFACTS_DIR, ROOT_DIR
from ..db import Assertion, Entity, Evidence


def resolve_local_artifact(blob_ref: str) -> Path | None:
    """Resolve one local collector artifact path and reject anything outside the artifact directory."""
    if "://" in blob_ref and not blob_ref.startswith(("file://",)):
        return None

    normalized = blob_ref[7:] if blob_ref.startswith("file://") else blob_ref
    candidate = Path(normalized).expanduser()
    if not candidate.is_absolute():
        candidate = ROOT_DIR / candidate
    try:
        resolved = candidate.resolve()
    except OSError:
        return None

    try:
        resolved.relative_to(COLLECTOR_ARTIFACTS_DIR)
    except ValueError:
        return None

    if not resolved.exists() or not resolved.is_file():
        return None

    return resolved


def safe_read_raw_evidence(blob_ref: str) -> tuple[str | None, str]:
    """Return raw evidence text for local collector artifacts only."""
    resolved = resolve_local_artifact(blob_ref)
    if not resolved:
        if "://" in blob_ref and not blob_ref.startswith(("file://",)):
            return None, "Raw content unavailable for non-file evidence reference"
        return None, "Raw artifact file not found or not permitted"

    raw = resolved.read_text(encoding="utf-8", errors="replace")
    max_chars = 100_000
    if len(raw) > max_chars:
        return raw[:max_chars], f"Raw content truncated to {max_chars} characters"
    return raw, ""


def resolve_linked_entity(session, scope_id: str, evidence: Evidence, assertions: list[Assertion]) -> Entity | None:
    """Resolve linked entity from assertion subject IDs with blob_ref fallback."""
    subject_entity_ids: list[str] = []
    for assertion in assertions:
        if assertion.subject_entity_id and assertion.subject_entity_id not in subject_entity_ids:
            subject_entity_ids.append(assertion.subject_entity_id)

    entity = None
    if subject_entity_ids:
        entity = session.exec(
            select(Entity)
            .where(Entity.scope_id == scope_id)
            .where(col(Entity.entity_id).in_(subject_entity_ids))
            .order_by(col(Entity.last_seen).desc())
        ).first()

    if entity:
        return entity

    linked_hostname = evidence.blob_ref.split("/")[-1] if "/" in evidence.blob_ref else evidence.blob_ref
    return session.exec(select(Entity).where(Entity.scope_id == scope_id, Entity.canonical_name == linked_hostname)).first()
