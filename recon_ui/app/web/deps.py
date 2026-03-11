from __future__ import annotations

"""Shared web-layer dependencies and lightweight globals."""

from datetime import datetime, timezone

from fastapi.templating import Jinja2Templates

from ..orchestrator import EventBus, Orchestrator


def _template_security_context(request):  # type: ignore[no-untyped-def]
    """Inject shared security context (for example CSRF token) in all templates."""
    return {"csrf_token": getattr(request.state, "csrf_token", "")}


# Server-rendered templates keep MVP simple and auditable.
templates = Jinja2Templates(directory="recon_ui/app/templates", context_processors=[_template_security_context])
# Shared event bus/orchestrator instances for in-process background runs.
event_bus = EventBus()
orchestrator = Orchestrator(event_bus=event_bus)


def utcnow_iso() -> str:
    """Generate UTC timestamp strings for UI status messages."""
    return datetime.now(timezone.utc).isoformat()
