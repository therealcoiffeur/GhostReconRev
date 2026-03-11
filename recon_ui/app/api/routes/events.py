from __future__ import annotations

"""SSE event streaming endpoints."""

import json
import queue

from fastapi import APIRouter, Path
from fastapi.responses import StreamingResponse

from ...web.deps import event_bus

router = APIRouter()

JOB_ID_PATTERN = r"^job_[0-9a-f]{12}$"


@router.get("/api/jobs/{job_id}/events")
def stream_job_events(job_id: str = Path(..., pattern=JOB_ID_PATTERN)) -> StreamingResponse:
    """Stream timeline events via SSE so the UI updates in real time."""

    def event_gen() -> str:
        """Yield timeline events and periodic keepalives for one job stream."""
        q = event_bus.subscribe(job_id)
        try:
            while True:
                try:
                    item = q.get(timeout=15)
                    yield f"data: {json.dumps(item)}\\n\\n"
                except queue.Empty:
                    # Keep intermediaries and browsers from considering the stream idle.
                    yield "event: keepalive\\ndata: {}\\n\\n"
        finally:
            # Always detach the subscriber queue so disconnected clients do not leak memory.
            event_bus.unsubscribe(job_id, q)

    response = StreamingResponse(event_gen(), media_type="text/event-stream")
    # Disable proxy buffering and caching so the browser sees updates immediately.
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Accel-Buffering"] = "no"
    return response
