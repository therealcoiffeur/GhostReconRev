from __future__ import annotations

"""In-memory event bus used by orchestration and SSE endpoints."""

import queue
import threading


class EventBus:
    """In-memory pub/sub bus that feeds job events to SSE clients."""

    def __init__(self) -> None:
        self._subs: dict[str, list[queue.Queue]] = {}
        self._lock = threading.Lock()

    def subscribe(self, job_id: str) -> queue.Queue:
        """Attach a subscriber queue to one job event stream."""
        q: queue.Queue = queue.Queue(maxsize=500)
        with self._lock:
            self._subs.setdefault(job_id, []).append(q)
        return q

    def unsubscribe(self, job_id: str, q: queue.Queue) -> None:
        """Detach a subscriber queue when a client disconnects."""
        with self._lock:
            if job_id in self._subs and q in self._subs[job_id]:
                self._subs[job_id].remove(q)
                if not self._subs[job_id]:
                    del self._subs[job_id]

    def publish(self, job_id: str, event: dict) -> None:
        """Broadcast an event to all listeners for the specified job."""
        # Copy subscribers under lock, then publish outside lock to reduce contention.
        with self._lock:
            subscribers = list(self._subs.get(job_id, []))

        for q in subscribers:
            try:
                q.put_nowait(event)
            except queue.Full:
                # Drop oldest event to prevent one slow client from unbounded memory growth.
                try:
                    q.get_nowait()
                except queue.Empty:
                    pass
                try:
                    q.put_nowait(event)
                except queue.Full:
                    # If queue is still full, skip this publish for that subscriber.
                    continue
