from __future__ import annotations

"""Optional Telegram delivery for timeline events."""

import json
import queue
import threading
import urllib.parse
import urllib.request

from ..config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_TIMEOUT, TELEGRAM_TIMELINE_ENABLED


class TelegramTimelineNotifier:
    """Send timeline events to Telegram without blocking orchestration threads."""

    def __init__(self) -> None:
        self._enabled = bool(TELEGRAM_TIMELINE_ENABLED and TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)
        self._queue: queue.Queue[dict] = queue.Queue(maxsize=500)
        if self._enabled:
            threading.Thread(target=self._worker, daemon=True, name="telegram-timeline-notifier").start()

    def notify(self, event: dict) -> None:
        """Queue one event for Telegram delivery when the feature is enabled."""
        if not self._enabled:
            return
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                return

    def _worker(self) -> None:
        """Serialize and send queued events to Telegram."""
        while True:
            event = self._queue.get()
            try:
                self._send_message(self._format_message(event))
            except Exception:
                # Telegram delivery is optional; never break orchestration flow on notification errors.
                pass
            finally:
                self._queue.task_done()

    def _format_message(self, event: dict) -> str:
        """Render one concise Telegram message from a persisted event."""
        severity = str(event.get("severity", "")).upper()
        severity_icon = {
            "ERROR": "🔴",
            "WARNING": "🟠",
            "WARN": "🟠",
            "INFO": "🔵",
        }.get(severity, "⚪")
        event_icon = self._event_icon(str(event.get("event_type", "")), str(event.get("message", "")))
        parts = [
            f"{event_icon} GhostReconRev timeline event",
            f"🕒 Time: {event.get('timestamp', '')}",
            f"🧾 Job: {event.get('job_id', '')}",
            f"{severity_icon} Severity: {event.get('severity', '')}",
            f"📌 Type: {event.get('event_type', '')}",
        ]
        if event.get("stage_id"):
            parts.append(f"🧱 Stage: {event['stage_id']}")
        if event.get("task_id"):
            parts.append(f"⚙️ Task: {event['task_id']}")
        parts.append(f"💬 Message: {event.get('message', '')}")

        payload = event.get("payload") or {}
        if payload:
            details = json.dumps(payload, sort_keys=True, ensure_ascii=True)
            max_details = 3000
            if len(details) > max_details:
                details = f"{details[:max_details]}..."
            parts.append(f"🧠 Details: {details}")

        message = "\n".join(parts)
        max_message = 3800
        if len(message) > max_message:
            return f"{message[:max_message]}..."
        return message

    def _event_icon(self, event_type: str, message: str) -> str:
        """Choose one icon that matches the timeline event intent."""
        text = f"{event_type} {message}".lower()
        if "failed" in text or "error" in text:
            return "❌"
        if "running" in text:
            return "🏃"
        if "succeeded" in text or "completed" in text:
            return "✅"
        if "scheduled" in text or "proposed" in text or "planning" in text:
            return "🗂️"
        return "📡"

    def _send_message(self, message: str) -> None:
        """Post one message to the Telegram Bot API over HTTPS."""
        payload = urllib.parse.urlencode(
            {
                "chat_id": TELEGRAM_CHAT_ID,
                "text": message,
                "disable_web_page_preview": "true",
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            url=f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            data=payload,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "GhostReconRev/0.1",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=TELEGRAM_TIMEOUT) as response:
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname != "api.telegram.org":
                raise RuntimeError("Telegram redirect blocked")
            response.read()
