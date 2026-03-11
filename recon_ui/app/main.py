from __future__ import annotations

"""FastAPI entrypoint for safe-by-default recon pipeline demo UI/API."""

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api.routes import evidence, events, reports, runs
from .config import (
    APP_AUTH_PASSWORD,
    APP_AUTH_USERNAME,
    APP_REQUIRE_AUTH,
    ROOT_DIR,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
    TELEGRAM_TIMELINE_ENABLED,
)
from .db import init_db
from .web.security import apply_security_headers

app = FastAPI(
    title="GhostReconRev Safe Recon UI",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.mount("/static", StaticFiles(directory="recon_ui/app/static"), name="static")


@app.on_event("startup")
def startup() -> None:
    """Initialize local database tables at application startup."""
    if APP_REQUIRE_AUTH and (not APP_AUTH_USERNAME or not APP_AUTH_PASSWORD):
        raise RuntimeError(
            "APP_REQUIRE_AUTH is enabled but APP_AUTH_USERNAME/APP_AUTH_PASSWORD are not configured."
        )
    if APP_REQUIRE_AUTH and (
        len(APP_AUTH_PASSWORD) < 12 or APP_AUTH_PASSWORD.strip().lower() in {"change-this-password", "password"}
    ):
        raise RuntimeError("APP_AUTH_PASSWORD must be at least 12 characters and not a placeholder value.")
    if TELEGRAM_TIMELINE_ENABLED and (not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID):
        raise RuntimeError(
            "TELEGRAM_TIMELINE_ENABLED is true but TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID are not configured."
        )
    init_db()


app.middleware("http")(apply_security_headers)


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> FileResponse:
    """Serve the configured favicon file for browser tab rendering."""
    return FileResponse(ROOT_DIR / "recon_ui/app/static/favicon.ico", media_type="image/x-icon")


# Route registration is split by concern for maintainability.
app.include_router(runs.router)
app.include_router(evidence.router)
app.include_router(reports.router)
app.include_router(events.router)
