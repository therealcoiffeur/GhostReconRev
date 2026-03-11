from __future__ import annotations

"""Centralized runtime configuration and .env loading."""

import os
import re
from pathlib import Path


def _load_dotenv(path: Path) -> None:
    """Load KEY=VALUE pairs from .env into environment when unset."""
    if not path.exists() or not path.is_file():
        return

    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue
        value = value.strip()
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        os.environ.setdefault(key, value)


def _env_int(name: str, default: int, aliases: tuple[str, ...] = ()) -> int:
    """Read integer env var with fallback/default handling."""
    candidates = (name, *aliases)
    raw_value = ""
    for candidate in candidates:
        raw_value = os.getenv(candidate, "").strip()
        if raw_value:
            break
    if not raw_value:
        return default
    try:
        return int(raw_value)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    """Read boolean env var using common truthy/falsey spellings."""
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return default


def _env_list(name: str, default: list[str]) -> list[str]:
    """Read comma-separated env var into normalized non-empty tokens."""
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    values = [item.strip().lower() for item in raw.split(",")]
    return [item for item in values if item]


# Resolve paths from the repository root instead of the current shell working directory.
ROOT_DIR = Path(__file__).resolve().parents[2]
_load_dotenv(ROOT_DIR / ".env")

TOOLS_BIN_DIR = (ROOT_DIR / "tools/bin").resolve()
COLLECTOR_ARTIFACTS_DIR = (ROOT_DIR / "artifacts/collectors").resolve()
REPORTS_DIR = (ROOT_DIR / "artifacts/reports").resolve()

AMASS_TIMEOUT = _env_int("AMASS_TIMEOUT", 60, aliases=("AMASS_TIMETOUT",))
ASSETFINDER_TIMEOUT = _env_int("ASSETFINDER_TIMEOUT", 60)
CRTSH_TIMEOUT = _env_int("CRTSH_TIMEOUT", 20)
COLLECTOR_MAX_WORKERS = _env_int("COLLECTOR_MAX_WORKERS", 4)
DNSX_TIMEOUT = _env_int("DNSX_TIMEOUT", 20)
HOST_TIMEOUT = _env_int("HOST_TIMEOUT", 15)
GAU_TIMEOUT = _env_int("GAU_TIMEOUT", 120)
GAU_THREADS = _env_int("GAU_THREADS", 10)
GAU_MAX_WORKERS = _env_int("GAU_MAX_WORKERS", 5)
NAABU_TIMEOUT = _env_int("NAABU_TIMEOUT", 60)
NAABU_MAX_WORKERS = _env_int("NAABU_MAX_WORKERS", 5)
ACTIVE_ENRICHMENT_ENABLED = _env_bool("ACTIVE_ENRICHMENT_ENABLED", _env_bool("NERVA_ENABLED", False))
NERVA_TIMEOUT = _env_int("NERVA_TIMEOUT", 60)
NERVA_MAX_WORKERS = _env_int("NERVA_MAX_WORKERS", 5)
HTTPX_TIMEOUT = _env_int("HTTPX_TIMEOUT", 45)
HTTPX_MAX_WORKERS = _env_int("HTTPX_MAX_WORKERS", 8)
HTTPX_MAX_REDIRECTS = _env_int("HTTPX_MAX_REDIRECTS", 2)
TELEGRAM_TIMEOUT = _env_int("TELEGRAM_TIMEOUT", 10)
APP_MAX_REQUEST_BYTES = _env_int("APP_MAX_REQUEST_BYTES", 1_048_576)
# Keep auth opt-in for local development; production deployments should enable it.
APP_REQUIRE_AUTH = _env_bool("APP_REQUIRE_AUTH", False)
APP_AUTH_USERNAME = os.getenv("APP_AUTH_USERNAME", "").strip()
APP_AUTH_PASSWORD = os.getenv("APP_AUTH_PASSWORD", "").strip()
ALLOWED_HOSTS = _env_list("ALLOWED_HOSTS", ["127.0.0.1", "localhost", "::1"])
TELEGRAM_TIMELINE_ENABLED = _env_bool("TELEGRAM_TIMELINE_ENABLED", False)
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
ACUNETIX_MCP_URL = os.getenv("ACUNETIX_MCP_URL", "http://127.0.0.1:3000/mcp").strip() or "http://127.0.0.1:3000/mcp"
ACUNETIX_MCP_HEALTH_URL = (
    os.getenv("ACUNETIX_MCP_HEALTH_URL", "http://127.0.0.1:3000/healthz").strip() or "http://127.0.0.1:3000/healthz"
)
ACUNETIX_MCP_AUTH_TOKEN = os.getenv("ACUNETIX_MCP_AUTH_TOKEN", "").strip()
ACUNETIX_MCP_TIMEOUT = _env_int("ACUNETIX_MCP_TIMEOUT", 60)
ACUNETIX_DEFAULT_PROFILE_ID = (
    os.getenv("ACUNETIX_DEFAULT_PROFILE_ID", "11111111-1111-1111-1111-111111111111").strip()
    or "11111111-1111-1111-1111-111111111111"
)
ACUNETIX_DEFAULT_REPORT_TEMPLATE_ID = (
    os.getenv("ACUNETIX_DEFAULT_REPORT_TEMPLATE_ID", "11111111-1111-1111-1111-111111111111").strip()
    or "11111111-1111-1111-1111-111111111111"
)
ACUNETIX_TARGET_SCAN_SPEED = os.getenv("ACUNETIX_TARGET_SCAN_SPEED", "moderate").strip().lower() or "moderate"
ACUNETIX_TARGET_USER_AGENT = (
    os.getenv(
        "ACUNETIX_TARGET_USER_AGENT",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0",
    ).strip()
    or "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0"
)
ACUNETIX_TARGET_CASE_SENSITIVE = os.getenv("ACUNETIX_TARGET_CASE_SENSITIVE", "yes").strip().lower() or "yes"
ACUNETIX_TARGET_PROXY_ENABLED = _env_bool("ACUNETIX_TARGET_PROXY_ENABLED", True)
ACUNETIX_TARGET_PROXY_PROTOCOL = os.getenv("ACUNETIX_TARGET_PROXY_PROTOCOL", "http").strip().lower() or "http"
ACUNETIX_TARGET_PROXY_ADDRESS = os.getenv("ACUNETIX_TARGET_PROXY_ADDRESS", "192.168.167.1").strip()
ACUNETIX_TARGET_PROXY_PORT = _env_int("ACUNETIX_TARGET_PROXY_PORT", 1348)
ACUNETIX_TARGET_CRITICALITY = _env_int("ACUNETIX_TARGET_CRITICALITY", 0)
ACUNETIX_RESULT_HISTORY_LIMIT = _env_int("ACUNETIX_RESULT_HISTORY_LIMIT", 10)
ACUNETIX_VULNERABILITIES_PAGE_LIMIT = _env_int("ACUNETIX_VULNERABILITIES_PAGE_LIMIT", 99)
ACUNETIX_SCAN_POLL_INTERVAL = _env_int("ACUNETIX_SCAN_POLL_INTERVAL", 10)
ACUNETIX_SCAN_MAX_RUNTIME = _env_int("ACUNETIX_SCAN_MAX_RUNTIME", 14400, aliases=("ACUNETIX_SCAN_TIMEOUT",))
ACUNETIX_REPORT_POLL_INTERVAL = _env_int("ACUNETIX_REPORT_POLL_INTERVAL", 5)
ACUNETIX_REPORT_TIMEOUT = _env_int("ACUNETIX_REPORT_TIMEOUT", 300)

REPORT_LLM_MODEL_DEFAULT = "gpt-4.1-nano"
DAST_BINARY_CANDIDATES = (
    "nuclei",
    "nikto",
    "wapiti",
    "zap.sh",
    "zap-baseline.py",
    "zap-full-scan.py",
)
DAST_BINARY_LABELS = {
    "nuclei": "Nuclei",
    "nikto": "Nikto",
    "wapiti": "Wapiti",
    "zap.sh": "OWASP ZAP",
    "zap-baseline.py": "OWASP ZAP Baseline",
    "zap-full-scan.py": "OWASP ZAP Full Scan",
}


def get_report_llm_model() -> str:
    """Resolve report enrichment model from environment with safe default."""
    return os.getenv("REPORT_LLM_MODEL", REPORT_LLM_MODEL_DEFAULT).strip() or REPORT_LLM_MODEL_DEFAULT


def get_openai_api_key() -> str:
    """Resolve OpenAI API key used for report enrichment."""
    return os.getenv("OPENAI_API_KEY", "").strip()
