from __future__ import annotations

"""Container health probe for the FastAPI web process."""

import base64
import os
import sys
import urllib.error
import urllib.request


def _bool_env(name: str, default: bool = False) -> bool:
    """Read one boolean environment flag using common truthy spellings."""
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def main() -> int:
    """Request a lightweight local endpoint and return shell-friendly status."""
    request = urllib.request.Request("http://127.0.0.1:8000/favicon.ico", method="GET")

    if _bool_env("APP_REQUIRE_AUTH", False):
        # Mirror the app's Basic Auth requirement so the probe still succeeds when auth is enabled.
        username = os.getenv("APP_AUTH_USERNAME", "")
        password = os.getenv("APP_AUTH_PASSWORD", "")
        if not username or not password:
            return 1
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        request.add_header("Authorization", f"Basic {token}")

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return 0 if 200 <= response.status < 300 else 1
    except urllib.error.HTTPError:
        return 1
    except Exception:
        return 1


if __name__ == "__main__":
    """Exit with healthcheck status code when executed as a script."""
    raise SystemExit(main())
