from __future__ import annotations

"""Helpers for discovering available DAST integrations."""

import json
import socket
import urllib.error
import urllib.request
from collections.abc import Iterable
from shutil import which
from typing import Any

from ..config import (
    ACUNETIX_MCP_AUTH_TOKEN,
    ACUNETIX_MCP_HEALTH_URL,
    ACUNETIX_MCP_TIMEOUT,
    ACUNETIX_MCP_URL,
    DAST_BINARY_CANDIDATES,
    DAST_BINARY_LABELS,
    TOOLS_BIN_DIR,
)

MCP_PROTOCOL_VERSION = "2024-11-05"
MCP_CLIENT_INFO = {"name": "ghostreconrev", "version": "0.1.0"}
_ACUNETIX_MCP_TOOL_NAMES_CACHE: tuple[str, ...] = ()


def _is_timeout_reason(reason: Any) -> bool:
    """Normalize urllib timeout variants so workflow errors are explicit."""
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return True
    return str(reason).strip().lower() == "timed out"


def _http_json_request(
    url: str,
    *,
    method: str,
    payload: dict[str, Any] | None = None,
    timeout: int = ACUNETIX_MCP_TIMEOUT,
) -> tuple[int, dict[str, Any], dict[str, str]]:
    """Send one JSON request and return status, parsed body, and response headers."""
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "GhostReconRev/0.1",
    }
    # The MCP endpoint controls scanner-side effects, so use a shared bearer token when configured.
    if ACUNETIX_MCP_AUTH_TOKEN:
        headers["Authorization"] = f"Bearer {ACUNETIX_MCP_AUTH_TOKEN}"
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw_body = response.read().decode("utf-8", errors="replace").strip()
        parsed = json.loads(raw_body) if raw_body else {}
        response_headers = {key.lower(): value for key, value in response.headers.items()}
        return response.status, parsed, response_headers


def _mcp_call(method: str, *, params: dict[str, Any], request_id: int | None, timeout: int | None = None) -> dict[str, Any]:
    """Call one JSON-RPC method on the Acunetix MCP endpoint."""
    effective_timeout = timeout if timeout is not None else ACUNETIX_MCP_TIMEOUT
    payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params}
    if request_id is not None:
        payload["id"] = request_id
    try:
        _, response_body, _ = _http_json_request(
            ACUNETIX_MCP_URL,
            method="POST",
            payload=payload,
            timeout=effective_timeout,
        )
    except urllib.error.URLError as exc:
        if _is_timeout_reason(exc.reason):
            raise RuntimeError(f"Acunetix MCP request timed out after {effective_timeout}s") from exc
        raise RuntimeError(f"Acunetix MCP unreachable: {exc.reason}") from exc
    except (TimeoutError, socket.timeout) as exc:
        raise RuntimeError(f"Acunetix MCP request timed out after {effective_timeout}s") from exc
    return response_body


def initialize_acunetix_mcp(*, timeout: int | None = None) -> dict[str, Any]:
    """Run the basic MCP handshake and return protocol/tool inventory details."""
    effective_timeout = timeout if timeout is not None else ACUNETIX_MCP_TIMEOUT
    try:
        health_status, health_body, _ = _http_json_request(
            ACUNETIX_MCP_HEALTH_URL,
            method="GET",
            timeout=effective_timeout,
        )
    except urllib.error.URLError as exc:
        if _is_timeout_reason(exc.reason):
            raise RuntimeError(f"Acunetix MCP health check timed out after {effective_timeout}s") from exc
        raise RuntimeError(f"Acunetix MCP unreachable: {exc.reason}") from exc
    except (TimeoutError, socket.timeout) as exc:
        raise RuntimeError(f"Acunetix MCP health check timed out after {effective_timeout}s") from exc
    if health_status != 200 or not health_body.get("ok"):
        raise RuntimeError("Acunetix MCP health check failed")

    initialize_result = _mcp_call(
        "initialize",
        params={
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": MCP_CLIENT_INFO,
        },
        request_id=1,
        timeout=effective_timeout,
    )
    init_payload = initialize_result.get("result") if isinstance(initialize_result, dict) else None
    if not isinstance(init_payload, dict):
        raise RuntimeError("Acunetix MCP initialize returned no result")

    _mcp_call("notifications/initialized", params={}, request_id=None, timeout=effective_timeout)

    tools_result = _mcp_call("tools/list", params={}, request_id=2, timeout=effective_timeout)
    tools_payload = tools_result.get("result") if isinstance(tools_result, dict) else None
    tool_rows = tools_payload.get("tools") if isinstance(tools_payload, dict) else None
    if not isinstance(tool_rows, list):
        raise RuntimeError("Acunetix MCP tools/list returned no tool inventory")

    tool_names = [
        str(tool.get("name", "")).strip()
        for tool in tool_rows
        if isinstance(tool, dict) and str(tool.get("name", "")).strip()
    ]
    if not tool_names:
        raise RuntimeError("Acunetix MCP reported zero tools")

    global _ACUNETIX_MCP_TOOL_NAMES_CACHE
    _ACUNETIX_MCP_TOOL_NAMES_CACHE = tuple(tool_names)

    return {
        "protocol_version": str(init_payload.get("protocolVersion") or MCP_PROTOCOL_VERSION),
        "tool_names": tool_names,
    }


def _get_acunetix_mcp_tool_names() -> tuple[str, ...]:
    """Return the discovered MCP tool names, initializing the server handshake if needed."""
    if _ACUNETIX_MCP_TOOL_NAMES_CACHE:
        return _ACUNETIX_MCP_TOOL_NAMES_CACHE
    handshake = initialize_acunetix_mcp()
    return tuple(handshake["tool_names"])


def call_acunetix_mcp_tool(tool_name: str, arguments: dict[str, Any], *, timeout: int | None = None) -> dict[str, Any]:
    """Execute one MCP tool and return the structured payload."""
    resolved_tool_name = resolve_acunetix_mcp_tool_name(tool_name, _get_acunetix_mcp_tool_names())
    if not resolved_tool_name:
        raise RuntimeError(f"Acunetix MCP is missing required tool: {tool_name}")

    result = _mcp_call(
        "tools/call",
        params={"name": resolved_tool_name, "arguments": arguments},
        request_id=3,
        timeout=timeout,
    )
    result_payload = result.get("result") if isinstance(result, dict) else None
    if not isinstance(result_payload, dict):
        raise RuntimeError(f"Acunetix MCP tools/call returned no result for {resolved_tool_name}")

    structured = result_payload.get("structuredContent")
    if not isinstance(structured, dict):
        raise RuntimeError(f"Acunetix MCP tools/call returned no structured payload for {resolved_tool_name}")

    if result_payload.get("isError") or not structured.get("ok"):
        message = str(structured.get("message") or f"{resolved_tool_name} failed").strip() or f"{resolved_tool_name} failed"
        validation_errors = structured.get("validation_errors")
        if isinstance(validation_errors, list):
            details = [str(item).strip() for item in validation_errors if str(item).strip()]
            if details:
                message = f"{message} {'; '.join(details)}"
        raise RuntimeError(message)
    return structured


def resolve_acunetix_mcp_tool_name(tool_name: str, available_tool_names: Iterable[str]) -> str | None:
    """Resolve a canonical GhostReconRev tool name to the MCP tool exposed at runtime."""
    available = {
        str(candidate).strip()
        for candidate in available_tool_names
        if str(candidate).strip()
    }
    if tool_name in available:
        return tool_name

    suffix = f"_{tool_name}"
    suffix_matches = sorted(candidate for candidate in available if candidate.endswith(suffix))
    if len(suffix_matches) == 1:
        return suffix_matches[0]
    return None


def _discover_local_dast_tools() -> list[dict[str, Any]]:
    """Return DAST binaries found locally in tools/bin or PATH."""
    available_tools: list[dict[str, Any]] = []
    seen_binaries: set[str] = set()
    for binary_name in DAST_BINARY_CANDIDATES:
        if binary_name in seen_binaries:
            continue
        seen_binaries.add(binary_name)

        local_binary = TOOLS_BIN_DIR / binary_name
        source = ""
        if local_binary.exists() and local_binary.is_file():
            source = "tools/bin"
        elif which(binary_name):
            source = "PATH"

        if not source:
            continue

        available_tools.append(
            {
                "id": f"binary:{binary_name}",
                "label": DAST_BINARY_LABELS.get(binary_name, binary_name),
                "kind": "binary",
                "source": source,
                "summary": "Local DAST binary available",
                "tool_count": 0,
                "tool_names_preview": [],
            }
        )
    return available_tools


def _discover_acunetix_mcp() -> tuple[dict[str, Any] | None, str]:
    """Return one Acunetix DAST entry when the MCP is reachable and usable."""
    try:
        handshake = initialize_acunetix_mcp()
        tool_names = handshake["tool_names"]

        return (
            {
                "id": "mcp:acunetix",
                "label": "Acunetix",
                "kind": "mcp",
                "source": "streamable-http-mcp",
                "summary": f"{len(tool_names)} MCP tool{'s' if len(tool_names) != 1 else ''} discovered",
                "tool_count": len(tool_names),
                "tool_names_preview": tool_names[:8],
                "endpoint": ACUNETIX_MCP_URL,
                "protocol_version": str(handshake["protocol_version"]),
            },
            "",
        )
    except urllib.error.HTTPError as exc:
        return None, f"Acunetix MCP returned HTTP {exc.code}"
    except urllib.error.URLError as exc:
        return None, f"Acunetix MCP unreachable: {exc.reason}"
    except (TypeError, ValueError, json.JSONDecodeError):
        return None, "Acunetix MCP returned invalid JSON"


def discover_available_dast_tools() -> dict[str, Any]:
    """Return detected DAST integrations and any discovery warnings."""
    available_tools = _discover_local_dast_tools()
    warnings: list[str] = []

    acunetix_entry, acunetix_warning = _discover_acunetix_mcp()
    if acunetix_entry:
        available_tools.insert(0, acunetix_entry)
    elif acunetix_warning:
        warnings.append(acunetix_warning)

    return {
        "ok": True,
        "tools": available_tools,
        "warnings": warnings,
    }
