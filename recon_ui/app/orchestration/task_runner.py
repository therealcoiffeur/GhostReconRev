from __future__ import annotations

"""Task execution and collector-specific parsing/ingestion helpers."""

import hashlib
import json
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from sqlmodel import select

from ..config import (
    AMASS_TIMEOUT,
    ASSETFINDER_TIMEOUT,
    COLLECTOR_ARTIFACTS_DIR,
    CRTSH_TIMEOUT,
    DNSX_TIMEOUT,
    GAU_MAX_WORKERS,
    GAU_THREADS,
    GAU_TIMEOUT,
    HOST_TIMEOUT,
    HTTPX_MAX_REDIRECTS,
    HTTPX_MAX_WORKERS,
    HTTPX_TIMEOUT,
    NAABU_MAX_WORKERS,
    NAABU_TIMEOUT,
    NERVA_MAX_WORKERS,
    NERVA_TIMEOUT,
    TOOLS_BIN_DIR,
)
from ..db import Assertion, Entity, Evidence, OutOfScopeBlocked, ScopePolicy, Task, get_session
from ..scope import ScopeRules, canonicalize_hostname, evaluate_scope
from ..services.evidence_service import resolve_local_artifact
from .common import make_id, utcnow

DNSX_RESOLUTION_PROOF_TYPES = {"A", "AAAA", "CNAME"}
DNSX_RECON_LINE_RE = re.compile(
    r"^\s*(?P<host>[A-Za-z0-9._-]+)\s+\[(?P<rtype>[A-Z0-9]+)\]\s+\[(?P<value>.+)\]\s*$"
)
CRTSH_MIN_ATTEMPTS = 3
NAABU_TCP_PORT_RE = re.compile(r"\b(?P<port>\d{1,5})/tcp\b", re.IGNORECASE)
NAABU_COLON_PORT_RE = re.compile(r":(?P<port>\d{1,5})(?:\b|/)")


class TaskRunner:
    """Runs one validated task and persists resulting entities/evidence/assertions."""

    def read_artifact_bytes(self, artifact_path: str | Path) -> bytes:
        """Return artifact bytes, or an empty payload when the artifact is missing or unreadable."""
        artifact = Path(artifact_path)
        try:
            return artifact.read_bytes() if artifact.exists() and artifact.is_file() else b""
        except OSError:
            return b""

    def artifact_has_content(self, artifact_path: str | Path) -> bool:
        """Return True when one artifact file exists and is not zero-sized."""
        return bool(self.read_artifact_bytes(artifact_path))

    def get_scope_root(self, scope_id: str) -> str:
        """Return persisted root domain for the given scope."""
        with get_session() as session:
            scope = session.exec(select(ScopePolicy).where(ScopePolicy.scope_id == scope_id)).one()
        return scope.root_domain

    def upsert_hostname_entity_in_session(self, session, scope_id: str, hostname: str) -> tuple[str, bool]:
        """Insert or refresh a hostname entity using an existing DB session."""
        existing = session.exec(
            select(Entity).where(
                Entity.scope_id == scope_id,
                Entity.entity_type == "HOSTNAME",
                Entity.canonical_name == hostname,
            )
        ).first()
        if existing:
            existing.last_seen = utcnow()
            session.add(existing)
            return existing.entity_id, False

        ent = Entity(
            entity_id=make_id("ent"),
            scope_id=scope_id,
            entity_type="HOSTNAME",
            canonical_name=hostname,
            display_name=hostname,
            status="NEW",
            resolution_status="UNRESOLVED",
        )
        session.add(ent)
        return ent.entity_id, True

    def run_collector_command(self, args: list[str], timeout_seconds: int = 180) -> str:
        """Run one passive collector command safely and return stdout."""
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout_seconds, check=False)
        except FileNotFoundError as exc:
            raise RuntimeError(f"Collector binary not found: {args[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Collector timed out after {timeout_seconds}s: {' '.join(args)}") from exc

        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            raise RuntimeError(f"Collector failed ({args[0]}): {stderr or f'rc={proc.returncode}'}")

        return proc.stdout or ""

    def run_amass_for_domain(self, domain: str, task_id: str) -> str:
        """Run amass enum first, then export discovered names with amass subs."""
        amass_bin = self.resolve_collector_binary("amass")
        COLLECTOR_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
        output_file = COLLECTOR_ARTIFACTS_DIR / f"{task_id}_amass.txt"
        # Give the wrapper slightly more time than the amass CLI timeout budget.
        amass_timeout_seconds = max(180, (AMASS_TIMEOUT * 60) + 30)

        try:
            self.run_collector_command(
                [
                    amass_bin,
                    "enum",
                    "-silent",
                    "-timeout",
                    str(AMASS_TIMEOUT),
                    "-d",
                    domain,
                ],
                timeout_seconds=amass_timeout_seconds,
            )
        except RuntimeError as exc:
            raise RuntimeError(f"amass enum failed: {exc}") from exc

        try:
            output = self.run_collector_command(
                [
                    amass_bin,
                    "subs",
                    "-names",
                    "-d",
                    domain,
                    "-o",
                    str(output_file),
                ],
                timeout_seconds=amass_timeout_seconds,
            )
        except RuntimeError as exc:
            raise RuntimeError(f"amass subs export failed: {exc}") from exc

        if not output_file.exists():
            output_file.write_text(output, encoding="utf-8")
        return str(output_file)

    def resolve_collector_binary(self, binary_name: str) -> str:
        """Resolve collector binary from tools/bin first, then PATH."""
        local_binary = TOOLS_BIN_DIR / binary_name
        if local_binary.exists() and local_binary.is_file():
            return str(local_binary)
        return binary_name

    def run_gau_for_hostname(self, host: str, task_id: str) -> tuple[str, bool]:
        """Run gau for one hostname and return (artifact_path, success)."""
        gau_bin = self.resolve_collector_binary("gau")
        COLLECTOR_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
        host_hash = hashlib.sha256(host.encode("utf-8")).hexdigest()[:12]
        output_file = COLLECTOR_ARTIFACTS_DIR / f"{task_id}_gau_{host_hash}.txt"
        try:
            proc = subprocess.run(
                [gau_bin, "--threads", str(GAU_THREADS), "--o", str(output_file)],
                input=f"{host}\n",
                capture_output=True,
                text=True,
                timeout=GAU_TIMEOUT,
                check=False,
            )
        except FileNotFoundError:
            output_file.write_text("gau execution failed: binary not found\n", encoding="utf-8")
            return str(output_file), False
        except subprocess.TimeoutExpired:
            output_file.write_text("gau execution failed: timeout\n", encoding="utf-8")
            return str(output_file), False

        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            output_file.write_text(
                f"gau execution failed (rc={proc.returncode}): {stderr or 'no stderr output'}\n",
                encoding="utf-8",
            )
            return str(output_file), False

        if not output_file.exists():
            output_file.write_text(proc.stdout or "", encoding="utf-8")
        return str(output_file), True

    def run_naabu_for_hostname(self, host: str, task_id: str) -> tuple[str, bool]:
        """Run naabu for one resolved hostname and return (artifact_path, success)."""
        naabu_bin = self.resolve_collector_binary("naabu")
        COLLECTOR_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
        host_hash = hashlib.sha256(host.encode("utf-8")).hexdigest()[:12]
        output_file = COLLECTOR_ARTIFACTS_DIR / f"{task_id}_naabu_{host_hash}.txt"
        try:
            proc = subprocess.run(
                [naabu_bin, "-host", host, "-o", str(output_file)],
                capture_output=True,
                text=True,
                timeout=NAABU_TIMEOUT,
                check=False,
            )
        except FileNotFoundError:
            output_file.write_text("naabu execution failed: binary not found\n", encoding="utf-8")
            return str(output_file), False
        except subprocess.TimeoutExpired:
            output_file.write_text("naabu execution failed: timeout\n", encoding="utf-8")
            return str(output_file), False

        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            output_file.write_text(
                f"naabu execution failed (rc={proc.returncode}): {stderr or 'no stderr output'}\n",
                encoding="utf-8",
            )
            return str(output_file), False

        if not output_file.exists():
            output_file.write_text(proc.stdout or "", encoding="utf-8")
        return str(output_file), True

    def parse_naabu_open_ports(self, raw_output: str) -> set[int]:
        """Parse open TCP ports from naabu artifact text."""
        ports: set[int] = set()
        for line in raw_output.splitlines():
            text = line.strip()
            if not text or text.lower().startswith("naabu execution failed"):
                continue
            for pattern in (NAABU_TCP_PORT_RE, NAABU_COLON_PORT_RE):
                for match in pattern.finditer(text):
                    try:
                        port = int(match.group("port"))
                    except (TypeError, ValueError):
                        continue
                    if 1 <= port <= 65535:
                        ports.add(port)
        return ports

    def run_httpx_for_endpoint(self, host: str, port: int, task_id: str) -> tuple[str, bool]:
        """Run httpx for one hostname:port endpoint and return (artifact_path, success)."""
        httpx_bin = self.resolve_collector_binary("httpx")
        COLLECTOR_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
        host_hash = hashlib.sha256(host.encode("utf-8")).hexdigest()[:12]
        output_file = COLLECTOR_ARTIFACTS_DIR / f"{task_id}_httpx_{host_hash}_{port}.txt"
        try:
            proc = subprocess.run(
                [
                    httpx_bin,
                    "-no-color",
                    "-random-agent",
                    "-status-code",
                    "-location",
                    "-title",
                    "-server",
                    "-tech-detect",
                    "-wordpress",
                    "-ip",
                    "-extract-fqdn",
                    "-cdn",
                    "-follow-redirects",
                    "-max-redirects",
                    str(HTTPX_MAX_REDIRECTS),
                    "-u",
                    f"{host}:{port}",
                    "-o",
                    str(output_file),
                ],
                capture_output=True,
                text=True,
                timeout=HTTPX_TIMEOUT,
                check=False,
            )
        except FileNotFoundError:
            output_file.write_text("httpx execution failed: binary not found\n", encoding="utf-8")
            return str(output_file), False
        except subprocess.TimeoutExpired:
            output_file.write_text("httpx execution failed: timeout\n", encoding="utf-8")
            return str(output_file), False

        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            output_file.write_text(
                f"httpx execution failed (rc={proc.returncode}): {stderr or 'no stderr output'}\n",
                encoding="utf-8",
            )
            return str(output_file), False

        if not output_file.exists():
            output_file.write_text(proc.stdout or "", encoding="utf-8")
        return str(output_file), True

    def run_nerva_for_endpoint(self, host: str, port: int, task_id: str) -> tuple[str, bool]:
        """Run nerva for one hostname:port endpoint and return (artifact_path, success)."""
        nerva_bin = self.resolve_collector_binary("nerva")
        COLLECTOR_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
        host_hash = hashlib.sha256(host.encode("utf-8")).hexdigest()[:12]
        output_file = COLLECTOR_ARTIFACTS_DIR / f"{task_id}_nerva_{host_hash}_{port}.json"
        try:
            proc = subprocess.run(
                [nerva_bin, "--json", "-t", f"{host}:{port}", "-o", str(output_file)],
                capture_output=True,
                text=True,
                timeout=NERVA_TIMEOUT,
                check=False,
            )
        except FileNotFoundError:
            output_file.write_text("nerva execution failed: binary not found\n", encoding="utf-8")
            return str(output_file), False
        except subprocess.TimeoutExpired:
            output_file.write_text("nerva execution failed: timeout\n", encoding="utf-8")
            return str(output_file), False

        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            output_file.write_text(
                f"nerva execution failed (rc={proc.returncode}): {stderr or 'no stderr output'}\n",
                encoding="utf-8",
            )
            return str(output_file), False

        if not output_file.exists():
            output_file.write_text(proc.stdout or "", encoding="utf-8")
        return str(output_file), True

    def ingest_collector_hosts(
        self,
        tool_name: str,
        task: Task,
        scope_root: str,
        rules: ScopeRules,
        raw_output: str,
        artifact_blob_ref: str,
    ) -> tuple[int, int, int, int]:
        """Filter collector output by scope and ingest entities/evidence/assertions."""
        allowed_hosts: set[str] = set()
        blocked_hosts: set[tuple[str, str]] = set()

        for line in raw_output.splitlines():
            candidate = line.strip()
            if not candidate or " " in candidate or "*" in candidate:
                continue
            try:
                host = canonicalize_hostname(candidate)
            except ValueError:
                continue

            decision = evaluate_scope(host, rules)
            if not decision.allowed:
                blocked_hosts.add((host, decision.reason))
                continue
            if host == scope_root or host.endswith("." + scope_root):
                allowed_hosts.add(host)

        if blocked_hosts:
            with get_session() as session:
                for host, reason in sorted(blocked_hosts):
                    session.add(
                        OutOfScopeBlocked(
                            block_id=make_id("blk"),
                            job_id=task.job_id,
                            scope_id=task.scope_id,
                            task_id=task.task_id,
                            source=tool_name,
                            hostname=host,
                            reason=reason,
                        )
                    )
                session.commit()

        entities_delta = 0
        evidence_delta = 0
        assertions_delta = 0
        persist_provenance = self.artifact_has_content(artifact_blob_ref)
        with get_session() as session:
            for host in sorted(allowed_hosts):
                entity_id, is_new = self.upsert_hostname_entity_in_session(session, task.scope_id, host)
                if is_new:
                    entities_delta += 1

                if not persist_provenance:
                    continue

                evd = Evidence(
                    evidence_id=make_id("evd"),
                    scope_id=task.scope_id,
                    job_id=task.job_id,
                    task_id=task.task_id,
                    kind="DNS_RECORD",
                    source=tool_name,
                    content_hash=hashlib.sha256(host.encode("utf-8")).hexdigest(),
                    blob_ref=artifact_blob_ref,
                )
                asr = Assertion(
                    assertion_id=make_id("asr"),
                    scope_id=task.scope_id,
                    subject_entity_id=entity_id,
                    predicate="discovered_by",
                    value=tool_name,
                    status="SUPPORTED",
                    evidence_refs=json.dumps([evd.evidence_id]),
                )
                session.add(evd)
                session.add(asr)
                evidence_delta += 1
                assertions_delta += 1
            session.commit()

        blocked_out_of_scope = len(blocked_hosts)
        return entities_delta, evidence_delta, assertions_delta, blocked_out_of_scope

    def fetch_crtsh_candidates(self, scope_root: str, task_id: str) -> str:
        """Query crt.sh JSON endpoint and return newline-delimited hostname candidates."""
        query = urllib.parse.quote(scope_root, safe="")
        url = f"https://crt.sh/json?q={query}"
        request = urllib.request.Request(url, headers={"User-Agent": "GhostReconRev/0.1"})
        last_error: RuntimeError | None = None
        raw = ""
        rows: list[dict] | None = None

        for attempt in range(1, CRTSH_MIN_ATTEMPTS + 1):
            try:
                with urllib.request.urlopen(request, timeout=CRTSH_TIMEOUT) as response:
                    final = urllib.parse.urlsplit(response.geturl())
                    if final.scheme != "https" or final.hostname not in {"crt.sh", "www.crt.sh"}:
                        raise RuntimeError("crt.sh redirect blocked")
                    raw = response.read().decode("utf-8", errors="replace")
                rows = json.loads(raw)
                break
            except urllib.error.URLError as exc:
                last_error = RuntimeError(f"crt.sh request failed on attempt {attempt}")  # noqa: B904
                last_error.__cause__ = exc
            except json.JSONDecodeError as exc:
                last_error = RuntimeError(f"crt.sh returned invalid JSON on attempt {attempt}")  # noqa: B904
                last_error.__cause__ = exc

            if attempt < CRTSH_MIN_ATTEMPTS:
                time.sleep(attempt)

        if rows is None:
            raise last_error or RuntimeError("crt.sh request failed")

        COLLECTOR_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
        artifact_path = COLLECTOR_ARTIFACTS_DIR / f"{task_id}_crtsh.json"
        artifact_path.write_text(raw, encoding="utf-8")

        candidates: set[str] = set()
        for row in rows:
            name_value = str(row.get("name_value", "")).strip()
            common_name = str(row.get("common_name", "")).strip()
            for source in (name_value, common_name):
                if not source:
                    continue
                for entry in source.splitlines():
                    host = entry.strip().lower()
                    if host.startswith("*."):
                        host = host[2:]
                    if host:
                        candidates.add(host)

        return "\n".join(sorted(candidates))

    def parse_dnsx_recon_output(self, raw_output: str, expected_host: str) -> list[dict[str, str]]:
        """Parse dnsx recon output and return normalized records for one hostname."""
        records: list[dict[str, str]] = []
        for line in raw_output.splitlines():
            text = line.strip()
            if not text or text.startswith("[INF]"):
                continue
            match = DNSX_RECON_LINE_RE.match(text)
            if not match:
                continue

            host = match.group("host").strip().lower()
            if host != expected_host:
                continue
            records.append(
                {
                    "host": host,
                    "type": match.group("rtype").strip().upper(),
                    "value": match.group("value").strip(),
                }
            )

        return records

    def classify_dnsx_resolution(
        self,
        expected_host: str,
        raw_output: str,
        command_succeeded: bool,
    ) -> tuple[str, list[dict[str, str]], list[str]]:
        """Classify dnsx output into RESOLVED / NEEDCHECK / UNRESOLVED."""
        records = self.parse_dnsx_recon_output(raw_output, expected_host)
        record_types = sorted({record["type"] for record in records})
        has_resolution_proof = bool(set(record_types) & DNSX_RESOLUTION_PROOF_TYPES)

        if has_resolution_proof:
            return "RESOLVED", records, record_types
        if records:
            return "NEEDCHECK", records, record_types
        if command_succeeded:
            return "NEEDCHECK", records, record_types
        return "UNRESOLVED", records, record_types

    def collect_open_port_targets(self, scope_id: str, job_id: str) -> set[tuple[str, str, int]]:
        """Return unique entity/host/port tuples from latest successful naabu evidence."""
        with get_session() as session:
            entities_by_id = {
                row.entity_id: row
                for row in session.exec(
                    select(Entity)
                    .where(Entity.scope_id == scope_id)
                    .where(Entity.entity_type.in_(["DOMAIN", "HOSTNAME"]))
                ).all()
            }
            naabu_evidence_by_id = {
                row.evidence_id: row
                for row in session.exec(
                    select(Evidence)
                    .where(Evidence.job_id == job_id)
                    .where(Evidence.source == "naabu")
                    .where(Evidence.kind == "PORT_SCAN")
                ).all()
            }
            naabu_assertions = session.exec(
                select(Assertion)
                .where(Assertion.scope_id == scope_id)
                .where(Assertion.predicate == "ports_scanned_by")
                .where(Assertion.value == "true")
                .order_by(Assertion.created_at.desc())
            ).all()

        endpoint_targets: set[tuple[str, str, int]] = set()
        for assertion in naabu_assertions:
            entity_row = entities_by_id.get(assertion.subject_entity_id)
            if not entity_row:
                continue
            try:
                evidence_refs = json.loads(assertion.evidence_refs or "[]")
            except json.JSONDecodeError:
                continue
            for evidence_id in evidence_refs:
                evidence_row = naabu_evidence_by_id.get(evidence_id)
                if not evidence_row:
                    continue
                # Reuse the same artifact guardrails as the evidence download/read paths.
                artifact = resolve_local_artifact(evidence_row.blob_ref)
                if not artifact:
                    continue
                try:
                    raw_text = artifact.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for port in self.parse_naabu_open_ports(raw_text):
                    endpoint_targets.add((entity_row.entity_id, entity_row.canonical_name, port))
        return endpoint_targets

    def run_task(self, task: Task, scope_root: str, rules: ScopeRules) -> tuple[int, int, int, int]:
        """Execute one task and return (entities, evidence, assertions, blocked)."""
        entities_delta = 0
        evidence_delta = 0
        assertions_delta = 0
        blocked_out_of_scope = 0

        if task.task_type == "seed_root_domain":
            with get_session() as session:
                ent = Entity(
                    entity_id=make_id("ent"),
                    scope_id=task.scope_id,
                    entity_type="DOMAIN",
                    canonical_name=scope_root,
                    display_name=scope_root,
                    status="CONFIRMED",
                    resolution_status="UNRESOLVED",
                )
                session.add(ent)
                session.commit()
            entities_delta = 1

        elif task.task_type == "run_amass_passive":
            output_file = Path(self.run_amass_for_domain(scope_root, task.task_id))
            output = output_file.read_text(encoding="utf-8") if output_file.exists() else ""
            entities_delta, evidence_delta, assertions_delta, blocked_out_of_scope = self.ingest_collector_hosts(
                "amass", task, scope_root, rules, output, artifact_blob_ref=str(output_file)
            )

        elif task.task_type == "run_subfinder_passive":
            subfinder_bin = self.resolve_collector_binary("subfinder")
            COLLECTOR_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
            output_file = COLLECTOR_ARTIFACTS_DIR / f"{task.task_id}_subfinder.txt"
            _ = self.run_collector_command([subfinder_bin, "-silent", "-d", scope_root, "-all", "-o", str(output_file)])
            output = output_file.read_text(encoding="utf-8") if output_file.exists() else ""
            entities_delta, evidence_delta, assertions_delta, blocked_out_of_scope = self.ingest_collector_hosts(
                "subfinder", task, scope_root, rules, output, artifact_blob_ref=str(output_file)
            )

        elif task.task_type == "run_assetfinder_passive":
            assetfinder_bin = self.resolve_collector_binary("assetfinder")
            COLLECTOR_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
            output_file = COLLECTOR_ARTIFACTS_DIR / f"{task.task_id}_assetfinder.txt"
            try:
                proc = subprocess.run(
                    [assetfinder_bin, "-subs-only", scope_root],
                    capture_output=True,
                    text=True,
                    timeout=ASSETFINDER_TIMEOUT,
                    check=False,
                )
            except FileNotFoundError as exc:
                raise RuntimeError(f"Collector binary not found: {assetfinder_bin}") from exc
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("Collector timed out: assetfinder") from exc

            if proc.returncode != 0:
                stderr = (proc.stderr or "").strip()
                raise RuntimeError(f"Collector failed ({assetfinder_bin}): {stderr or f'rc={proc.returncode}'}")

            output = proc.stdout or ""
            output_file.write_text(output, encoding="utf-8")
            entities_delta, evidence_delta, assertions_delta, blocked_out_of_scope = self.ingest_collector_hosts(
                "assetfinder", task, scope_root, rules, output, artifact_blob_ref=str(output_file)
            )

        elif task.task_type == "run_crtsh_passive":
            output = self.fetch_crtsh_candidates(scope_root, task.task_id)
            artifact_path = COLLECTOR_ARTIFACTS_DIR / f"{task.task_id}_crtsh.json"
            entities_delta, evidence_delta, assertions_delta, blocked_out_of_scope = self.ingest_collector_hosts(
                "crtsh",
                task,
                scope_root,
                rules,
                output,
                artifact_blob_ref=str(artifact_path),
            )

        elif task.task_type == "run_gau_enumeration":
            with get_session() as session:
                targets = session.exec(
                    select(Entity)
                    .where(Entity.scope_id == task.scope_id)
                    .where(Entity.entity_type.in_(["DOMAIN", "HOSTNAME"]))
                    .order_by(Entity.canonical_name)
                ).all()

            def _run_single_gau(target: Entity) -> tuple[str, str, bool, str]:
                host = target.canonical_name
                artifact_path, succeeded = self.run_gau_for_hostname(host, task.task_id)
                artifact = Path(artifact_path)
                try:
                    raw = artifact.read_bytes() if artifact.exists() else b""
                except OSError:
                    raw = b""
                content_hash = hashlib.sha256(raw if raw else f"gau|{host}|{task.task_id}".encode("utf-8")).hexdigest()
                return target.entity_id, artifact_path, succeeded, content_hash

            gau_results: list[tuple[str, str, bool, str]] = []
            if targets:
                workers = min(max(1, GAU_MAX_WORKERS), len(targets))
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = [pool.submit(_run_single_gau, target) for target in targets]
                    for future in as_completed(futures):
                        gau_results.append(future.result())

            with get_session() as session:
                for entity_id, artifact_path, succeeded, content_hash in gau_results:
                    evd = Evidence(
                        evidence_id=make_id("evd"),
                        scope_id=task.scope_id,
                        job_id=task.job_id,
                        task_id=task.task_id,
                        kind="URL_ENUMERATION" if succeeded else "URL_ENUMERATION_ERROR",
                        source="gau",
                        content_hash=content_hash,
                        blob_ref=artifact_path,
                    )
                    asr = Assertion(
                        assertion_id=make_id("asr"),
                        scope_id=task.scope_id,
                        subject_entity_id=entity_id,
                        predicate="urls_collected_by",
                        value="true" if succeeded else "false",
                        status="SUPPORTED",
                        evidence_refs=json.dumps([evd.evidence_id]),
                    )
                    session.add(evd)
                    session.add(asr)
                    evidence_delta += 1
                    assertions_delta += 1
                session.commit()

        elif task.task_type == "run_dnsx_resolution":
            dnsx_bin = self.resolve_collector_binary("dnsx")
            host_bin = self.resolve_collector_binary("host")
            with get_session() as session:
                targets = session.exec(
                    select(Entity)
                    .where(Entity.scope_id == task.scope_id)
                    .where(Entity.entity_type.in_(["DOMAIN", "HOSTNAME"]))
                    .order_by(Entity.canonical_name)
                ).all()

            COLLECTOR_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
            for target in targets:
                host = target.canonical_name
                host_hash = hashlib.sha256(host.encode("utf-8")).hexdigest()[:12]
                host_output_file = COLLECTOR_ARTIFACTS_DIR / f"{task.task_id}_host_{host_hash}.txt"
                output_file = COLLECTOR_ARTIFACTS_DIR / f"{task.task_id}_dnsx_{host_hash}.txt"
                resolution_status = "UNRESOLVED"
                stderr_msg = ""
                dnsx_raw_output = ""
                record_types: list[str] = []
                evidence_source = "dnsx"
                artifact_path = output_file
                try:
                    host_proc = subprocess.run(
                        [host_bin, host],
                        capture_output=True,
                        text=True,
                        timeout=HOST_TIMEOUT,
                        check=False,
                    )
                    host_raw_output = "\n".join(
                        [chunk for chunk in [(host_proc.stdout or "").strip(), (host_proc.stderr or "").strip()] if chunk]
                    ).strip()
                    host_output_file.write_text(host_raw_output + ("\n" if host_raw_output else ""), encoding="utf-8")

                    if host_proc.returncode == 0:
                        proc = subprocess.run(
                            [dnsx_bin, "-no-color", "-recon", "-o", str(output_file)],
                            input=f"{host}\n",
                            capture_output=True,
                            text=True,
                            timeout=DNSX_TIMEOUT,
                            check=False,
                        )
                        if proc.returncode != 0:
                            stderr_msg = (proc.stderr or "").strip()
                        if output_file.exists():
                            dnsx_raw_output = output_file.read_text(encoding="utf-8")
                        if not dnsx_raw_output.strip():
                            dnsx_raw_output = proc.stdout or ""
                            if dnsx_raw_output.strip():
                                output_file.write_text(dnsx_raw_output, encoding="utf-8")

                        resolution_status, _, record_types = self.classify_dnsx_resolution(
                            host,
                            dnsx_raw_output,
                            command_succeeded=(proc.returncode == 0),
                        )
                        evidence_source = "dnsx"
                        artifact_path = output_file
                    else:
                        stderr_msg = f"host precheck failed (rc={host_proc.returncode})"
                        evidence_source = "host"
                        artifact_path = host_output_file
                except FileNotFoundError as exc:
                    raise RuntimeError(f"Collector binary not found: {exc.filename}") from exc
                except subprocess.TimeoutExpired:
                    stderr_msg = "timeout"
                    evidence_source = "host"
                    artifact_path = host_output_file

                with get_session() as session:
                    entity_row = session.exec(
                        select(Entity).where(
                            Entity.scope_id == task.scope_id,
                            Entity.canonical_name == host,
                            Entity.entity_type == target.entity_type,
                        )
                    ).first()
                    if entity_row:
                        entity_row.resolution_status = resolution_status
                        entity_row.resolution_checked_at = utcnow()
                        entity_row.resolution_source = evidence_source
                        entity_row.resolution_artifact = str(artifact_path)
                        entity_row.last_seen = utcnow()
                        session.add(entity_row)

                    if self.artifact_has_content(artifact_path):
                        evd = Evidence(
                            evidence_id=make_id("evd"),
                            scope_id=task.scope_id,
                            job_id=task.job_id,
                            task_id=task.task_id,
                            kind="DNS_RESOLUTION",
                            source=evidence_source,
                            content_hash=hashlib.sha256(
                                f"{host}|{resolution_status}|{evidence_source}|{','.join(record_types)}|{stderr_msg}".encode(
                                    "utf-8"
                                )
                            ).hexdigest(),
                            blob_ref=str(artifact_path),
                        )
                        assertion_value = (
                            "true"
                            if resolution_status == "RESOLVED"
                            else "needcheck"
                            if resolution_status == "NEEDCHECK"
                            else "false"
                        )
                        asr = Assertion(
                            assertion_id=make_id("asr"),
                            scope_id=task.scope_id,
                            subject_entity_id=(entity_row.entity_id if entity_row else target.entity_id),
                            predicate="resolves",
                            value=assertion_value,
                            status="SUPPORTED",
                            evidence_refs=json.dumps([evd.evidence_id]),
                        )
                        session.add(evd)
                        session.add(asr)
                        evidence_delta += 1
                        assertions_delta += 1
                    session.commit()

        elif task.task_type == "run_naabu_resolved":
            with get_session() as session:
                targets = session.exec(
                    select(Entity)
                    .where(Entity.scope_id == task.scope_id)
                    .where(Entity.entity_type.in_(["DOMAIN", "HOSTNAME"]))
                    .where(Entity.resolution_status == "RESOLVED")
                    .order_by(Entity.canonical_name)
                ).all()

            def _run_single_naabu(target: Entity) -> tuple[str, str, bool, str]:
                host = target.canonical_name
                artifact_path, succeeded = self.run_naabu_for_hostname(host, task.task_id)
                raw = self.read_artifact_bytes(artifact_path)
                content_hash = hashlib.sha256(raw if raw else f"naabu|{host}|{task.task_id}".encode("utf-8")).hexdigest()
                return target.entity_id, artifact_path, succeeded, content_hash

            naabu_results: list[tuple[str, str, bool, str]] = []
            if targets:
                # Probe resolved targets concurrently while keeping bounded worker count.
                workers = min(max(1, NAABU_MAX_WORKERS), len(targets))
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = [pool.submit(_run_single_naabu, target) for target in targets]
                    for future in as_completed(futures):
                        naabu_results.append(future.result())

            with get_session() as session:
                for entity_id, artifact_path, succeeded, content_hash in naabu_results:
                    if not self.artifact_has_content(artifact_path):
                        continue
                    evd = Evidence(
                        evidence_id=make_id("evd"),
                        scope_id=task.scope_id,
                        job_id=task.job_id,
                        task_id=task.task_id,
                        kind="PORT_SCAN" if succeeded else "PORT_SCAN_ERROR",
                        source="naabu",
                        content_hash=content_hash,
                        blob_ref=artifact_path,
                    )
                    asr = Assertion(
                        assertion_id=make_id("asr"),
                        scope_id=task.scope_id,
                        subject_entity_id=entity_id,
                        predicate="ports_scanned_by",
                        value="true" if succeeded else "false",
                        status="SUPPORTED",
                        evidence_refs=json.dumps([evd.evidence_id]),
                    )
                    session.add(evd)
                    session.add(asr)
                    evidence_delta += 1
                    assertions_delta += 1
                session.commit()

        elif task.task_type == "run_httpx_on_open_ports":
            endpoint_targets = self.collect_open_port_targets(task.scope_id, task.job_id)

            def _run_single_httpx(target: tuple[str, str, int]) -> tuple[str, str, int, str, bool, str]:
                entity_id, host, port = target
                artifact_path, succeeded = self.run_httpx_for_endpoint(host, port, task.task_id)
                raw = self.read_artifact_bytes(artifact_path)
                content_hash = hashlib.sha256(
                    raw if raw else f"httpx|{host}:{port}|{task.task_id}".encode("utf-8")
                ).hexdigest()
                return entity_id, host, port, artifact_path, succeeded, content_hash

            httpx_results: list[tuple[str, str, int, str, bool, str]] = []
            if endpoint_targets:
                # Probe endpoints concurrently while keeping bounded worker count.
                workers = min(max(1, HTTPX_MAX_WORKERS), len(endpoint_targets))
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = [pool.submit(_run_single_httpx, target) for target in sorted(endpoint_targets)]
                    for future in as_completed(futures):
                        httpx_results.append(future.result())

            with get_session() as session:
                for entity_id, _, port, artifact_path, succeeded, content_hash in httpx_results:
                    if not self.artifact_has_content(artifact_path):
                        continue
                    evd = Evidence(
                        evidence_id=make_id("evd"),
                        scope_id=task.scope_id,
                        job_id=task.job_id,
                        task_id=task.task_id,
                        kind="HTTP_PROBE" if succeeded else "HTTP_PROBE_ERROR",
                        source="httpx",
                        content_hash=content_hash,
                        blob_ref=artifact_path,
                    )
                    session.add(evd)
                    evidence_delta += 1

                    if succeeded:
                        # Store port-specific evidence linkage for popup deep-links.
                        asr = Assertion(
                            assertion_id=make_id("asr"),
                            scope_id=task.scope_id,
                            subject_entity_id=entity_id,
                            predicate="port_http_profiled",
                            value=str(port),
                            status="SUPPORTED",
                            evidence_refs=json.dumps([evd.evidence_id]),
                        )
                        session.add(asr)
                        assertions_delta += 1
                session.commit()

        elif task.task_type == "run_nerva_on_open_ports":
            endpoint_targets = self.collect_open_port_targets(task.scope_id, task.job_id)

            def _run_single_nerva(target: tuple[str, str, int]) -> tuple[str, str, int, str, bool, str]:
                entity_id, host, port = target
                artifact_path, succeeded = self.run_nerva_for_endpoint(host, port, task.task_id)
                raw = self.read_artifact_bytes(artifact_path)
                content_hash = hashlib.sha256(
                    raw if raw else f"nerva|{host}:{port}|{task.task_id}".encode("utf-8")
                ).hexdigest()
                return entity_id, host, port, artifact_path, succeeded, content_hash

            nerva_results: list[tuple[str, str, int, str, bool, str]] = []
            if endpoint_targets:
                workers = min(max(1, NERVA_MAX_WORKERS), len(endpoint_targets))
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = [pool.submit(_run_single_nerva, target) for target in sorted(endpoint_targets)]
                    for future in as_completed(futures):
                        nerva_results.append(future.result())

            with get_session() as session:
                for entity_id, _, port, artifact_path, succeeded, content_hash in nerva_results:
                    if not self.artifact_has_content(artifact_path):
                        continue
                    evd = Evidence(
                        evidence_id=make_id("evd"),
                        scope_id=task.scope_id,
                        job_id=task.job_id,
                        task_id=task.task_id,
                        kind="SERVICE_PROBE" if succeeded else "SERVICE_PROBE_ERROR",
                        source="nerva",
                        content_hash=content_hash,
                        blob_ref=artifact_path,
                    )
                    session.add(evd)
                    evidence_delta += 1

                    if succeeded:
                        asr = Assertion(
                            assertion_id=make_id("asr"),
                            scope_id=task.scope_id,
                            subject_entity_id=entity_id,
                            predicate="port_service_profiled",
                            value=str(port),
                            status="SUPPORTED",
                            evidence_refs=json.dumps([evd.evidence_id]),
                        )
                        session.add(asr)
                        assertions_delta += 1
                session.commit()

        elif task.task_type == "normalize_placeholder":
            time.sleep(0.2)

        elif task.task_type == "plan_next_placeholder":
            time.sleep(0.2)

        return entities_delta, evidence_delta, assertions_delta, blocked_out_of_scope
