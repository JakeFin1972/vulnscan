"""OpenVAS / Greenbone Vulnerability Manager (GVM) scanner.

Uses python-gvm to connect to a running GVM daemon and run a full
vulnerability assessment.

Quick-start with Docker:
  # Option A — official Greenbone Community Edition (recommended):
  docker run -d --name openvas \
    -p 9390:9390 \
    -e GVMD_USER=admin -e GVMD_PASSWORD=admin \
    greenbone/gvm

  # Option B — Unix socket (when running GVM locally or in the same container):
  export OPENVAS_SOCKET=/run/gvm/gvmd.sock

Connection settings via env vars:
  OPENVAS_HOST     (default: localhost)    — GMP host (TLS/TCP mode)
  OPENVAS_PORT     (default: 9390)         — GMP port (TLS/TCP mode)
  OPENVAS_SOCKET   (default: unset)        — Unix socket path; if set, takes
                                             priority over HOST/PORT
  OPENVAS_USER     (default: admin)
  OPENVAS_PASSWORD (default: admin)
  OPENVAS_TIMEOUT  (default: 1800)  — max seconds to wait for a scan task

Scan config:
  OPENVAS_SCAN_CONFIG — name *or* UUID of a GVM scan config
                        (default: "Full and fast")
"""
from __future__ import annotations

import os
import re
import time
from typing import Any

from .base import DynamicFinding, cvss_to_severity

_OV_HOST     = os.environ.get("OPENVAS_HOST",     "localhost")
_OV_PORT     = int(os.environ.get("OPENVAS_PORT",     "9390"))
_OV_SOCKET   = os.environ.get("OPENVAS_SOCKET",   "")   # Unix socket path
_OV_USER     = os.environ.get("OPENVAS_USER",     "admin")
_OV_PASSWORD = os.environ.get("OPENVAS_PASSWORD", "admin")
_OV_TIMEOUT  = int(os.environ.get("OPENVAS_TIMEOUT",  "1800"))
_OV_CONFIG   = os.environ.get("OPENVAS_SCAN_CONFIG", "Full and fast")

# UUID regex — if OPENVAS_SCAN_CONFIG looks like a UUID treat it directly
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# ── Simple TTL cache for is_available() to avoid blocking every health-check ──

_avail_cache: dict[str, Any] = {"value": None, "expires": 0.0}
_AVAIL_TTL = 30.0  # seconds


try:
    from gvm.connections import TLSConnection, UnixSocketConnection  # type: ignore[import-untyped]
    from gvm.protocols.gmp import Gmp                                # type: ignore[import-untyped]
    from gvm.transforms import EtreeTransform                        # type: ignore[import-untyped]
    _GVM_AVAILABLE = True
except ImportError:
    _GVM_AVAILABLE = False


# ── Connection helpers ────────────────────────────────────────────────────────

def _make_connection(
    host: str | None = None,
    port: int | None = None,
    socket: str | None = None,
):
    sock = socket or _OV_SOCKET
    if sock:
        return UnixSocketConnection(path=sock)
    return TLSConnection(hostname=host or _OV_HOST, port=port or _OV_PORT)


def _connect(
    host: str | None = None,
    port: int | None = None,
    socket: str | None = None,
):
    conn = _make_connection(host=host, port=port, socket=socket)
    return Gmp(connection=conn, transform=EtreeTransform())


# ── Availability (cached) ─────────────────────────────────────────────────────

def is_available() -> bool:
    now = time.monotonic()
    if _avail_cache["expires"] > now:
        return bool(_avail_cache["value"])

    result = _probe_available()
    _avail_cache["value"] = result
    _avail_cache["expires"] = now + _AVAIL_TTL
    return result


def _probe_available() -> bool:
    if not _GVM_AVAILABLE:
        return False
    try:
        with _connect() as gmp:
            gmp.authenticate(_OV_USER, _OV_PASSWORD)
            return True
    except Exception:  # noqa: BLE001
        return False


# ── GVM object lookup helpers ─────────────────────────────────────────────────

def _find_config_id(gmp: Any) -> str | None:
    """Return the scan config UUID for _OV_CONFIG (name or UUID passthrough)."""
    if _UUID_RE.match(_OV_CONFIG):
        return _OV_CONFIG  # already a UUID — use directly
    configs = gmp.get_scan_configs()
    for cfg in configs.findall("config"):
        if cfg.findtext("name", "") == _OV_CONFIG:
            return cfg.get("id")
    return None


def _find_scanner_id(gmp: Any) -> str | None:
    scanners = gmp.get_scanners()
    for s in scanners.findall("scanner"):
        name = s.findtext("name", "").lower()
        if "openvas" in name or "default" in name:
            return s.get("id")
    return None


def _find_port_list_id(gmp: Any) -> str:
    """Return the UUID of 'All IANA assigned TCP' port list (fall back to hardcoded)."""
    _FALLBACK = "730ef368-57e2-11e1-a90f-406186ea4fc5"
    try:
        pls = gmp.get_port_lists()
        for pl in pls.findall("port_list"):
            name = pl.findtext("name", "").lower()
            if "all iana assigned tcp" in name or "all tcp and nmap" in name:
                return pl.get("id") or _FALLBACK
    except Exception:  # noqa: BLE001
        pass
    return _FALLBACK


# ── Waiting ───────────────────────────────────────────────────────────────────

def _wait_for_task(gmp: Any, task_id: str, timeout: int) -> str:
    """Poll until task reaches Done / Stopped / error. Returns final status."""
    elapsed = 0
    while elapsed < timeout:
        task = gmp.get_task(task_id=task_id)
        status = task.findtext("task/status", "")
        if status in ("Done", "Stopped", "Internal Error"):
            return status
        time.sleep(10)
        elapsed += 10
    return "Timeout"


# ── Result parsing ────────────────────────────────────────────────────────────

def _classify_nvt(name: str, cve: str) -> str:
    if cve:
        return "cve"
    n = name.lower()
    for kw, cat in [
        ("default credential",    "default_credentials"),
        ("weak password",         "weak_credentials"),
        ("ssl",                   "tls_issue"),
        ("tls",                   "tls_issue"),
        ("open port",             "open_port"),
        ("service detection",     "service_detection"),
        ("anonymous",             "anonymous_access"),
        ("brute",                 "brute_force_susceptible"),
        ("remote code",           "rce"),
        ("command injection",     "os_command"),
        ("sql injection",         "sqli"),
        ("xss",                   "xss"),
        ("directory traversal",   "path_traversal"),
        ("information disclosure","info_disclosure"),
        ("buffer overflow",       "buffer_overflow"),
    ]:
        if kw in n:
            return cat
    return "vulnerability"


def _results_to_findings(gmp: Any, task_id: str, target: str) -> list[DynamicFinding]:
    findings: list[DynamicFinding] = []
    # Fetch up to 1 000 results; GVM paginates with first/rows
    results_el = gmp.get_results(task_id=task_id, details=True)
    for result in results_el.findall("result"):
        name      = result.findtext("name",        "Unknown")
        desc      = result.findtext("description", "")
        host      = result.findtext("host",        target)
        port_text = result.findtext("port",        "")
        cvss_text = result.findtext("severity",    "0")
        nvt       = result.find("nvt")
        cve       = ""
        solution  = ""

        if nvt is not None:
            for ref in nvt.findall("refs/ref"):
                if ref.get("type", "").lower() == "cve" and not cve:
                    cve = ref.get("id", "").upper()
            solution = nvt.findtext("solution", "")

        try:
            cvss = float(cvss_text)
        except ValueError:
            cvss = 0.0

        sev = cvss_to_severity(cvss)

        port_num: int | None = None
        if port_text and port_text not in ("general/tcp", "general/udp", ""):
            try:
                port_num = int(port_text.split("/")[0])
            except ValueError:
                pass

        findings.append(DynamicFinding(
            tool="openvas",
            target=host or target,
            name=name,
            description=desc[:800],
            severity=sev,
            category=_classify_nvt(name, cve),
            evidence=f"CVSS: {cvss:.1f}" + (f" | CVE: {cve}" if cve else ""),
            port=port_num,
            cve=cve or None,
            remediation=solution[:400] if solution else None,
        ))
    return findings


# ── Cleanup helpers ───────────────────────────────────────────────────────────

def _cleanup(gmp: Any, task_id: str | None, target_id: str | None) -> None:
    """Best-effort removal of GVM task and target created for this scan."""
    try:
        if task_id:
            gmp.delete_task(task_id=task_id, ultimate=True)
    except Exception:  # noqa: BLE001
        pass
    try:
        if target_id:
            gmp.delete_target(target_id=target_id, ultimate=True)
    except Exception:  # noqa: BLE001
        pass


# ── Public scan function ──────────────────────────────────────────────────────

def scan(
    target: str,
    timeout: int = _OV_TIMEOUT,
    host: str | None = None,
    port: int | None = None,
    socket: str | None = None,
    user: str | None = None,
    password: str | None = None,
) -> list[DynamicFinding]:
    """Run a GVM full scan against *target* (hostname, IP or CIDR).

    Connection priority:
      1. ``socket`` argument / ``OPENVAS_SOCKET`` env var (Unix socket)
      2. ``host`` / ``port`` arguments (TLS/TCP)
      3. ``OPENVAS_HOST`` / ``OPENVAS_PORT`` env vars (TLS/TCP)

    Returns a list of :class:`~vulnscan.scanners.base.DynamicFinding` objects.
    Returns a single info-level finding if GVM is not installed or unreachable.
    """
    ov_user = user     or _OV_USER
    ov_pass = password or _OV_PASSWORD

    if not _GVM_AVAILABLE:
        return [DynamicFinding(
            tool="openvas", target=target,
            name="python-gvm not installed",
            description=(
                "Install with: pip install python-gvm\n"
                "Start GVM with Docker:\n"
                "  docker run -d --name openvas -p 9390:9390 greenbone/gvm"
            ),
            severity="info", category="scanner_unavailable",
        )]

    task_id:   str | None = None
    target_id: str | None = None

    try:
        with _connect(host=host, port=port, socket=socket) as gmp:
            gmp.authenticate(ov_user, ov_pass)

            config_id  = _find_config_id(gmp)
            scanner_id = _find_scanner_id(gmp)
            if not config_id or not scanner_id:
                return [DynamicFinding(
                    tool="openvas", target=target,
                    name="GVM scan config or scanner not found",
                    description=(
                        f"Could not find '{_OV_CONFIG}' config or an OpenVAS scanner in GVM. "
                        "GVM may still be initialising NVT feeds (this takes ~10 min on first start)."
                    ),
                    severity="info", category="scanner_error",
                )]

            port_list_id = _find_port_list_id(gmp)

            # Create ephemeral target
            t = gmp.create_target(
                name=f"vulnscan-{target}-{int(time.time())}",
                hosts=[target],
                port_list_id=port_list_id,
            )
            target_id = t.get("id")

            # Create and immediately start a task
            task = gmp.create_task(
                name=f"vulnscan-task-{int(time.time())}",
                config_id=config_id,
                target_id=target_id,
                scanner_id=scanner_id,
            )
            task_id = task.get("id")
            gmp.start_task(task_id=task_id)

            # Invalidate availability cache so next /health reflects running state
            _avail_cache["expires"] = 0.0

            status = _wait_for_task(gmp, task_id, timeout)

            if status == "Timeout":
                _cleanup(gmp, task_id, target_id)
                return [DynamicFinding(
                    tool="openvas", target=target,
                    name="OpenVAS scan timed out",
                    description=f"Scan task did not complete within {timeout}s.",
                    severity="info", category="scanner_error",
                )]

            if status != "Done":
                _cleanup(gmp, task_id, target_id)
                return [DynamicFinding(
                    tool="openvas", target=target,
                    name=f"OpenVAS scan ended: {status}",
                    description=f"GVM task status: {status}",
                    severity="info", category="scanner_error",
                )]

            findings = _results_to_findings(gmp, task_id, target)
            _cleanup(gmp, task_id, target_id)
            return findings

    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        if "Connection refused" in msg or "timed out" in msg.lower() or "No such file" in msg:
            sock_hint = _OV_SOCKET or (socket or "")
            conn_hint = (
                f"socket {sock_hint}" if sock_hint
                else f"{host or _OV_HOST}:{port or _OV_PORT}"
            )
            return [DynamicFinding(
                tool="openvas", target=target,
                name="GVM daemon not reachable",
                description=(
                    f"Could not connect to GVM at {conn_hint}: {exc}\n\n"
                    "Start GVM with Docker:\n"
                    "  docker run -d --name openvas -p 9390:9390 greenbone/gvm\n\n"
                    "Or set OPENVAS_SOCKET=/run/gvm/gvmd.sock if GVM runs locally."
                ),
                severity="info", category="scanner_unavailable",
            )]
        return [DynamicFinding(
            tool="openvas", target=target,
            name=f"OpenVAS error: {type(exc).__name__}",
            description=msg[:500],
            severity="info", category="scanner_error",
        )]
