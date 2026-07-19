"""OpenVAS / Greenbone Vulnerability Manager (GVM) scanner.

Uses python-gvm to connect to a running GVM daemon and run a full
vulnerability assessment.

Quick-start with Docker:
  docker run -d --name openvas -p 9390:9390 -p 80:80 \
    -e PUBLIC_HOSTNAME=localhost \
    greenbone/community-edition

Connection settings via env vars:
  OPENVAS_HOST     (default: localhost)
  OPENVAS_PORT     (default: 9390)
  OPENVAS_USER     (default: admin)
  OPENVAS_PASSWORD (default: admin)
  OPENVAS_TIMEOUT  (default: 1800)  — max seconds to wait for a scan task

Scan config:
  "Full and fast"  (the default GVM scan config) is used unless
  OPENVAS_SCAN_CONFIG env var is set to a different config name or UUID.
"""
from __future__ import annotations

import os
import sys
import time
from typing import Any

from .base import DynamicFinding, cvss_to_severity

_OV_HOST     = os.environ.get("OPENVAS_HOST",     "localhost")
_OV_PORT     = int(os.environ.get("OPENVAS_PORT",     "9390"))
_OV_USER     = os.environ.get("OPENVAS_USER",     "admin")
_OV_PASSWORD = os.environ.get("OPENVAS_PASSWORD", "admin")
_OV_TIMEOUT  = int(os.environ.get("OPENVAS_TIMEOUT",  "1800"))
_OV_CONFIG   = os.environ.get("OPENVAS_SCAN_CONFIG", "Full and fast")

try:
    from gvm.connections import TLSConnection  # type: ignore[import-untyped]
    from gvm.protocols.gmp import Gmp          # type: ignore[import-untyped]
    from gvm.transforms import EtreeTransform   # type: ignore[import-untyped]
    _GVM_AVAILABLE = True
except ImportError:
    _GVM_AVAILABLE = False


def is_available() -> bool:
    if not _GVM_AVAILABLE:
        return False
    try:
        with _connect() as gmp:
            gmp.authenticate(_OV_USER, _OV_PASSWORD)
            return True
    except Exception:  # noqa: BLE001
        return False


def _connect():
    conn = TLSConnection(hostname=_OV_HOST, port=_OV_PORT)
    return Gmp(connection=conn, transform=EtreeTransform())


def _find_config_id(gmp: Any) -> str | None:
    configs = gmp.get_scan_configs()
    for cfg in configs.findall("config"):
        name = cfg.findtext("name", "")
        if name == _OV_CONFIG:
            return cfg.get("id")
    return None


def _find_scanner_id(gmp: Any) -> str | None:
    scanners = gmp.get_scanners()
    for s in scanners.findall("scanner"):
        name = s.findtext("name", "")
        if "openvas" in name.lower() or "default" in name.lower():
            return s.get("id")
    return None


def _wait_for_task(gmp: Any, task_id: str, timeout: int) -> str:
    """Wait for GVM task to reach 'Done' status. Returns final status."""
    elapsed = 0
    while elapsed < timeout:
        task = gmp.get_task(task_id=task_id)
        status = task.findtext("task/status", "")
        if status in ("Done", "Stopped", "Internal Error"):
            return status
        time.sleep(10)
        elapsed += 10
    return "Timeout"


def _results_to_findings(gmp: Any, task_id: str, target: str) -> list[DynamicFinding]:
    findings: list[DynamicFinding] = []
    results_el = gmp.get_results(task_id=task_id, details=True)
    for result in results_el.findall("result"):
        name       = result.findtext("name",        "Unknown")
        desc       = result.findtext("description", "")
        host       = result.findtext("host",        target)
        port_text  = result.findtext("port",        "")
        cvss_text  = result.findtext("severity",    "0")
        nvt        = result.find("nvt")
        cve        = ""
        solution   = ""
        if nvt is not None:
            for ref in nvt.findall("refs/ref"):
                if ref.get("type") == "cve":
                    cve = ref.get("id", "")
                    break
            solution = nvt.findtext("solution", "")

        try:
            cvss = float(cvss_text)
        except ValueError:
            cvss = 0.0

        sev = cvss_to_severity(cvss)
        port_num: int | None = None
        if port_text and port_text != "general/tcp":
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


def _classify_nvt(name: str, cve: str) -> str:
    n = name.lower()
    if cve:
        return "cve"
    for kw, cat in [
        ("default credential", "default_credentials"),
        ("weak password",      "weak_credentials"),
        ("ssl",                "tls_issue"),
        ("tls",                "tls_issue"),
        ("open port",          "open_port"),
        ("service detection",  "service_detection"),
        ("anonymous",          "anonymous_access"),
        ("brute",              "brute_force_susceptible"),
    ]:
        if kw in n:
            return cat
    return "vulnerability"


def scan(
    target: str,
    timeout: int = _OV_TIMEOUT,
    host: str | None = None,
    port: int | None = None,
    user: str | None = None,
    password: str | None = None,
) -> list[DynamicFinding]:
    """Run a GVM full scan against `target` (host or CIDR).

    Returns [] with an info finding if GVM is not installed or not reachable.
    """
    ov_host = host or _OV_HOST
    ov_port = port or _OV_PORT
    ov_user = user or _OV_USER
    ov_pass = password or _OV_PASSWORD

    if not _GVM_AVAILABLE:
        return [DynamicFinding(
            tool="openvas", target=target,
            name="python-gvm not installed",
            description=(
                "Install with: pip install python-gvm\n"
                "Start GVM with Docker: docker run -d --name openvas -p 9390:9390 "
                "greenbone/community-edition"
            ),
            severity="info", category="scanner_unavailable",
        )]

    task_id: str | None = None
    target_id: str | None = None

    try:
        conn = TLSConnection(hostname=ov_host, port=ov_port)
        with Gmp(connection=conn, transform=EtreeTransform()) as gmp:
            gmp.authenticate(ov_user, ov_pass)

            config_id  = _find_config_id(gmp)
            scanner_id = _find_scanner_id(gmp)
            if not config_id or not scanner_id:
                return [DynamicFinding(
                    tool="openvas", target=target,
                    name="GVM scan config or scanner not found",
                    description=f"Could not find '{_OV_CONFIG}' config or OpenVAS scanner in GVM.",
                    severity="info", category="scanner_error",
                )]

            # Create target
            t = gmp.create_target(
                name=f"vulnscan-{target}-{int(time.time())}",
                hosts=[target],
                port_list_id="730ef368-57e2-11e1-a90f-406186ea4fc5",  # "All IANA assigned TCP"
            )
            target_id = t.get("id")

            # Create and start task
            task = gmp.create_task(
                name=f"vulnscan-task-{int(time.time())}",
                config_id=config_id,
                target_id=target_id,
                scanner_id=scanner_id,
            )
            task_id = task.get("id")
            gmp.start_task(task_id=task_id)

            # Wait
            status = _wait_for_task(gmp, task_id, timeout)
            if status == "Timeout":
                return [DynamicFinding(
                    tool="openvas", target=target,
                    name="OpenVAS scan timed out",
                    description=f"Scan task {task_id} did not complete within {timeout}s.",
                    severity="info", category="scanner_error",
                )]
            if status != "Done":
                return [DynamicFinding(
                    tool="openvas", target=target,
                    name=f"OpenVAS scan ended: {status}",
                    description=f"Task status: {status}",
                    severity="info", category="scanner_error",
                )]

            return _results_to_findings(gmp, task_id, target)

    except Exception as exc:  # noqa: BLE001
        if "Connection refused" in str(exc) or "timed out" in str(exc).lower():
            return [DynamicFinding(
                tool="openvas", target=target,
                name="GVM daemon not reachable",
                description=(
                    f"Could not connect to GVM at {ov_host}:{ov_port}: {exc}\n"
                    f"Start with Docker: docker run -d -p 9390:9390 greenbone/community-edition"
                ),
                severity="info", category="scanner_unavailable",
            )]
        return [DynamicFinding(
            tool="openvas", target=target,
            name=f"OpenVAS error: {type(exc).__name__}",
            description=str(exc)[:500],
            severity="info", category="scanner_error",
        )]
