"""OWASP ZAP scanner — DAST for web apps and APIs.

Connects to a running ZAP daemon via its REST API. ZAP must be started
externally (e.g. `zap.sh -daemon -port 8080`) or managed via Docker.

Flow:
  1. Spider/AJAX-spider the target URL.
  2. Run passive scan (collected during spider).
  3. Run active scan (optional — takes longer, more thorough).
  4. Collect alerts → DynamicFinding list.

Docker quick-start (no ZAP installation needed):
  docker run -u zap -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable \
    zap.sh -daemon -host 0.0.0.0 -port 8080 \
    -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true \
    -config api.disablekey=true

ZAP API key: set via ZAP_API_KEY env var (or leave empty if key is disabled).
ZAP host/port: set via ZAP_HOST (default: localhost) and ZAP_PORT (default: 8080).
"""
from __future__ import annotations

import os
import sys
import time
from typing import Any

from .base import DynamicFinding, ZAP_RISK_MAP, Severity

try:
    from zapv2 import ZAPv2  # type: ignore[import-untyped]
    _ZAP_AVAILABLE = True
except ImportError:
    _ZAP_AVAILABLE = False

_ZAP_HOST    = os.environ.get("ZAP_HOST",    "localhost")
_ZAP_PORT    = int(os.environ.get("ZAP_PORT",    "8080"))
_ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")

# ZAP alert confidence → include/exclude filter
_MIN_CONFIDENCE = {"False Positive": -1, "Low": 0, "Medium": 1, "High": 2}
_EXCLUDE_CONFIDENCE = {"False Positive"}


def is_available() -> bool:
    """Return True if the ZAP package is installed and the daemon is reachable."""
    if not _ZAP_AVAILABLE:
        return False
    try:
        zap = _connect()
        zap.core.version()
        return True
    except Exception:  # noqa: BLE001
        return False


def _connect() -> "ZAPv2":
    proxies = {"http": f"http://{_ZAP_HOST}:{_ZAP_PORT}",
               "https": f"http://{_ZAP_HOST}:{_ZAP_PORT}"}
    return ZAPv2(apikey=_ZAP_API_KEY, proxies=proxies)


def _wait_for_scan(zap: "ZAPv2", scan_id: str, kind: str = "ascan",
                   poll_seconds: float = 2.0, timeout: int = 600) -> None:
    elapsed = 0.0
    while elapsed < timeout:
        if kind == "ascan":
            progress = int(zap.ascan.status(scan_id))
        else:
            progress = int(zap.spider.status(scan_id))
        if progress >= 100:
            return
        time.sleep(poll_seconds)
        elapsed += poll_seconds
    raise TimeoutError(f"ZAP {kind} scan {scan_id} timed out after {timeout}s")


def _alerts_to_findings(alerts: list[dict], target: str) -> list[DynamicFinding]:
    findings: list[DynamicFinding] = []
    for alert in alerts:
        confidence = alert.get("confidence", "Low")
        if confidence in _EXCLUDE_CONFIDENCE:
            continue
        risk      = alert.get("risk",      "Informational")
        name      = alert.get("name",      "Unknown alert")
        desc      = alert.get("description", "")
        solution  = alert.get("solution",  "")
        url       = alert.get("url",       "")
        evidence  = alert.get("evidence",  "")
        param     = alert.get("param",     "")
        cweid     = alert.get("cweid",     "")
        wascid    = alert.get("wascid",    "")
        severity: Severity = ZAP_RISK_MAP.get(risk, "info")  # type: ignore[assignment]

        # Elevate to "critical" for known critical alert names
        name_lower = name.lower()
        if any(k in name_lower for k in ("sql injection", "os command", "remote code", "xxe", "deserialization")):
            if severity in ("high", "medium"):
                severity = "critical"

        category = _classify_alert(name, cweid)
        detail_parts = [desc]
        if param:
            detail_parts.append(f"Parameter: {param}")
        if cweid:
            detail_parts.append(f"CWE-{cweid}")
        if wascid:
            detail_parts.append(f"WASC-{wascid}")

        findings.append(DynamicFinding(
            tool="zap",
            target=target,
            name=name,
            description="\n".join(detail_parts)[:800],
            severity=severity,
            category=category,
            evidence=f"{evidence[:200]} | URL: {url}".strip(" |"),
            url=url or None,
            remediation=solution[:400] if solution else None,
        ))
    return findings


def _classify_alert(name: str, cweid: str) -> str:
    n = name.lower()
    cwe_map: dict[str, str] = {
        "89":  "sql_injection",
        "79":  "xss",
        "78":  "os_command_injection",
        "611": "xxe",
        "918": "ssrf",
        "22":  "path_traversal",
        "502": "unsafe_deserialization",
        "352": "csrf",
        "601": "open_redirect",
        "200": "information_disclosure",
        "311": "missing_encryption",
        "319": "cleartext_transmission",
        "16":  "security_misconfiguration",
    }
    if cweid in cwe_map:
        return cwe_map[cweid]
    for kw, cat in [
        ("sql", "sql_injection"), ("xss", "xss"), ("command", "os_command_injection"),
        ("xxe", "xxe"), ("ssrf", "ssrf"), ("traversal", "path_traversal"),
        ("deseri", "unsafe_deserialization"), ("csrf", "csrf"),
        ("header", "missing_security_header"), ("redirect", "open_redirect"),
        ("csrf", "csrf"), ("cors", "cors_misconfiguration"),
        ("tls", "tls_issue"), ("ssl", "tls_issue"), ("cookie", "insecure_cookie"),
        ("disclosure", "information_disclosure"),
    ]:
        if kw in n:
            return cat
    return "web_vulnerability"


def scan(
    target_url: str,
    active: bool = True,
    ajax_spider: bool = False,
    timeout: int = 600,
) -> list[DynamicFinding]:
    """Spider + optionally active-scan `target_url` using ZAP.

    Returns [] with an info finding if ZAP is not installed or not running.
    """
    if not _ZAP_AVAILABLE:
        print("warning: zaproxy package not installed", file=sys.stderr)
        return [DynamicFinding(
            tool="zap", target=target_url,
            name="zaproxy package not installed",
            description="Install with: pip install zaproxy. Then start ZAP: docker run -u zap -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -port 8080 -config api.disablekey=true",
            severity="info", category="scanner_unavailable",
        )]

    try:
        zap = _connect()
        version = zap.core.version()
    except Exception as exc:  # noqa: BLE001
        return [DynamicFinding(
            tool="zap", target=target_url,
            name="ZAP daemon not reachable",
            description=(
                f"Could not connect to ZAP at {_ZAP_HOST}:{_ZAP_PORT}: {exc}\n"
                f"Start ZAP with: docker run -u zap -p 8080:8080 "
                f"ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -port 8080 "
                f"-config api.disablekey=true\n"
                f"Set ZAP_HOST/ZAP_PORT/ZAP_API_KEY env vars if needed."
            ),
            severity="info", category="scanner_unavailable",
        )]

    try:
        # Clear previous session
        zap.core.new_session(name="vulnscan", overwrite=True)

        # Access the target to seed the session
        zap.core.access_url(target_url, followredirects=True)
        time.sleep(1)

        # Spider
        spider_id = zap.spider.scan(target_url, maxchildren=None, recurse=True,
                                    contextname=None, subtreeonly=False)
        _wait_for_scan(zap, spider_id, "spider", timeout=min(timeout // 2, 180))

        # Optional AJAX spider for SPAs
        if ajax_spider:
            zap.ajaxSpider.scan(target_url)
            elapsed = 0
            while elapsed < 120:
                if zap.ajaxSpider.status() in ("stopped", "stop"):
                    break
                time.sleep(3); elapsed += 3

        # Wait for passive scan to catch up
        time.sleep(5)

        # Active scan
        if active:
            ascan_id = zap.ascan.scan(target_url, recurse=True, inscopeonly=False)
            _wait_for_scan(zap, ascan_id, "ascan", timeout=timeout)

        # Collect alerts
        alerts = zap.core.alerts(baseurl=target_url, start=0, count=1000)
        return _alerts_to_findings(alerts, target_url)

    except TimeoutError as exc:
        return [DynamicFinding(
            tool="zap", target=target_url,
            name="ZAP scan timed out",
            description=str(exc),
            severity="info", category="scanner_error",
        )]
    except Exception as exc:  # noqa: BLE001
        return [DynamicFinding(
            tool="zap", target=target_url,
            name=f"ZAP scan error: {type(exc).__name__}",
            description=str(exc)[:500],
            severity="info", category="scanner_error",
        )]
