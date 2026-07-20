"""SSLyze TLS/SSL configuration scanner.

Performs deep TLS analysis against a host:
  - Deprecated protocol detection (SSL 2/3, TLS 1.0/1.1)
  - Certificate issues (expiry, trust, hostname mismatch)
  - Heartbleed (CVE-2014-0160)
  - ROBOT attack
  - CRIME (TLS compression)
  - OpenSSL CCS injection (CVE-2014-0224)
  - Insecure session renegotiation

Install:
  pip install sslyze

Works on any TLS port. Skips plain-HTTP targets gracefully.
"""
from __future__ import annotations

import datetime
import urllib.parse
from typing import Any

from .base import DynamicFinding

TOOL = "sslyze"

try:
    from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation  # type: ignore[import-untyped]
    from sslyze.plugins.scan_commands import ScanCommand                   # type: ignore[import-untyped]
    _SSLYZE_AVAILABLE = True
except ImportError:
    _SSLYZE_AVAILABLE = False


def is_available() -> bool:
    return _SSLYZE_AVAILABLE


def scan(target: str, options: dict[str, Any] | None = None) -> list[DynamicFinding]:
    """Scan *target* (URL or host[:port]) for TLS/SSL weaknesses."""
    if not _SSLYZE_AVAILABLE:
        return [DynamicFinding(
            tool=TOOL, target=target,
            name="sslyze not installed",
            description="Install with: pip install sslyze",
            severity="info", category="scanner_unavailable",
        )]

    hostname, port, skipped = _parse_target(target)
    if skipped:
        return [DynamicFinding(
            tool=TOOL, target=target,
            name="TLS scan skipped — plain HTTP target",
            description=f"SSLyze only tests TLS. {target} appears to be plain HTTP. "
                        "Switch to HTTPS or specify a TLS port.",
            severity="info", category="scanner_info",
        )]

    try:
        return _run_scan(target, hostname, port)
    except Exception as exc:  # noqa: BLE001
        return [DynamicFinding(
            tool=TOOL, target=target,
            name=f"SSLyze error: {type(exc).__name__}",
            description=str(exc)[:500],
            severity="info", category="scanner_error",
        )]


# ── Target parsing ────────────────────────────────────────────────────────────

def _parse_target(target: str) -> tuple[str, int, bool]:
    """Return (hostname, port, skip_because_plaintext)."""
    if "://" in target:
        p = urllib.parse.urlparse(target)
        if p.scheme == "http" and not p.port:
            return p.hostname or target, 80, True   # plain HTTP, no explicit port
        hostname = p.hostname or target
        port = p.port or (443 if p.scheme == "https" else 443)
        return hostname, port, False
    # host or host:port
    if ":" in target:
        host, _, port_str = target.rpartition(":")
        try:
            return host, int(port_str), False
        except ValueError:
            pass
    return target, 443, False


# ── Core scan ─────────────────────────────────────────────────────────────────

_SCAN_COMMANDS = None  # populated lazily after import check


def _get_commands() -> set:
    return {
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.HEARTBLEED,
        ScanCommand.ROBOT,
        ScanCommand.TLS_COMPRESSION,
        ScanCommand.TLS_FALLBACK_SCSV,
        ScanCommand.SESSION_RENEGOTIATION,
        ScanCommand.OPENSSL_CCS_INJECTION,
    }


def _run_scan(target: str, hostname: str, port: int) -> list[DynamicFinding]:
    findings: list[DynamicFinding] = []

    location = ServerNetworkLocation(hostname=hostname, port=port)
    request  = ServerScanRequest(server_location=location, scan_commands=_get_commands())

    scanner = Scanner()
    scanner.queue_scans([request])

    for result in scanner.get_results():
        # Connection failure
        if result.scan_result is None:
            err = getattr(result, "connectivity_error_trace", None)
            findings.append(DynamicFinding(
                tool=TOOL, target=target,
                name=f"TLS connection failed to {hostname}:{port}",
                description=str(err) if err else "Could not establish TLS connection.",
                severity="info", category="scanner_error",
            ))
            return findings

        sr = result.scan_result

        # ── Deprecated protocols ──────────────────────────────────────────────
        _check_old_protocol(findings, target, sr, "ssl_2_0_cipher_suites",
                            "SSL 2.0 supported",
                            "SSL 2.0 is broken and deprecated since 1996. Connections can be "
                            "decrypted using DROWN and similar attacks.",
                            "critical", "weak_tls_protocol")

        _check_old_protocol(findings, target, sr, "ssl_3_0_cipher_suites",
                            "SSL 3.0 supported",
                            "SSL 3.0 is vulnerable to POODLE (CVE-2014-3566) and should be disabled.",
                            "high", "weak_tls_protocol", cve="CVE-2014-3566")

        _check_old_protocol(findings, target, sr, "tls_1_0_cipher_suites",
                            "TLS 1.0 supported",
                            "TLS 1.0 is deprecated (RFC 8996) and vulnerable to BEAST. "
                            "PCI-DSS and most compliance frameworks require it to be disabled.",
                            "medium", "weak_tls_protocol")

        _check_old_protocol(findings, target, sr, "tls_1_1_cipher_suites",
                            "TLS 1.1 supported",
                            "TLS 1.1 is deprecated (RFC 8996). While less severe than 1.0, "
                            "it lacks important security improvements present in TLS 1.2+.",
                            "medium", "weak_tls_protocol")

        # ── Certificate checks ────────────────────────────────────────────────
        cert_scan = getattr(sr, "certificate_info", None)
        if cert_scan and getattr(cert_scan, "result", None):
            _check_certificates(findings, target, cert_scan.result)

        # ── Heartbleed ────────────────────────────────────────────────────────
        hb = getattr(sr, "heartbleed", None)
        if hb and getattr(hb, "result", None):
            if hb.result.is_vulnerable_to_heartbleed:
                findings.append(DynamicFinding(
                    tool=TOOL, target=target,
                    name="Heartbleed vulnerability (CVE-2014-0160)",
                    description="The server is vulnerable to Heartbleed. An attacker can read "
                                "up to 64KB of server memory per request, leaking private keys, "
                                "session tokens, and plaintext data.",
                    severity="critical", category="cve",
                    cve="CVE-2014-0160",
                    remediation="Upgrade OpenSSL to 1.0.1g or later and regenerate all TLS certificates.",
                ))

        # ── ROBOT ─────────────────────────────────────────────────────────────
        robot = getattr(sr, "robot", None)
        if robot and getattr(robot, "result", None):
            robot_result = robot.result.robot_result.name  # e.g. VULNERABLE_WEAK_ORACLE
            if "VULNERABLE" in robot_result:
                findings.append(DynamicFinding(
                    tool=TOOL, target=target,
                    name="ROBOT attack vulnerability",
                    description="The server is vulnerable to the Return Of Bleichenbacher's Oracle "
                                "Threat (ROBOT). Attackers can perform RSA decryption and signing "
                                "operations with the server's private key.",
                    severity="high", category="vulnerability",
                    evidence=f"ROBOT oracle: {robot_result}",
                    remediation="Disable RSA key exchange cipher suites. Use ECDHE or DHE exclusively.",
                ))

        # ── TLS compression (CRIME) ───────────────────────────────────────────
        comp = getattr(sr, "tls_compression", None)
        if comp and getattr(comp, "result", None):
            if comp.result.supports_compression:
                findings.append(DynamicFinding(
                    tool=TOOL, target=target,
                    name="TLS compression enabled (CRIME)",
                    description="TLS compression is enabled, making the server vulnerable to the "
                                "CRIME attack (CVE-2012-4929). Attackers who can inject data into "
                                "TLS sessions can recover plaintext such as session cookies.",
                    severity="medium", category="vulnerability",
                    cve="CVE-2012-4929",
                    remediation="Disable TLS-level compression in your SSL/TLS library configuration.",
                ))

        # ── OpenSSL CCS injection ─────────────────────────────────────────────
        ccs = getattr(sr, "openssl_ccs_injection", None)
        if ccs and getattr(ccs, "result", None):
            if ccs.result.is_vulnerable_to_ccs_injection:
                findings.append(DynamicFinding(
                    tool=TOOL, target=target,
                    name="OpenSSL CCS injection (CVE-2014-0224)",
                    description="The server is vulnerable to the OpenSSL ChangeCipherSpec injection "
                                "vulnerability. Attackers in a man-in-the-middle position can force "
                                "the use of weak keying material, enabling session decryption.",
                    severity="high", category="cve",
                    cve="CVE-2014-0224",
                    remediation="Upgrade OpenSSL to 0.9.8za, 1.0.0m, or 1.0.1h or later.",
                ))

        # ── Insecure renegotiation ────────────────────────────────────────────
        reneg = getattr(sr, "session_renegotiation", None)
        if reneg and getattr(reneg, "result", None):
            if not reneg.result.supports_secure_renegotiation:
                findings.append(DynamicFinding(
                    tool=TOOL, target=target,
                    name="Insecure TLS renegotiation supported",
                    description="The server supports insecure TLS renegotiation (CVE-2009-3555). "
                                "This can allow man-in-the-middle attackers to inject plaintext "
                                "into TLS sessions.",
                    severity="medium", category="vulnerability",
                    cve="CVE-2009-3555",
                    remediation="Enable secure renegotiation (RFC 5746) and disable legacy renegotiation.",
                ))
            elif reneg.result.is_vulnerable_to_client_renegotiation_dos:
                findings.append(DynamicFinding(
                    tool=TOOL, target=target,
                    name="Client-initiated renegotiation DoS risk",
                    description="The server allows unlimited client-initiated renegotiations. "
                                "This can be abused to exhaust server CPU (DoS).",
                    severity="low", category="vulnerability",
                    remediation="Rate-limit or disable client-initiated TLS renegotiation.",
                ))

    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _check_old_protocol(
    findings: list[DynamicFinding],
    target: str,
    sr: Any,
    attr: str,
    name: str,
    description: str,
    severity: str,
    category: str,
    cve: str | None = None,
) -> None:
    proto_scan = getattr(sr, attr, None)
    if proto_scan is None or getattr(proto_scan, "result", None) is None:
        return
    accepted = getattr(proto_scan.result, "accepted_cipher_suites", [])
    if accepted:
        cipher_names = ", ".join(
            getattr(getattr(cs, "cipher_suite", None), "name", "unknown")
            for cs in accepted[:5]
        )
        findings.append(DynamicFinding(
            tool=TOOL, target=target,
            name=name,
            description=description,
            severity=severity,  # type: ignore[arg-type]
            category=category,
            evidence=f"Accepted cipher suites: {cipher_names}",
            cve=cve,
            remediation="Disable this protocol version in your TLS configuration. "
                        "Require TLS 1.2 as the minimum.",
        ))


def _check_certificates(findings: list[DynamicFinding], target: str, result: Any) -> None:
    deployments = getattr(result, "certificate_deployments", [])
    for dep in deployments:
        chain = getattr(dep, "received_certificate_chain", [])
        if not chain:
            continue
        leaf = chain[0]

        # Expiry
        try:
            not_after = leaf.not_valid_after_utc
        except AttributeError:
            try:
                not_after = leaf.not_valid_after
                if not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=datetime.timezone.utc)
            except AttributeError:
                not_after = None

        if not_after is not None:
            now = datetime.datetime.now(datetime.timezone.utc)
            days_left = (not_after - now).days
            if days_left < 0:
                findings.append(DynamicFinding(
                    tool=TOOL, target=target,
                    name="TLS certificate expired",
                    description=f"The certificate expired {abs(days_left)} day(s) ago "
                                f"(not_valid_after: {not_after.date()}).",
                    severity="critical", category="tls_certificate",
                    remediation="Renew the TLS certificate immediately.",
                ))
            elif days_left < 30:
                findings.append(DynamicFinding(
                    tool=TOOL, target=target,
                    name=f"TLS certificate expiring in {days_left} day(s)",
                    description=f"The certificate expires on {not_after.date()}.",
                    severity="high" if days_left < 7 else "medium",
                    category="tls_certificate",
                    remediation="Renew the TLS certificate before it expires.",
                ))

        # Trust chain
        verified_chain = getattr(dep, "verified_certificate_chain", None)
        path_validation = getattr(dep, "path_validation_results", [])
        any_failed = any(
            not getattr(r, "was_validation_successful", True)
            for r in path_validation
        )
        if verified_chain is None or any_failed:
            findings.append(DynamicFinding(
                tool=TOOL, target=target,
                name="TLS certificate not trusted",
                description="The certificate chain could not be validated against a trusted CA store. "
                            "This may indicate a self-signed certificate or a broken chain.",
                severity="high", category="tls_certificate",
                remediation="Use a certificate from a publicly trusted CA (e.g. Let's Encrypt). "
                            "Ensure the full chain including intermediates is served.",
            ))

        # Hostname match
        hostname_match = getattr(dep, "leaf_certificate_subject_matches_hostname", True)
        if not hostname_match:
            try:
                subject = leaf.subject.rfc4514_string()
            except Exception:  # noqa: BLE001
                subject = "(unknown subject)"
            findings.append(DynamicFinding(
                tool=TOOL, target=target,
                name="TLS certificate hostname mismatch",
                description=f"The certificate subject ({subject}) does not match the target hostname. "
                            "Browsers will reject this connection with a security warning.",
                severity="high", category="tls_certificate",
                remediation="Use a certificate that covers the correct hostname (or a wildcard/SAN cert).",
            ))
