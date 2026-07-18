"""Built-in HTTP security scanner.

Checks a URL for common web security issues without needing an external tool:
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- Insecure scheme / unforced HTTPS
- Server banner disclosure
- Cookie security flags
- TLS/redirect behaviour
- Basic sensitive path probing (/.env, /backup.zip, etc.)

Uses only httpx (already a dependency).
"""
from __future__ import annotations

import ssl
import urllib.parse
from typing import Any

import httpx

from .base import DynamicFinding

TOOL = "http"


def is_available() -> bool:
    return True  # pure-Python, always available


def scan(url: str, options: dict[str, Any] | None = None) -> list[DynamicFinding]:
    opts = options or {}
    timeout = opts.get("timeout", 15)
    probe_paths = opts.get("probe_paths", True)

    findings: list[DynamicFinding] = []

    # Normalise URL
    if not url.startswith("http"):
        url = "http://" + url

    parsed = urllib.parse.urlparse(url)

    # ── 1. Fetch the root URL (follow redirects) ───────────────────────────────
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=True) as client:
            resp = client.get(url)
    except httpx.ConnectError as exc:
        findings.append(_finding(
            url, "Connection refused",
            f"Could not connect to {url}: {exc}",
            "high", "network_error",
            remediation="Verify the server is reachable and listening on the expected port.",
        ))
        return findings
    except httpx.RequestError as exc:
        findings.append(_finding(
            url, "Request error",
            str(exc), "medium", "network_error",
        ))
        return findings

    final_url = str(resp.url)
    headers = {k.lower(): v for k, v in resp.headers.items()}

    # ── 2. HTTPS enforcement ───────────────────────────────────────────────────
    if parsed.scheme == "http":
        if final_url.startswith("https://"):
            # Redirect exists — check it's permanent
            if resp.history and resp.history[0].status_code not in (301, 308):
                findings.append(_finding(
                    url, "Non-permanent HTTP→HTTPS redirect",
                    f"HTTP redirects to HTTPS using status {resp.history[0].status_code}. "
                    "Browsers won't cache temporary redirects, leaving users vulnerable to "
                    "downgrade attacks on first visit.",
                    "medium", "insecure_transport",
                    remediation="Use a 301 or 308 permanent redirect from HTTP to HTTPS.",
                ))
        else:
            findings.append(_finding(
                url, "Site served over plain HTTP",
                "The site does not redirect HTTP to HTTPS. All traffic including "
                "credentials and session cookies is transmitted in cleartext.",
                "high", "insecure_transport",
                remediation="Enable HTTPS and add a 301 redirect from HTTP to HTTPS. "
                            "Obtain a free certificate via Let's Encrypt.",
            ))

    # ── 3. HSTS ───────────────────────────────────────────────────────────────
    hsts = headers.get("strict-transport-security")
    if final_url.startswith("https://"):
        if not hsts:
            findings.append(_finding(
                final_url, "Missing Strict-Transport-Security header",
                "HSTS is not set. Browsers will not enforce HTTPS on subsequent visits, "
                "leaving users vulnerable to SSL-stripping attacks.",
                "medium", "missing_security_header",
                remediation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            ))
        else:
            # Check max-age
            try:
                max_age = int(next(
                    p.split("=")[1] for p in hsts.split(";")
                    if "max-age" in p.lower()
                ))
                if max_age < 86400:
                    findings.append(_finding(
                        final_url, "HSTS max-age too short",
                        f"HSTS max-age is {max_age}s (< 1 day). Browsers expire HSTS protection quickly.",
                        "low", "weak_security_header",
                        remediation="Set max-age to at least 31536000 (1 year).",
                    ))
            except (StopIteration, ValueError, IndexError):
                pass

    # ── 4. Content-Security-Policy ────────────────────────────────────────────
    csp = headers.get("content-security-policy")
    if not csp:
        findings.append(_finding(
            final_url, "Missing Content-Security-Policy header",
            "No CSP header found. Without CSP, the browser has no restrictions on "
            "inline script execution, making XSS attacks significantly more impactful.",
            "medium", "missing_security_header",
            remediation="Add a Content-Security-Policy header. Start with: "
                        "Content-Security-Policy: default-src 'self'",
        ))
    elif "unsafe-inline" in csp and "script-src" in csp:
        findings.append(_finding(
            final_url, "CSP allows unsafe-inline scripts",
            "The Content-Security-Policy includes 'unsafe-inline' for script-src, "
            "which negates XSS protection.",
            "medium", "weak_security_header",
            remediation="Remove 'unsafe-inline' from script-src. Use nonces or hashes instead.",
        ))

    # ── 5. X-Frame-Options ────────────────────────────────────────────────────
    xfo = headers.get("x-frame-options")
    csp_frame = "frame-ancestors" in (csp or "")
    if not xfo and not csp_frame:
        findings.append(_finding(
            final_url, "Missing X-Frame-Options / frame-ancestors",
            "The page can be embedded in an iframe on any domain, enabling clickjacking attacks.",
            "medium", "missing_security_header",
            remediation="Add X-Frame-Options: DENY or SAMEORIGIN, or use "
                        "Content-Security-Policy: frame-ancestors 'none'",
        ))

    # ── 6. X-Content-Type-Options ─────────────────────────────────────────────
    xcto = headers.get("x-content-type-options", "")
    if "nosniff" not in xcto.lower():
        findings.append(_finding(
            final_url, "Missing X-Content-Type-Options: nosniff",
            "Without this header, older browsers may MIME-sniff responses and execute "
            "content as a different type (e.g. treat a text file as JavaScript).",
            "low", "missing_security_header",
            remediation="Add: X-Content-Type-Options: nosniff",
        ))

    # ── 7. Server banner ──────────────────────────────────────────────────────
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    for banner_header, banner_val in [("Server", server), ("X-Powered-By", powered)]:
        if banner_val and any(ch.isdigit() for ch in banner_val):
            findings.append(_finding(
                final_url, f"Version disclosure in {banner_header} header",
                f"The response includes '{banner_header}: {banner_val}', revealing the "
                "server software version. Attackers use this to target known CVEs.",
                "low", "information_disclosure",
                remediation=f"Remove or genericise the {banner_header} header in your web server config.",
            ))

    # ── 8. Cookie security flags ──────────────────────────────────────────────
    for sc in resp.cookies.jar:
        name = sc.name
        missing: list[str] = []
        if final_url.startswith("https://") and not sc.secure:
            missing.append("Secure")
        if not sc.has_nonstandard_attr("HttpOnly"):
            missing.append("HttpOnly")
        if not sc.has_nonstandard_attr("SameSite"):
            missing.append("SameSite")
        if missing:
            findings.append(_finding(
                final_url,
                f"Cookie '{name}' missing security flags: {', '.join(missing)}",
                f"The cookie '{name}' is set without {', '.join(missing)} flag(s). "
                "Missing Secure allows theft over HTTP. Missing HttpOnly enables JS theft. "
                "Missing SameSite enables CSRF.",
                "medium", "insecure_cookie",
                remediation=f"Set the cookie with: Set-Cookie: {name}=...; Secure; HttpOnly; SameSite=Strict",
            ))

    # ── 9. Sensitive path probing ─────────────────────────────────────────────
    if probe_paths:
        sensitive_paths = [
            ("/.env",              "Environment file exposed",        "critical"),
            ("/.git/config",       "Git repository exposed",          "critical"),
            ("/backup.zip",        "Backup archive exposed",          "high"),
            ("/backup.sql",        "Database backup exposed",         "critical"),
            ("/phpinfo.php",       "PHP info page exposed",           "high"),
            ("/wp-config.php.bak", "WordPress config backup exposed", "critical"),
            ("/server-status",     "Apache server-status exposed",    "medium"),
            ("/actuator",          "Spring Boot actuator exposed",    "high"),
            ("/actuator/env",      "Spring Boot env actuator exposed","critical"),
            ("/.DS_Store",         "macOS .DS_Store file exposed",    "low"),
            ("/robots.txt",        None,                              "info"),   # just collect
        ]
        base = f"{parsed.scheme}://{parsed.netloc}"
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as probe_client:
            for path, label, sev in sensitive_paths:
                try:
                    r = probe_client.get(base + path)
                    if r.status_code in (200, 206) and label:
                        body_preview = r.text[:200].strip()
                        findings.append(_finding(
                            base + path,
                            label,
                            f"GET {path} returned HTTP {r.status_code}. "
                            f"Preview: {body_preview[:120]}",
                            sev, "sensitive_file_exposed",
                            remediation=f"Block access to {path} via your web server or firewall. "
                                        "Remove the file from the server if it is not needed.",
                        ))
                except httpx.RequestError:
                    pass

    return findings


# ── Helpers ────────────────────────────────────────────────────────────────────

def _finding(
    url: str,
    name: str,
    description: str,
    severity: str,
    category: str,
    remediation: str | None = None,
    evidence: str | None = None,
) -> DynamicFinding:
    return DynamicFinding(
        tool=TOOL,
        target=url,
        name=name,
        description=description,
        severity=severity,  # type: ignore[arg-type]
        category=category,
        evidence=evidence or "",
        url=url,
        port=None,
        cve=None,
        remediation=remediation,
    )
