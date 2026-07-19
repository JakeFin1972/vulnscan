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
    resp = None
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
        # Still run path probes — server may be slow on root but respond on specific paths
    except httpx.TimeoutException:
        findings.append(_finding(
            url, "Request timeout",
            f"GET {url} timed out after {timeout}s. Server may be slow or rate-limiting.",
            "info", "network_error",
        ))
        # Continue to path probes despite timeout
    except httpx.RequestError as exc:
        findings.append(_finding(
            url, "Request error",
            str(exc), "medium", "network_error",
        ))

    final_url = str(resp.url) if resp is not None else url
    headers = {k.lower(): v for k, v in resp.headers.items()} if resp is not None else {}

    # ── 2. HTTPS enforcement ───────────────────────────────────────────────────
    if resp is not None and parsed.scheme == "http":
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
    else:
        # Parse directives to check script-src specifically
        csp_directives = {
            d.strip().split()[0].lower(): d.strip()
            for d in csp.split(";") if d.strip()
        }
        script_src = csp_directives.get("script-src", csp_directives.get("default-src", ""))
        if "'unsafe-inline'" in script_src:
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
    for sc in (resp.cookies.jar if resp is not None else []):
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
    # Each entry: (path, label, severity, content_validator)
    # content_validator(body: str) -> bool  — returns True only if the body
    # looks like the actual file, not a generic 200 (SPA fallback, error page…)
    if probe_paths:
        def _is_env(b: str) -> bool:
            return bool(b) and "=" in b and not b.lstrip().startswith("<")

        def _is_git_config(b: str) -> bool:
            return "[core]" in b or "[remote" in b

        def _is_sql(b: str) -> bool:
            t = b.upper()
            return "INSERT INTO" in t or "CREATE TABLE" in t or "-- MySQL" in t

        def _is_php_info(b: str) -> bool:
            return "phpinfo()" in b or "PHP Version" in b

        def _is_server_status(b: str) -> bool:
            return "Apache Server Status" in b or "requests currently being processed" in b

        def _is_actuator(b: str) -> bool:
            return '"_links"' in b or '"status"' in b

        def _is_ds_store(b: bytes) -> bool:
            return b[:4] == b"\x00\x00\x00\x01"

        def _is_zip(b: bytes) -> bool:
            return b[:2] == b"PK"

        def _any(_b: str) -> bool:
            return True

        def _is_csv(b: str) -> bool:
            lines = b.strip().splitlines()
            return len(lines) >= 2 and "," in lines[0]

        def _is_doc_content(b: str) -> bool:
            # DOCX/XLSX/PPTX are ZIP-based, Office XML or plaintext office docs
            return bool(b) and not b.lstrip().startswith("<")

        def _is_dir_listing(b: str) -> bool:
            return ("Index of" in b or "Directory listing" in b
                    or ("<a href=" in b and ("Parent Directory" in b or ".." in b)))

        sensitive_paths: list[tuple] = [
            ("/.env",                "Environment file exposed",              "critical", _is_env),
            ("/.env.local",          "Environment file (.env.local) exposed", "critical", _is_env),
            ("/.env.production",     "Environment file (.env.production) exposed", "critical", _is_env),
            ("/.git/config",         "Git repository exposed",                "critical", _is_git_config),
            ("/backup.sql",          "Database backup exposed",               "critical", _is_sql),
            ("/dump.sql",            "Database dump exposed",                 "critical", _is_sql),
            ("/database.sql",        "Database file exposed",                 "critical", _is_sql),
            ("/phpinfo.php",         "PHP info page exposed",                 "high",     _is_php_info),
            ("/wp-config.php.bak",   "WordPress config backup exposed",       "critical", _is_env),
            ("/server-status",       "Apache server-status exposed",          "medium",   _is_server_status),
            ("/actuator",            "Spring Boot actuator exposed",          "high",     _is_actuator),
            ("/actuator/env",        "Spring Boot env actuator exposed",      "critical", _is_actuator),
            ("/api/swagger.json",    "Swagger API spec exposed",              "medium",   _any),
            ("/swagger.json",        "Swagger API spec exposed",              "medium",   _any),
            ("/openapi.json",        "OpenAPI spec exposed",                  "medium",   _any),
            ("/v1/swagger.json",     "Swagger v1 spec exposed",               "medium",   _any),
            ("/documents/",          "Document directory listing exposed",     "high",     _is_dir_listing),
            ("/uploads/",            "Upload directory listing exposed",       "high",     _is_dir_listing),
            ("/files/",              "Files directory listing exposed",        "high",     _is_dir_listing),
            ("/backup/",             "Backup directory listing exposed",       "critical", _is_dir_listing),
            ("/config/",             "Config directory listing exposed",       "critical", _is_dir_listing),
            # Common exposed data files on pentest/practice sites
            ("/documents/employees/employees.csv",         "Employee data exposed",      "critical", _is_csv),
            ("/documents/company/full_backup_2026_01_27.csv", "Company backup exposed",  "critical", _is_csv),
            ("/employees.csv",       "Employee CSV exposed",                  "critical", _is_csv),
            ("/users.csv",           "User CSV exposed",                      "critical", _is_csv),
            ("/export.csv",          "Data export exposed",                   "high",     _is_csv),
            ("/data.csv",            "Data file exposed",                     "high",     _is_csv),
        ]
        # Binary checks (need raw bytes)
        binary_paths: list[tuple] = [
            ("/backup.zip",   "Backup archive exposed",    "high", _is_zip),
            ("/backup.tar.gz","Backup archive exposed",    "high", lambda b: b[:2] == b"\x1f\x8b"),
            ("/.DS_Store",    "macOS .DS_Store exposed",   "low",  _is_ds_store),
        ]

        base = f"{parsed.scheme}://{parsed.netloc}"
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as probe_client:
            for path, label, sev, validator in sensitive_paths:
                try:
                    r = probe_client.get(base + path)
                    if r.status_code in (200, 206):
                        body = r.text[:500]
                        if validator(body):
                            findings.append(_finding(
                                base + path, label,
                                f"GET {path} returned HTTP {r.status_code} with content "
                                f"matching the expected file format.\nPreview: {body[:120]}",
                                sev, "sensitive_file_exposed",
                                remediation=f"Block access to {path} via your web server or WAF. "
                                            "Remove the file from the server if not needed.",
                            ))
                except httpx.RequestError:
                    pass
            for path, label, sev, validator in binary_paths:
                try:
                    r = probe_client.get(base + path)
                    if r.status_code in (200, 206) and validator(r.content[:8]):
                        findings.append(_finding(
                            base + path, label,
                            f"GET {path} returned HTTP {r.status_code} with binary content "
                            "matching the expected file signature.",
                            sev, "sensitive_file_exposed",
                            remediation=f"Block access to {path}. Remove the file from the server.",
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
