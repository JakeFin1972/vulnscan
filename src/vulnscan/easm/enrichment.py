"""EASM vulnerability enrichment.

Fetches CVE details from NVD API v2 and EPSS probability from FIRST,
then derives a human-readable exploit insight for each vulnerability.

Non-CVE findings receive a static profile based on their category.
"""
from __future__ import annotations

import time
from typing import Any

import httpx

_NVD_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_EPSS_URL = "https://api.first.org/data/v1/epss"
_TIMEOUT  = 12  # seconds per request

# ── Static category exploit profiles ──────────────────────────────────────────

_CATEGORY_PROFILES: dict[str, dict] = {
    "sensitive_file_exposed": {
        "exploit_maturity": "trivial",
        "exploit_insight": (
            "Exploitable immediately — fetch the URL directly in a browser or with curl. "
            "No authentication, no tooling required. Exposed secrets (API keys, DB credentials, "
            "environment configs) enable full account or system compromise within seconds. "
            "Treat as P0: take the file offline before any other remediation."
        ),
    },
    "insecure_transport": {
        "exploit_maturity": "moderate",
        "exploit_insight": (
            "Requires network-level MITM capability: same LAN segment, rogue Wi-Fi hotspot, "
            "ARP/DNS poisoning, or ISP-level interception. Credentials and session tokens "
            "transmitted over HTTP are captured passively with Wireshark or mitmproxy. "
            "On public networks this is a realistic attack scenario."
        ),
    },
    "missing_security_header": {
        "exploit_maturity": "requires_chain",
        "exploit_insight": (
            "Not directly exploitable as a standalone issue. Missing CSP makes XSS attacks "
            "significantly more impactful (attacker can execute arbitrary JS without nonce/hash "
            "restriction). Missing X-Frame-Options / frame-ancestors enables clickjacking "
            "(UI redressing) — attacker overlays a hidden iframe to steal clicks or form submissions."
        ),
    },
    "weak_security_header": {
        "exploit_maturity": "requires_chain",
        "exploit_insight": (
            "Weakens defence-in-depth. 'unsafe-inline' in CSP directly negates XSS protection: "
            "any injected <script> tag executes without restriction. Short HSTS max-age means "
            "browsers re-check HTTP on next visit, allowing SSL-strip downgrade attacks until "
            "the HSTS entry is refreshed."
        ),
    },
    "insecure_cookie": {
        "exploit_maturity": "moderate",
        "exploit_insight": (
            "Missing HttpOnly: session token readable via document.cookie — "
            "one XSS payload is enough for session hijack. "
            "Missing SameSite: attacker crafts a cross-origin request (CSRF) that carries the "
            "cookie automatically, performing authenticated actions on the victim's behalf. "
            "Missing Secure flag: cookie sent over HTTP connections, capturable via MITM."
        ),
    },
    "information_disclosure": {
        "exploit_maturity": "low",
        "exploit_insight": (
            "Version banner enables targeted CVE lookup. Attackers run 'searchsploit <product> "
            "<version>' or search Exploit-DB / Metasploit for matching modules. Impact escalates "
            "dramatically if a public exploit exists for the disclosed version. "
            "Low effort: automated scanners harvest banners at scale."
        ),
    },
    "open_port": {
        "exploit_maturity": "requires_chain",
        "exploit_insight": (
            "Open port confirms service reachability — a prerequisite for service-specific "
            "attacks. Exploitation depends entirely on the service, version, and configuration. "
            "Cross-reference with CVE databases (NVD, Exploit-DB) for the identified service. "
            "Common quick wins: default credentials, unauthenticated admin panels, unpatched daemons."
        ),
    },
    "cve": {
        "exploit_maturity": "known",
        "exploit_insight": (
            "Public CVE identifier. Exploit code may be available on Exploit-DB, GitHub, or "
            "Metasploit — search the CVE ID directly. Check CISA KEV status: if listed, "
            "active exploitation in the wild is confirmed. Prioritise by CVSS base score and "
            "EPSS probability."
        ),
    },
    "network_error": {
        "exploit_maturity": "unknown",
        "exploit_insight": "Connection issue during scan — not a security vulnerability.",
    },
    "scanner_error": {
        "exploit_maturity": "unknown",
        "exploit_insight": "Scanner error — not a security vulnerability.",
    },
    "scanner_unavailable": {
        "exploit_maturity": "unknown",
        "exploit_insight": "Scanner not available — not a security vulnerability.",
    },
}

_DEFAULT_PROFILE: dict = {
    "exploit_maturity": "unknown",
    "exploit_insight": (
        "No specific exploit profile available for this category. "
        "Investigate manually: review the finding description and remediation guidance."
    ),
}

# ── NVD API fetch ─────────────────────────────────────────────────────────────

def _fetch_nvd(cve_id: str) -> dict[str, Any]:
    """Query NVD API v2 for one CVE.  Returns enriched dict or {} on failure."""
    try:
        r = httpx.get(_NVD_URL, params={"cveId": cve_id.upper()}, timeout=_TIMEOUT)
        if r.status_code != 200:
            return {}
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {}
        cve_data = vulns[0].get("cve", {})

        metrics = cve_data.get("metrics", {})
        cvss_vector: str | None = None
        cvss_base:   float | None = None

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cd = m.get("cvssData", {})
                cvss_vector = cd.get("vectorString")
                cvss_base   = cd.get("baseScore")
                break

        kev = bool(cve_data.get("cisaExploitAdd"))

        descriptions = cve_data.get("descriptions", [])
        desc_en = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), None
        )

        return {
            "cvss_vector":  cvss_vector,
            "cvss_score":   cvss_base,
            "kev":          kev,
            "description":  desc_en,
        }
    except Exception:  # noqa: BLE001
        return {}


# ── FIRST EPSS API fetch ───────────────────────────────────────────────────────

def _fetch_epss(cve_id: str) -> dict[str, float]:
    """Query FIRST EPSS API.  Returns {epss_score, epss_percentile} or {}."""
    try:
        r = httpx.get(_EPSS_URL, params={"cve": cve_id.upper()}, timeout=_TIMEOUT)
        if r.status_code != 200:
            return {}
        items = r.json().get("data", [])
        if not items:
            return {}
        row = items[0]
        return {
            "epss_score":      float(row.get("epss", 0)),
            "epss_percentile": float(row.get("percentile", 0)),
        }
    except Exception:  # noqa: BLE001
        return {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_vector(vector: str, key: str) -> str | None:
    """Extract a metric value from a CVSS vector string."""
    for part in (vector or "").split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            if k == key:
                return v
    return None


def _maturity_from_epss(score: float | None, kev: bool) -> str:
    if kev:
        return "actively_exploited"
    if score is None:
        return "unknown"
    if score >= 0.50:
        return "actively_exploited"
    if score >= 0.20:
        return "proof_of_concept"
    if score >= 0.05:
        return "theoretical"
    return "low"


def _build_cve_insight(cve: str, nvd: dict, epss: dict) -> str:
    parts: list[str] = []

    kev        = nvd.get("kev", False)
    cvss_score = nvd.get("cvss_score")
    vector     = nvd.get("cvss_vector", "") or ""
    epss_score = epss.get("epss_score")
    epss_pct   = epss.get("epss_percentile")

    if kev:
        parts.append(
            f"{cve} is in the CISA Known Exploited Vulnerabilities catalogue — "
            "active exploitation confirmed in the wild. Patch immediately."
        )

    if cvss_score is not None:
        av = _parse_vector(vector, "AV") or "?"
        ac = _parse_vector(vector, "AC") or "?"
        pr = _parse_vector(vector, "PR") or "?"
        ui = _parse_vector(vector, "UI") or "?"
        av_text = {"N": "network", "A": "adjacent-network", "L": "local", "P": "physical"}.get(av, av)
        ac_text = {"L": "low", "H": "high"}.get(ac, ac)
        pr_text = {"N": "none", "L": "low", "H": "high"}.get(pr, pr)
        ui_text = {"N": "none required", "R": "required"}.get(ui, ui)
        parts.append(
            f"CVSS {cvss_score:.1f} — Attack vector: {av_text}, complexity: {ac_text}, "
            f"privileges required: {pr_text}, user interaction: {ui_text}."
        )
        if ac == "L" and pr == "N" and ui == "N":
            parts.append(
                "This is a high-ease exploit: no authentication, no special position, "
                "exploitable over the network without any user action."
            )
        elif ac == "L" and pr == "N":
            parts.append(
                "Requires no special privileges and low complexity — "
                "automation (mass scanning) is realistic."
            )

    if epss_score is not None:
        pct_str = f", top {(1 - epss_pct) * 100:.1f}% of all CVEs" if epss_pct else ""
        parts.append(
            f"EPSS exploitation probability (next 30 days): {epss_score * 100:.2f}%{pct_str}."
        )
        if epss_score >= 0.50:
            parts.append("Exploitation is highly likely in the current threat landscape.")
        elif epss_score >= 0.10:
            parts.append("Meaningful exploitation probability — prioritise patching.")
        else:
            parts.append("Low short-term exploitation probability based on current threat intel.")

    if not parts:
        return (
            f"{cve}: NVD/EPSS data unavailable. "
            "Search Exploit-DB or GitHub for public proof-of-concept code."
        )

    return " ".join(parts)


# ── Public API ─────────────────────────────────────────────────────────────────

def enrich_vuln(cve: str | None, category: str) -> dict[str, Any]:
    """
    Enrich one vulnerability record.

    Returns dict with keys:
      cvss_vector, epss_score, epss_percentile, kev,
      exploit_maturity, exploit_insight
    """
    result: dict[str, Any] = {
        "cvss_vector":      None,
        "epss_score":       None,
        "epss_percentile":  None,
        "kev":              0,
        "exploit_maturity": None,
        "exploit_insight":  None,
    }

    if cve:
        nvd_data  = _fetch_nvd(cve)
        # Small delay to respect NVD rate limit (5 req / 30 s without key)
        time.sleep(0.4)
        epss_data = _fetch_epss(cve)

        result["cvss_vector"]     = nvd_data.get("cvss_vector")
        result["epss_score"]      = epss_data.get("epss_score")
        result["epss_percentile"] = epss_data.get("epss_percentile")
        result["kev"]             = 1 if nvd_data.get("kev") else 0
        result["exploit_maturity"] = _maturity_from_epss(
            result["epss_score"], bool(nvd_data.get("kev"))
        )
        result["exploit_insight"] = _build_cve_insight(cve, nvd_data, epss_data)
    else:
        profile = _CATEGORY_PROFILES.get(category, _DEFAULT_PROFILE)
        result["exploit_maturity"] = profile["exploit_maturity"]
        result["exploit_insight"]  = profile["exploit_insight"]

    return result


def enrich_asset_vulns(
    asset_id: str,
    conn,  # sqlite3.Connection
    force: bool = False,
) -> tuple[int, int]:
    """
    Enrich all vulnerabilities for *asset_id* that have no insight yet.

    Set *force=True* to re-enrich already-enriched rows.

    Returns (enriched_count, error_count).
    """
    if force:
        rows = conn.execute(
            "SELECT id, cve, category FROM easm_vulnerabilities WHERE asset_id=?",
            (asset_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT id, cve, category FROM easm_vulnerabilities
               WHERE asset_id=? AND exploit_insight IS NULL""",
            (asset_id,),
        ).fetchall()

    enriched = 0
    errors   = 0

    for row in rows:
        try:
            data = enrich_vuln(row["cve"], row["category"])
            conn.execute(
                """UPDATE easm_vulnerabilities SET
                   cvss_vector=?, epss_score=?, epss_percentile=?,
                   kev=?, exploit_maturity=?, exploit_insight=?
                   WHERE id=?""",
                (
                    data["cvss_vector"],
                    data["epss_score"],
                    data["epss_percentile"],
                    data["kev"],
                    data["exploit_maturity"],
                    data["exploit_insight"],
                    row["id"],
                ),
            )
            conn.commit()
            enriched += 1
        except Exception:  # noqa: BLE001
            errors += 1

    return enriched, errors
