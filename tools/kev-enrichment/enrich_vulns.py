#!/usr/bin/env python3
"""enrich_vulns.py — Daily CVE enrichment with CISA KEV and FIRST EPSS.

Reads:  vuln_scan.json      — list of {cve, asset, ...} vulnerability records
Writes: enriched_vulns.json — same records enriched with:
          is_kev_listed   (bool)   — present in CISA Known Exploited Vulnerabilities
          epss_score      (float)  — FIRST EPSS probability of exploitation (0–1)
          epss_percentile (float)  — relative rank among all scored CVEs
          triage_priority (str)    — "1 - IMMEDIATE (KEV)"
                                     "2 - HIGH RISK (EPSS > 20%)"
                                     "3 - STANDARD"

Designed to run daily as a cron job (see cron.sh).

Usage:
  python enrich_vulns.py [--input vuln_scan.json] [--output enriched_vulns.json]
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

# ── Configuration ─────────────────────────────────────────────────────────────

CISA_KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL  = "https://api.first.org/data/v1/epss"

EPSS_BATCH_SIZE = 50        # CVEs per EPSS API request (keeps URLs short)
HTTP_TIMEOUT    = 30        # seconds per request
HTTP_RETRIES    = 3         # attempts before giving up
RETRY_BACKOFF   = 2.0       # seconds between retries (doubles each attempt)

EPSS_HIGH_RISK_THRESHOLD = 0.20  # 20% exploitation probability

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger(__name__)


# ── HTTP helper ───────────────────────────────────────────────────────────────

def _get(url: str, params: dict | None = None) -> Any:
    """GET with retry/backoff. Returns parsed JSON. Raises on final failure.

    When *params* contains a ``cves`` key the comma-separated CVE list is
    appended to the URL directly (not percent-encoded) because the FIRST EPSS
    API requires literal commas in the query string.
    """
    # Build URL manually for EPSS cve param to avoid percent-encoding commas.
    # The FIRST API uses ?cve= (singular) with a comma-separated list and
    # requires literal commas — httpx would encode them as %2C which the API ignores.
    if params and "cve" in params:
        cve_value = params.pop("cve")
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}cve={cve_value}"

    delay = RETRY_BACKOFF
    for attempt in range(1, HTTP_RETRIES + 1):
        try:
            with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
                resp = client.get(url, params=params or None)
                resp.raise_for_status()
                return resp.json()
        except (httpx.HTTPError, httpx.TimeoutException) as exc:
            if attempt == HTTP_RETRIES:
                raise
            log.warning("Request failed (attempt %d/%d): %s — retrying in %.0fs",
                        attempt, HTTP_RETRIES, exc, delay)
            time.sleep(delay)
            delay *= 2


# ── CISA KEV ──────────────────────────────────────────────────────────────────

def fetch_kev_lookup() -> dict[str, dict]:
    """Download the CISA KEV catalog and return a {cveID: entry} lookup dict."""
    log.info("Fetching CISA KEV catalog from %s", CISA_KEV_URL)
    try:
        data = _get(CISA_KEV_URL)
    except Exception as exc:  # noqa: BLE001
        log.error("Failed to fetch CISA KEV: %s — all entries will be is_kev_listed=False", exc)
        return {}

    vulns = data.get("vulnerabilities", [])
    catalog_version = data.get("catalogVersion", "unknown")
    date_released   = data.get("dateReleased", "unknown")

    lookup = {v["cveID"].upper(): v for v in vulns}
    log.info(
        "KEV catalog loaded: %d entries (version %s, released %s)",
        len(lookup), catalog_version, date_released,
    )
    return lookup


# ── FIRST EPSS ────────────────────────────────────────────────────────────────

def fetch_epss_scores(cves: list[str]) -> dict[str, dict]:
    """Query FIRST EPSS API for *cves* in batches. Returns {CVE-ID: {epss, percentile}}."""
    if not cves:
        return {}

    unique = sorted({c.upper() for c in cves})
    log.info("Querying FIRST EPSS for %d unique CVE(s) in batches of %d",
             len(unique), EPSS_BATCH_SIZE)

    scores: dict[str, dict] = {}

    for i in range(0, len(unique), EPSS_BATCH_SIZE):
        batch = unique[i : i + EPSS_BATCH_SIZE]
        log.debug("EPSS batch %d–%d: %s …", i + 1, i + len(batch), batch[0])
        try:
            data = _get(EPSS_API_URL, params={"cve": ",".join(batch)})
        except Exception as exc:  # noqa: BLE001
            log.error("EPSS batch %d failed: %s — scores will be None for this batch", i, exc)
            continue

        for entry in data.get("data", []):
            cve_id = entry.get("cve", "").upper()
            if cve_id:
                scores[cve_id] = {
                    "epss":       float(entry.get("epss",       0.0)),
                    "percentile": float(entry.get("percentile", 0.0)),
                    "date":       entry.get("date", ""),
                }

    log.info("EPSS scores retrieved for %d/%d CVEs", len(scores), len(unique))
    return scores


# ── Triage logic ──────────────────────────────────────────────────────────────

def triage_priority(is_kev: bool, epss: float | None) -> str:
    if is_kev:
        return "1 - IMMEDIATE (KEV)"
    if epss is not None and epss >= EPSS_HIGH_RISK_THRESHOLD:
        return "2 - HIGH RISK (EPSS > 20%)"
    return "3 - STANDARD"


# ── Enrichment ────────────────────────────────────────────────────────────────

def enrich(
    records: list[dict],
    kev: dict[str, dict],
    epss: dict[str, dict],
) -> list[dict]:
    enriched = []
    for rec in records:
        cve_id      = rec.get("cve", "").upper()
        kev_entry   = kev.get(cve_id)
        epss_entry  = epss.get(cve_id)

        is_kev      = kev_entry is not None
        epss_score  = epss_entry["epss"]       if epss_entry else None
        epss_pct    = epss_entry["percentile"] if epss_entry else None
        epss_date   = epss_entry["date"]        if epss_entry else None

        priority = triage_priority(is_kev, epss_score)

        out = {
            **rec,
            "cve":             cve_id,
            "is_kev_listed":   is_kev,
            "epss_score":      epss_score,
            "epss_percentile": epss_pct,
            "epss_date":       epss_date,
            "triage_priority": priority,
        }

        # Attach KEV metadata when available
        if kev_entry:
            out["kev_vendor"]       = kev_entry.get("vendorProject")
            out["kev_product"]      = kev_entry.get("product")
            out["kev_date_added"]   = kev_entry.get("dateAdded")
            out["kev_due_date"]     = kev_entry.get("dueDate")
            out["kev_ransomware"]   = kev_entry.get("knownRansomwareCampaignUse", "Unknown")

        enriched.append(out)

    return enriched


# ── Summary ───────────────────────────────────────────────────────────────────

def print_summary(records: list[dict]) -> None:
    total     = len(records)
    immediate = sum(1 for r in records if r["triage_priority"].startswith("1"))
    high_risk = sum(1 for r in records if r["triage_priority"].startswith("2"))
    standard  = sum(1 for r in records if r["triage_priority"].startswith("3"))

    log.info("─" * 60)
    log.info("ENRICHMENT SUMMARY")
    log.info("  Total vulnerabilities : %d", total)
    log.info("  1 - IMMEDIATE  (KEV)  : %d", immediate)
    log.info("  2 - HIGH RISK  (EPSS) : %d", high_risk)
    log.info("  3 - STANDARD          : %d", standard)
    log.info("─" * 60)

    if immediate:
        log.info("IMMEDIATE ACTION REQUIRED:")
        for r in sorted(
            (r for r in records if r["triage_priority"].startswith("1")),
            key=lambda r: r.get("kev_due_date") or "",
        ):
            log.info(
                "  %-20s  %-30s  KEV due: %s  ransomware: %s",
                r["cve"], r.get("asset", ""),
                r.get("kev_due_date", "N/A"),
                r.get("kev_ransomware", "Unknown"),
            )

    if high_risk:
        log.info("HIGH RISK (EPSS ≥ 20%%):")
        for r in sorted(
            (r for r in records if r["triage_priority"].startswith("2")),
            key=lambda r: -(r.get("epss_score") or 0),
        ):
            log.info(
                "  %-20s  %-30s  EPSS: %.1f%%  (p%.0f)",
                r["cve"], r.get("asset", ""),
                (r.get("epss_score") or 0) * 100,
                (r.get("epss_percentile") or 0) * 100,
            )


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Enrich CVE scan data with CISA KEV and FIRST EPSS metrics.",
    )
    p.add_argument(
        "--input",  "-i",
        default="vuln_scan.json",
        help="Input JSON file (default: vuln_scan.json)",
    )
    p.add_argument(
        "--output", "-o",
        default="enriched_vulns.json",
        help="Output JSON file (default: enriched_vulns.json)",
    )
    return p.parse_args()


def main() -> int:
    args   = parse_args()
    script_dir = Path(__file__).parent
    input_path  = Path(args.input)  if Path(args.input).is_absolute()  else script_dir / args.input
    output_path = Path(args.output) if Path(args.output).is_absolute() else script_dir / args.output

    run_ts = datetime.now(timezone.utc).isoformat()
    log.info("=== CVE enrichment run started at %s ===", run_ts)

    # ── Load input ────────────────────────────────────────────────────────────
    if not input_path.exists():
        log.error("Input file not found: %s", input_path)
        return 1

    records: list[dict] = json.loads(input_path.read_text())
    log.info("Loaded %d vulnerability record(s) from %s", len(records), input_path)

    if not records:
        log.warning("Input file is empty — nothing to enrich.")
        return 0

    # ── Fetch external data ───────────────────────────────────────────────────
    kev   = fetch_kev_lookup()
    cves  = [r.get("cve", "") for r in records if r.get("cve")]
    epss  = fetch_epss_scores(cves)

    # ── Enrich ───────────────────────────────────────────────────────────────
    enriched = enrich(records, kev, epss)

    # ── Write output ──────────────────────────────────────────────────────────
    output = {
        "enriched_at":        run_ts,
        "kev_entries_loaded": len(kev),
        "epss_scores_loaded": len(epss),
        "total_records":      len(enriched),
        "vulnerabilities":    enriched,
    }
    output_path.write_text(json.dumps(output, indent=2))
    log.info("Enriched data written to %s", output_path)

    # ── Summary ───────────────────────────────────────────────────────────────
    print_summary(enriched)
    log.info("=== Run complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
