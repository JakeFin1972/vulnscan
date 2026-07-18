"""vulnscan.easm — External Attack Surface Management + Risk Scoring.

Public API::

    from vulnscan.easm import parse_file, score_vulnerabilities, score_to_grade
    from vulnscan.easm.schema import Vulnerability, RiskScore, AssetInfo

Typical workflow::

    # 1. Ingest a scanner output file
    vulns = parse_file("scan_output.xml")          # auto-detects Nmap XML

    # 2. Score the asset
    score = score_vulnerabilities(vulns, asset_id="some-uuid")
    print(f"{score.score:.1f} / 100  ({score.grade})")

    # 3. Save to DB via the /easm/ingest API endpoint (see api.py).
"""
from .parsers import parse_file
from .scoring import score_vulnerabilities, score_to_grade
from .schema  import AssetInfo, RiskScore, Vulnerability

__all__ = [
    "parse_file",
    "score_vulnerabilities",
    "score_to_grade",
    "AssetInfo",
    "RiskScore",
    "Vulnerability",
]
