"""AI-powered vulnerability analysis — supports Anthropic Claude and OpenAI GPT.

Provider selection (first available wins):
  1. OPENAI_API_KEY   → GPT-4o (gpt-4o)
  2. ANTHROPIC_API_KEY → Claude Sonnet 4.6 (claude-sonnet-4-6)

All functions raise RuntimeError if no provider is available.
"""
from __future__ import annotations

import json
import os
import textwrap
from pathlib import Path
from typing import Any

_ANTHROPIC_MODEL = "claude-sonnet-4-6"
_OPENAI_MODEL    = "gpt-4o"
_MAX_TOKENS      = 2048

_SYSTEM_PROMPT = textwrap.dedent("""\
You are a senior application security engineer and penetration tester.
You analyse security findings from automated scanners and produce structured,
actionable reports. You are precise: you distinguish real vulnerabilities from
false positives, assess actual exploitability, and provide concrete fixes.

Always respond in the exact JSON format requested — no markdown, no prose outside JSON.
""")

# Public: which model string the UI should show
_MODEL = _OPENAI_MODEL  # updated dynamically by _active_provider()


def _active_provider() -> str:
    """Return 'openai' or 'anthropic' based on which key is set, or raise."""
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    raise RuntimeError(
        "No AI provider configured. Set OPENAI_API_KEY or ANTHROPIC_API_KEY."
    )


def is_available() -> bool:
    """True if at least one AI provider SDK + key is configured."""
    try:
        provider = _active_provider()
    except RuntimeError:
        return False
    if provider == "openai":
        try:
            import openai  # noqa: F401
            return True
        except ImportError:
            return False
    else:
        try:
            import anthropic  # noqa: F401
            return True
        except ImportError:
            return False


def active_model() -> str:
    """Return the model name for the active provider."""
    try:
        p = _active_provider()
        return _OPENAI_MODEL if p == "openai" else _ANTHROPIC_MODEL
    except RuntimeError:
        return "none"


def _call_ai(prompt: str) -> str:
    """Send prompt to the active provider and return raw text response."""
    provider = _active_provider()

    if provider == "openai":
        try:
            import openai
        except ImportError as exc:
            raise RuntimeError("openai SDK not installed. Run: pip install openai") from exc
        client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
        response = client.chat.completions.create(
            model=_OPENAI_MODEL,
            max_tokens=_MAX_TOKENS,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
        )
        return response.choices[0].message.content.strip()

    else:  # anthropic
        try:
            import anthropic
        except ImportError as exc:
            raise RuntimeError("anthropic SDK not installed. Run: pip install anthropic") from exc
        client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        response = client.messages.create(
            model=_ANTHROPIC_MODEL,
            max_tokens=_MAX_TOKENS,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text.strip()


def _parse_json(raw: str) -> dict:
    """Strip accidental markdown fences and parse JSON."""
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return json.loads(raw.strip())


# ── Static finding analysis ───────────────────────────────────────────────────

def analyze_static_finding(
    finding: dict[str, Any],
    code_snippet: str | None = None,
    scan_root: str | None = None,
) -> dict[str, Any]:
    snippet_block = ""
    if code_snippet:
        snippet_block = f"\n\nCode snippet (lines around finding):\n```\n{code_snippet}\n```"

    prompt = textwrap.dedent(f"""\
    Analyse this static security finding and respond in JSON.

    Finding:
    - Kind: {finding.get('kind', 'sink')}
    - Category: {finding.get('category', 'unknown')}
    - File: {finding.get('file', '')}
    - Line: {finding.get('line', 0)}
    - Symbol: {finding.get('name', '')}
    - Language: {finding.get('language', 'unknown')}
    - Severity (scanner estimate): {finding.get('severity', 'medium')}
    - Confidence (scanner estimate): {finding.get('confidence', 75)}%
    - Scan root: {scan_root or 'unknown'}{snippet_block}

    Respond ONLY with this JSON structure (no markdown fences):
    {{
      "verdict": "confirmed|false_positive|needs_review",
      "severity": "critical|high|medium|low|info",
      "confidence": 0-100,
      "exploit_difficulty": "trivial|low|moderate|high|not_exploitable",
      "exploit_scenario": "Numbered steps: 1. ... 2. ... 3. ...",
      "data_flow": "ComponentA → function() → sink at file:line",
      "remediation_summary": "One sentence fix",
      "remediation_code": "Concrete code fix example (empty string if none)",
      "cvss_vector": "CVSS:3.1/AV:.../...",
      "reasoning": "Why this verdict — 2-3 sentences"
    }}
    """)

    raw = _call_ai(prompt)
    return _parse_json(raw)


# ── Dynamic finding analysis ──────────────────────────────────────────────────

def analyze_dynamic_finding(finding: dict[str, Any]) -> dict[str, Any]:
    evidence    = finding.get("evidence", "")
    description = finding.get("description", "")
    cve         = finding.get("cve", "")
    cwe         = finding.get("cwe", "")

    prompt = textwrap.dedent(f"""\
    Analyse this dynamic security finding from an automated scanner and respond in JSON.

    Finding:
    - Name: {finding.get('name', '')}
    - Tool: {finding.get('tool', '')}
    - Target: {finding.get('target', '')}
    - Category: {finding.get('category', '')}
    - Severity (scanner): {finding.get('severity', 'medium')}
    - CVE: {cve or 'N/A'}
    - CWE: {cwe or 'N/A'}
    - Description: {description[:600] if description else 'N/A'}
    - Evidence: {evidence[:400] if evidence else 'N/A'}
    - Port: {finding.get('port', 'N/A')}
    - URL: {finding.get('url', 'N/A')}

    Respond ONLY with this JSON structure (no markdown fences):
    {{
      "verdict": "confirmed|false_positive|needs_review",
      "severity": "critical|high|medium|low|info",
      "confidence": 0-100,
      "exploit_difficulty": "trivial|low|moderate|high|not_exploitable",
      "exploit_scenario": "Numbered steps: 1. ... 2. ... 3. ...",
      "attack_vector": "How attacker reaches this from the internet",
      "affected_system": "What is compromised if exploited",
      "remediation_summary": "One sentence fix",
      "remediation_code": "Config change, command, or code fix (empty if N/A)",
      "cvss_vector": "CVSS:3.1/AV:.../...",
      "reasoning": "Why this verdict — 2-3 sentences"
    }}
    """)

    raw = _call_ai(prompt)
    return _parse_json(raw)


# ── Scan boost: taint analysis on source-sink pairs ──────────────────────────

def boost_scan(
    scan_report: dict[str, Any],
    max_pairs: int = 20,
) -> list[dict[str, Any]]:
    """AI taint analysis on source-sink candidate pairs from a static scan."""
    pairs   = scan_report.get("candidate_pairs", [])[:max_pairs]
    root    = scan_report.get("root", "")
    results = []

    for pair in pairs:
        src  = pair.get("source", {})
        sink = pair.get("sink", {})

        src_snippet  = _read_snippet(src.get("file", ""),  src.get("line",  0))
        sink_snippet = _read_snippet(sink.get("file", ""), sink.get("line", 0))

        prompt = textwrap.dedent(f"""\
        Perform taint analysis on this source-sink pair from a static scanner.

        SOURCE (attacker-controlled input enters here):
        - File: {src.get('file', '')}
        - Line: {src.get('line', 0)}
        - Symbol: {src.get('name', '')}
        - Category: {src.get('category', '')}
        Code:
        ```
        {src_snippet or '(file not readable)'}
        ```

        SINK (dangerous operation):
        - File: {sink.get('file', '')}
        - Line: {sink.get('line', 0)}
        - Symbol: {sink.get('name', '')}
        - Category: {sink.get('category', '')}
        Code:
        ```
        {sink_snippet or '(file not readable)'}
        ```

        Proximity: {pair.get('proximity', 'unknown')}
        Scan root: {root}

        Respond ONLY with JSON (no markdown):
        {{
          "verdict": "confirmed|false_positive|needs_review",
          "severity": "critical|high|medium|low|info",
          "confidence": 0-100,
          "exploit_difficulty": "trivial|low|moderate|high|not_exploitable",
          "vulnerability_title": "Short precise name (e.g. SSRF via fetch() with user-controlled URL)",
          "cwe": "CWE-NNN",
          "data_flow": "SourceSymbol (file:line) → propagation → SinkSymbol (file:line)",
          "exploit_scenario": "1. Attacker ... 2. Application ... 3. Attacker achieves ...",
          "remediation_summary": "One sentence fix",
          "remediation_code": "Concrete fixed code snippet",
          "reasoning": "2-3 sentences explaining the verdict"
        }}
        """)

        try:
            raw = _call_ai(prompt)
            ai  = _parse_json(raw)
        except Exception as exc:  # noqa: BLE001
            ai = {"error": str(exc), "verdict": "needs_review"}

        results.append({
            "source":    src,
            "sink":      sink,
            "proximity": pair.get("proximity"),
            "ai":        ai,
        })

    return results


def _read_snippet(file: str, line: int, context: int = 6) -> str:
    """Read lines around `line` from `file`."""
    try:
        lines = Path(file).read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(0, line - 1 - context)
        end   = min(len(lines), line - 1 + context + 1)
        return "\n".join(
            f"{i + 1:4d}  {'→' if i + 1 == line else ' '} {lines[i]}"
            for i in range(start, end)
        )
    except Exception:  # noqa: BLE001
        return ""
