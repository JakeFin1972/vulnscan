"""Port of review_to_changes.js: the return leg of the G1 profile review.

  extract  read a commented .docx, key each Word comment / tracked change to the claim ID it sits under,
           write a ChangeProposals.md the CISO marks up (y/n + optional new wording)
  apply    write approved rows into the master .md, bump the version, add Part D change-log rows

Standard library only. Nothing reaches the master that a human has not marked "y"."""
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

CLAIM_ID_RE = re.compile(r"^(A\d+|C\d+|B\.[A-Z0-9.]+?\.\d+)$")
_W_T = re.compile(r"<w:t(?:\s[^>]*)?>([\s\S]*?)</w:t>")
_W_DEL = re.compile(r"<w:delText(?:\s[^>]*)?>([\s\S]*?)</w:delText>")


def _today():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# ------------------------------------------------------------------ xml helpers
def xml_unescape(s: str) -> str:
    s = (s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&apos;", "'"))
    s = re.sub(r"&#(\d+);", lambda m: chr(int(m[1])), s)
    return s.replace("&amp;", "&")


def text_of(xml: str, deleted: bool = False) -> str:
    out = "".join(xml_unescape(m[1]) for m in (_W_DEL if deleted else _W_T).finditer(xml))
    return re.sub(r"\s+", " ", out).strip()


def attr(tag_xml: str, name: str) -> str:
    m = re.search(r"(?<![\w:])" + re.escape(name) + r'="([^"]*)"', tag_xml)
    return xml_unescape(m[1]) if m else ""


# ------------------------------------------------------------------ extract
def map_claim_positions(document_xml: str) -> list[tuple[int, str]]:
    out = []
    for m in re.finditer(r"<w:p[\s>][\s\S]*?</w:p>", document_xml):
        first = _W_T.search(m[0])
        if not first:
            continue
        cand = xml_unescape(first[1]).strip()
        if CLAIM_ID_RE.match(cand):
            out.append((m.start(), cand))
    return out


def claim_id_at(positions, index: int) -> str:
    found = "-"
    for pos, cid in positions:
        if pos <= index:
            found = cid
        else:
            break
    return found


BIG = 2 ** 53


def extract_comments(document_xml, comments_xml, extended_xml) -> list[dict]:
    if not comments_xml:
        return []
    positions = map_claim_positions(document_xml)
    ex = {}
    if extended_xml:
        for m in re.finditer(r"<w15:commentEx\b[^>]*/?>", extended_xml):
            pid = attr(m[0], "w15:paraId")
            if pid:
                ex[pid.upper()] = (attr(m[0], "w15:done") == "1", attr(m[0], "w15:paraIdParent").upper())
    out = []
    for m in re.finditer(r"<w:comment\b([^>]*)>([\s\S]*?)</w:comment>", comments_xml):
        attrs, body = m[1], m[2]
        cid = attr(attrs, "w:id")
        text = text_of(body)
        if text == "":
            continue
        status, is_reply = "unknown", False
        for pid in (x.upper() for x in re.findall(r'<w:p\b[^>]*w14:paraId="([0-9A-Fa-f]+)"', body)):
            if pid in ex:
                done, parent = ex[pid]
                status = "resolved" if done else "open"
                if parent and parent != "00000000":
                    is_reply = True
        anchored, pos = "", -1
        s_idx = document_xml.find(f'<w:commentRangeStart w:id="{cid}"')
        e_idx = document_xml.find(f'<w:commentRangeEnd w:id="{cid}"')
        if s_idx >= 0:
            pos = s_idx
            if e_idx > s_idx:
                anchored = text_of(document_xml[s_idx:e_idx])
        if pos < 0:
            r_idx = document_xml.find(f'<w:commentReference w:id="{cid}"')
            if r_idx >= 0:
                pos = r_idx
        out.append({"kind": "reply" if is_reply else "comment",
                    "claimId": claim_id_at(positions, pos) if pos >= 0 else "-",
                    "author": attr(attrs, "w:author") or "(unnamed)", "date": attr(attrs, "w:date")[:10],
                    "status": status, "anchored": anchored if len(anchored) <= 400 else anchored[:397] + "…",
                    "text": text, "pos": BIG if pos < 0 else pos})
    return out


def extract_tracked_changes(document_xml) -> list[dict]:
    positions = map_claim_positions(document_xml)
    out = []
    for tag, label, deleted in (("w:ins", "inserted", False), ("w:del", "deleted", True)):
        for m in re.finditer(rf"<{tag}\b([^>]*)>([\s\S]*?)</{tag}>", document_xml):
            t = text_of(m[2], deleted)
            if t == "":
                continue
            out.append({"kind": "tracked change", "claimId": claim_id_at(positions, m.start()),
                        "author": attr(m[1], "w:author") or "(unnamed)", "date": attr(m[1], "w:date")[:10],
                        "status": "n/a", "anchored": "",
                        "text": f'{label}: "{t if len(t) <= 300 else t[:297] + "…"}"', "pos": m.start()})
    return out


# ------------------------------------------------------------------ claim text in the master
def _anchor_of(cid):
    return re.compile(r"\{#" + re.escape(cid) + r"\}\s*$")


def find_claim_span(lines, claim_id):
    rx = _anchor_of(claim_id)
    anchor = next((i for i, ln in enumerate(lines) if rx.search(ln)), -1)
    if anchor < 0:
        return None
    start = anchor
    while start > 0:
        if re.match(r"^\s*(?:\d+\.|[-*+])\s+", lines[start]):
            break
        prev = lines[start - 1]
        if (prev.strip() == "" or re.match(r"^\s*#{1,6}\s", prev) or re.match(r"^\s*\|", prev)
                or re.match(r"^\s*(-{3,}|\*{3,}|_{3,})\s*$", prev) or re.match(r"^\s*>", prev)):
            break
        start -= 1
    return start, anchor


def claim_text(lines, span, claim_id):
    raw = " ".join(lines[span[0]:span[1] + 1])
    raw = _anchor_of(claim_id).sub("", raw)
    raw = re.sub(r"^\s*(?:\d+\.|[-*+])\s+", "", raw, count=1)
    return re.sub(r"\s+", " ", raw).strip()


# ------------------------------------------------------------------ proposals file
def write_proposals(items, docx_path, profile_path, md_lines, out_path) -> dict:
    counts = {"comment": sum(i["kind"] == "comment" for i in items),
              "reply": sum(i["kind"] == "reply" for i in items),
              "tracked": sum(i["kind"] == "tracked change" for i in items),
              "unmatched": sum(i["claimId"] == "-" for i in items)}
    L = ["# Profile review — change proposals", "", "| | |", "|---|---|",
         f"| Reviewed document | `{Path(docx_path).name}` |", f"| Master profile | `{Path(profile_path).name}` |",
         f"| Extracted | {_today()} |",
         f"| Proposals | {len(items)} (comments {counts['comment']}, replies {counts['reply']}, "
         f"tracked changes {counts['tracked']}) |"]
    if counts["unmatched"]:
        L.append(f"| **Not matched to a claim** | **{counts['unmatched']}** — these must be handled by hand; "
                 "`apply` will skip them |")
    L += ["", "## How to use this file", "", "For each proposal set `Approve:` to `y` or `n`.", "",
          "- **`y` with text under `New text:`** — that claim's wording in the master profile is replaced with it.",
          "- **`y` with `New text:` left empty** — no wording change, but the decision is still recorded in the "
          "profile's change log. Use this for \"accepted as unknown\" and for answers that need no edit.",
          "- **`n`** — nothing happens. The proposal stays here as the record of what was raised and declined.", "",
          "Do not edit the `Claim ID:` lines — `apply` matches on them. Everything else is yours to rewrite.", "",
          f"Then: `python -m staging_gate review-apply {Path(out_path).name} --profile "
          f"{Path(profile_path).name} --new-version CP-v2-approved`", "", "---", ""]
    for idx, it in enumerate(items):
        L += [f"## CP-{idx + 1:03d}", "", f"- Claim ID: {it['claimId']}", f"- Type: {it['kind']}",
              f"- Raised by: {it['author']}" + (f" on {it['date']}" if it["date"] else "")]
        if it["status"] != "n/a":
            L.append(f"- Thread status: {it['status']}")
        if it["anchored"]:
            L.append(f'- Anchored on: "{it["anchored"]}"')
        L += ["", f"**Reviewer says:** {it['text']}", ""]
        if it["claimId"] != "-":
            span = find_claim_span(md_lines, it["claimId"])
            if span:
                L += ["**Current text in the profile:**", "", "> " + claim_text(md_lines, span, it["claimId"])]
            else:
                L.append(f"**Current text in the profile:** _claim ID `{it['claimId']}` was not found in the "
                         "markdown — was the profile stamped before it was circulated?_")
        else:
            L.append("**Current text in the profile:** _this comment is not anchored to a claim (cover page, "
                     "heading, or a table). Handle it by hand._")
        L += ["", "New text:", "", "", "Approve:", "", "---", ""]
    Path(out_path).write_text("\n".join(L), encoding="utf-8")
    return counts


def parse_proposals(text: str) -> list[dict]:
    out = []
    chunks = re.split(r"^##[ \t]+(CP-\d+)[ \t]*$", text, flags=re.M)
    for i in range(1, len(chunks), 2):
        pid, body = chunks[i], chunks[i + 1] if i + 1 < len(chunks) else ""
        # [ \t]* not \s*: an empty "Approve:" must not swallow the newline and read the next line
        g = lambda rx: (re.search(rx, body, re.M) or [None, ""])[1]
        claim_id = g(r"^-[ \t]*Claim ID:[ \t]*(.+)$")
        author = g(r"^-[ \t]*Raised by:[ \t]*(.+?)(?:[ \t]+on[ \t]+\d{4}-\d{2}-\d{2})?[ \t]*$")
        says = g(r"^\*\*Reviewer says:\*\*[ \t]*([\s\S]*?)(?:\n\n|$)")
        new_text = ""
        n = re.search(r"^New text:[ \t]*$", body, re.M)
        a = re.search(r"^Approve:", body, re.M)
        if n and a and a.start() > n.start():
            seg = body[body.index("\n", n.start()) + 1:a.start()]
            new_text = " ".join(ln.strip() for ln in seg.split("\n")
                                if ln.strip() != "" and not re.match(r"^-{3,}$", ln.strip())).strip()
        approve = g(r"^Approve:[ \t]*(.*)$").strip().lower()
        out.append({"id": pid, "claimId": claim_id.strip(), "author": author.strip(),
                    "says": re.sub(r"\s+", " ", says).strip(), "newText": new_text, "approve": approve})
    return out


# ------------------------------------------------------------------ apply
def summarise(s):
    t = re.sub(r"\s+", " ", s or "").strip()
    if t == "":
        return "(no comment text)"
    return t if len(t) <= 110 else t[:107] + "…"


def evidence_in(s):
    ids = list(dict.fromkeys(re.findall(r"\bEV-\d+\b", s)))
    return ", ".join(ids) if ids else "—"


def append_to_change_log(lines, rows, today):
    if not rows:
        return {"inserted": 0, "note": "no rows to add"}
    h = next((i for i, ln in enumerate(lines) if re.match(r"^#{1,6}\s+Part\s+D\b", ln.strip(), re.I)), -1)
    if h < 0:
        return {"inserted": 0, "note": "Part D heading not found — change log not updated"}
    header = -1
    for i in range(h + 1, len(lines)):
        if re.match(r"^#{1,6}\s", lines[i].strip()):
            break
        if lines[i].strip().startswith("|") and i + 1 < len(lines) and re.match(r"^\s*\|[\s:|-]+\|\s*$", lines[i + 1]):
            header = i
            break
    if header < 0:
        return {"inserted": 0, "note": "no table under Part D — change log not updated"}
    cols = len(re.sub(r"\|$", "", re.sub(r"^\|", "", lines[header])).split("|"))
    last = header + 1
    for i in range(header + 2, len(lines)):
        if not lines[i].strip().startswith("|"):
            break
        last = i
    built = []
    for r in rows:
        cells = [today, r["change"], r["trigger"], r["evidence"]][:cols]
        cells += ["—"] * (cols - len(cells))
        built.append("| " + " | ".join(cells) + " |")
    lines[last + 1:last + 1] = built
    return {"inserted": len(built), "note": ""}


def apply_to_profile(md_text, proposals, new_version):
    lines = re.split(r"\r?\n", md_text)
    today = _today()
    applied, logged, skipped, failed = [], [], [], []
    for p in proposals:
        if p["approve"] not in ("y", "yes"):
            skipped.append(p)
            continue
        if p["newText"] == "":
            logged.append(p)
            continue
        if not p["claimId"] or p["claimId"] == "-":
            failed.append((p, "no claim ID — cannot locate the text to replace"))
            continue
        span = find_claim_span(lines, p["claimId"])
        if not span:
            failed.append((p, f"claim ID {p['claimId']} not found in the profile (is it stamped?)"))
            continue
        m = re.match(r"^(\s*(?:\d+\.|[-*+])\s+)", lines[span[0]])
        marker = m[1] if m else re.match(r"^(\s*)", lines[span[0]])[1]
        before = claim_text(lines, span, p["claimId"])
        rebuilt = marker + re.sub(r"\s*\{#[^}]+\}\s*$", "", p["newText"]) + " {#" + p["claimId"] + "}"
        lines[span[0]:span[1] + 1] = [rebuilt]
        applied.append((p, before))
    rows = [{"change": f"{p['claimId']} reworded — {summarise(p['says'])}",
             "trigger": f"G1 review — {p['author'] or 'reviewer'} ({p['id']})",
             "evidence": evidence_in(p["says"] + " " + p["newText"])} for p, _ in applied]
    rows += [{"change": (f"{p['claimId']}: " if p["claimId"] and p["claimId"] != "-" else "")
              + f"decision recorded — {summarise(p['says'])}",
              "trigger": f"G1 review — {p['author'] or 'reviewer'} ({p['id']})",
              "evidence": evidence_in(p["says"])} for p in logged]
    log_result = append_to_change_log(lines, rows, today)
    bumped = False
    if new_version:
        for i, ln in enumerate(lines):
            if re.search(r"profile version", ln, re.I) and re.search(r"CP-[A-Za-z0-9._-]+", ln):
                lines[i] = re.sub(r"CP-[A-Za-z0-9._-]+", new_version, ln, count=1)
                bumped = True
    return {"text": "\n".join(lines), "applied": applied, "logged": logged, "skipped": skipped,
            "failed": failed, "logResult": log_result, "versionBumped": bumped}


# ------------------------------------------------------------------ commands
def _read(z: zipfile.ZipFile, name):
    try:
        return z.read(name).decode("utf-8")
    except KeyError:
        return None


def cmd_extract(inp, profile, out=None) -> int:
    for f in (inp, profile):
        if not Path(f).exists():
            print(f"File not found: {f}", file=sys.stderr)
            return 1
    try:
        z = zipfile.ZipFile(inp)
    except zipfile.BadZipFile:
        print("Not a valid .docx (not a ZIP archive).", file=sys.stderr)
        return 1
    doc = _read(z, "word/document.xml")
    if not doc:
        print("word/document.xml not found — is this really a .docx?", file=sys.stderr)
        return 1
    items = sorted(extract_comments(doc, _read(z, "word/comments.xml"), _read(z, "word/commentsExtended.xml"))
                   + extract_tracked_changes(doc), key=lambda x: x["pos"])
    if not items:
        print(f"No comments and no tracked changes found in {Path(inp).name}.")
        print("If reviewers definitely commented, check you downloaded the commented copy and not the original.")
        return 0
    md_lines = re.split(r"\r?\n", Path(profile).read_text(encoding="utf-8"))
    if not re.search(r"\{#[A-Za-z0-9._-]+\}", "\n".join(md_lines)):
        print("WARNING: the profile has no {#id} anchors. Run `profile-docx --stamp` on it, then")
        print("         re-run this — otherwise apply cannot locate claims and will refuse every change.\n")
    out_path = out or str(Path(profile).parent / "ChangeProposals.md")
    c = write_proposals(items, inp, profile, md_lines, out_path)
    print(f"Wrote {out_path}")
    print(f"  proposals: {len(items)}  (comments {c['comment']}, replies {c['reply']}, tracked changes {c['tracked']})")
    if c["unmatched"]:
        print(f"  {c['unmatched']} not anchored to a claim — listed with ID '-', handle by hand.")
    print("\nNext: open it, set Approve: y/n on each, add New text: where wording should change.")
    return 0


def cmd_apply(inp, profile, new_version=None, dry_run=False, force=False) -> int:
    for f in (inp, profile):
        if not Path(f).exists():
            print(f"File not found: {f}", file=sys.stderr)
            return 1
    proposals = parse_proposals(Path(inp).read_text(encoding="utf-8"))
    if not proposals:
        print(f"No CP-nnn blocks found in {inp}.", file=sys.stderr)
        return 1
    undecided = [p for p in proposals if p["approve"] == ""]
    if undecided and not force:
        print(f"{len(undecided)} of {len(proposals)} proposals have an empty Approve: line:")
        print("  " + ", ".join(p["id"] for p in undecided))
        print("\nNothing has been changed. Decide them, or re-run with --force to apply only the ones marked y.")
        return 0
    md_text = Path(profile).read_text(encoding="utf-8")
    res = apply_to_profile(md_text, proposals, new_version)
    if dry_run:
        print("DRY RUN — nothing written.\n")
    else:
        Path(profile + ".bak").write_text(md_text, encoding="utf-8")
        Path(profile).write_text(res["text"], encoding="utf-8")
    print(f"Applied (text changed): {len(res['applied'])}")
    for p, _ in res["applied"]:
        print(f"  {p['id']}  {p['claimId']}")
    print(f"Logged (decision only, no text change): {len(res['logged'])}")
    print(f"Declined: {len(res['skipped'])}")
    if res["failed"]:
        print(f"COULD NOT APPLY: {len(res['failed'])}")
        for p, why in res["failed"]:
            print(f"  {p['id']}  {why}")
    lr = res["logResult"]
    print(f"Change-log rows added: {lr['inserted']}" + (f"  ({lr['note']})" if lr["note"] else ""))
    if new_version:
        print(f"Version bumped to {new_version}: "
              + ("yes" if res["versionBumped"] else "NO — no 'Profile version CP-…' line found, set it by hand"))
    if not dry_run:
        print(f"\nBackup of the previous profile: {Path(profile).name}.bak")
        print("\nPaste into 06_Governance/DecisionLog.md:")
        print(f"| {_today()} | G1 closed on profile {new_version or '(version)'} | {len(res['applied'])} reviewer "
              f"changes applied, {len(res['logged'])} decisions recorded, {len(res['skipped'])} declined | Done |")
    return 0
