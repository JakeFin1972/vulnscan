"""Mechanical enforcement of H2's ceiling rules on the model's JSON. It only ever LOWERS a score
or removes a proposal; it never raises one. Every change is recorded in the row's flags."""
from .controls import nr_str

# cumulative evidence needed per level (substring of the register's Type text)
_NEEDS = [(1, ("policy",)), (2, ("procedure",)), (3, ("config",)), (4, ("test",))]


def ceiling(types: list[str]) -> tuple[int, str]:
    t = " ".join(types).lower()
    lvl = 0
    for k, needles in _NEEDS:
        if any(n in t for n in needles):
            lvl = k
        else:
            break
    why = {0: "no policy-type evidence", 1: "no procedure evidence", 2: "no config export/coverage evidence",
           3: "no routine-test evidence", 4: "level 5 needs human confirmation"}[lvl]
    if lvl == 0 and types and all("interview" in x for x in types):
        return 1, "interview-only evidence (needs a named document for level 1)"
    return lvl, why


def _int(v):
    return int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and v == int(v) else None


def guard_h2(result: dict, controls: list[dict], register: dict[str, str]) -> tuple[dict, list[str]]:
    known = {(c["sheet"], c["nr"]) for c in controls}
    notes: list[str] = []
    kept, not_scored, seen = [], list(result.get("not_scored") or []), set()
    for p in result.get("proposals") or []:
        key = (p.get("sheet"), nr_str(p.get("nr")))
        label = f"{key[0]} nr {key[1]}"
        if key not in known:
            notes.append(f"{label}: no such control row - dropped")
            continue
        if key in seen:
            notes.append(f"{label}: duplicate proposal - dropped")
            continue
        seen.add(key)
        p = dict(p, flags=list(p.get("flags") or []))
        ev = [e for e in (p.get("evidence") or []) if e in register]
        for e in (p.get("evidence") or []):
            if e not in register:
                msg = f"fabricated EV-ID {e} removed"
                p["flags"].append(msg)
                notes.append(f"{label}: {msg}")
        p["evidence"] = ev
        sc = _int(p.get("S"))
        if not ev or sc is None or not 0 <= sc <= 5:
            reason = "no valid EV-ID" if not ev else f"invalid S {p.get('S')!r}"
            not_scored.append({"sheet": key[0], "nr": key[1], "reason": f"guard: {reason}"})
            notes.append(f"{label}: moved to not_scored ({reason})")
            continue
        cap, why = ceiling([register[e] for e in ev])
        if sc > cap:
            p["flags"].append(f"S lowered {sc}->{cap}: {why}")
            notes.append(f"{label}: S lowered {sc}->{cap} ({why})")
            sc = cap
        p["S"] = sc
        u = _int(p.get("U_proposed"))
        if u == 5:
            p["flags"].append("U=5 proposed: CISO/CIO must justify")
        kept.append(p)
    return {**result, "proposals": kept, "not_scored": not_scored, "guard_notes": notes}, notes
