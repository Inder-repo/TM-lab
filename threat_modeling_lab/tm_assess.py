"""Completion gates, discover-first reveal gating, rubric and integrity checks (Streamlit-free).

Design rules
  * Gates evaluate the ARTEFACTS (records and their quality), never a count of threats/mappings.
  * Reference answers are reachable ONLY through get_reference(), which enforces discover-first.
  * Automatic checks are heuristics: where free text matters the rubric flags 'needs reviewer'
    rather than claiming certainty.
"""
import re
from datetime import date

import tm_catalog
import tm_labs
import tm_library
import tm_model as m

STEPS = [
    (1, "Define scope and goals", "\U0001F4D0"),
    (2, "Create and validate the DFD", "\U0001F5FA\uFE0F"),
    (3, "Apply STRIDE and build threat statements", "\u26A1"),
    (4, "Validate trust boundaries", "\U0001F6A7"),
    (5, "Map MITRE ATT&CK and CAPEC", "\U0001F3AF"),
    (6, "Assess inherent risk", "\U0001F4CA"),
    (7, "Select and verify controls", "\U0001F6E1\uFE0F"),
    (8, "Record residual risk and open questions", "\u2696\uFE0F"),
    (9, "Review schedule and deliverables", "\U0001F501"),
]
STEP_TITLES = {n: t for n, t, _ in STEPS}


# ═════════════════════════════════════════════════════════════════════════════════════
# Discover-first: hypotheses, gating, reference access
# ═════════════════════════════════════════════════════════════════════════════════════
MIN_HYPOTHESIS = 30


def set_discover_first(ws, value):
    prof = tm_labs.profile(ws["lab_id"])
    if prof["discover_first_locked"] and not value:
        raise m.ValidationError("Discover-first mode is locked on for this lab.")
    ws["settings"]["discover_first"] = bool(value)


def set_hypothesis(ws, key, text):
    text = m.clean(text)
    if len(text) < MIN_HYPOTHESIS:
        raise m.ValidationError(f"Write your own initial hypothesis first (at least {MIN_HYPOTHESIS} characters) - what do you expect to find, and why?")
    ws["hypotheses"][str(key)] = {"text": text, "at": m.now()}


def has_hypothesis(ws, key):
    return len(ws["hypotheses"].get(str(key), {}).get("text", "")) >= MIN_HYPOTHESIS


def _own(coll):
    return [r for r in coll if r.get("origin") == "learner"]


def _own_threats(ws):
    """Threats the learner wrote without starting from a library example (those do not count as an independent hypothesis)."""
    return [t for t in ws["threats"] if t.get("origin") == "learner" and not t.get("library_ref")]


# ── assistance modes: guided -> fading -> independent ───────────────────────────────────
ASSIST_MODES = ["guided", "fading", "independent"]
OP_SKILL = {"add_element": "dfd", "add_flow": "dfd", "add_boundary": "dfd", "add_threat": "threats", "update_threat": "threats",
            "create_attack_tree": "trees", "add_step": "trees", "assess_step": "trees", "add_mapping": "mappings", "add_no_mapping": "mappings",
            "set_inherent_risk": "risk", "add_control": "controls", "record_verification": "controls", "set_residual_risk": "residual",
            "set_treatment": "residual"}
SKILL_LABEL = {"dfd": "DFD modelling", "threats": "Threat statements", "trees": "Attack trees", "mappings": "ATT&CK / CAPEC mapping",
               "risk": "Risk rating", "controls": "Controls and verification", "residual": "Residual risk decisions"}


def note_attempt(ws, op, ok):
    """Record whether a submission was accepted first time. Consecutive clean submissions fade the assistance."""
    skill = OP_SKILL.get(op)
    if not skill:
        return
    c = ws["competence"].setdefault(skill, {"clean": 0, "errors": 0, "streak": 0})
    if ok:
        c["clean"] += 1
        c["streak"] += 1
    else:
        c["errors"] += 1
        c["streak"] = 0


def assist_level(ws, skill):
    """'full' (examples + drafts), 'reduced' (applicability reasons, no drafts) or 'none' (library only after your own attempt)."""
    mode = ws["settings"].get("assist_mode", "independent")
    if mode == "guided":
        return "full"
    if mode == "independent":
        return "none"
    streak = ws["competence"].get(skill, {}).get("streak", 0)
    return "full" if streak < 2 else "reduced" if streak < 4 else "none"


def set_assist_mode(ws, mode):
    prof = tm_labs.profile(ws["lab_id"])
    if mode not in ASSIST_MODES:
        raise m.ValidationError("Mode must be guided, fading or independent.")
    if prof["assist_locked"] and mode != prof["assist_default"]:
        raise m.ValidationError(f"This lab is locked to {prof['assist_default']} mode.")
    ws["settings"]["assist_mode"] = mode
    ws["settings"]["discover_first"] = mode != "guided"


def reveal_status(ws, kind, ref=None):
    """Return (allowed, reason). Pure function of the workspace - this is the single enforcement point."""
    prof = tm_labs.profile(ws["lab_id"])
    if kind == "worked_example":
        return (bool(prof["worked_example"]), "" if prof["worked_example"] else "No worked example in this lab.")
    if kind in ("library_suggestions", "library_browse", "tree_templates"):
        lvl = assist_level(ws, "trees" if kind == "tree_templates" else "threats")
        if lvl in ("full", "reduced") or not ws["settings"]["discover_first"]:
            return True, ""
        if kind == "tree_templates":
            if not has_hypothesis(ws, f"3:{ref}"):
                return False, "Independent mode: describe the attack path for this threat in your own words, then templates unlock."
            return True, ""
        if not has_hypothesis(ws, "3") or not _own_threats(ws):
            return False, "Independent mode: record your threat hypothesis and write at least one threat without help; the library unlocks after that."
        return True, ""
    if not ws["settings"]["discover_first"]:
        return True, ""
    if kind == "dfd_reference":
        own_e, own_f = _own(m.elements(ws)), _own(m.flows(ws))
        if len(own_e) < 3 or not own_f:
            return False, "Discover-first: add at least 3 elements and 1 flow of your own to the DFD first."
        if not has_hypothesis(ws, "2"):
            return False, "Discover-first: record your initial hypothesis about the architecture (what is in it, where trust changes)."
        return True, ""
    if kind in ("stride_suggestions", "reference_comparison", "attack_tree"):
        if not has_hypothesis(ws, "3"):
            return False, "Discover-first: record your initial threat hypothesis for this system first."
        if not _own_threats(ws):
            return False, "Discover-first: record at least one threat of your own (not started from a library example) before seeing reference threats."
        if kind == "reference_comparison" and m.stride_coverage(ws)["by_status"]["unconsidered"]:
            return False, "Finish considering every STRIDE applicability prompt before comparing with the reference."
        return True, ""
    if kind == "mapping_suggestions":
        if not has_hypothesis(ws, f"5:{ref}"):
            return False, "Discover-first: describe the attack path for this threat in your own words before seeing suggested techniques/patterns."
        return True, ""
    if kind == "risk_reference":
        r = m.get_risk(ws, ref)
        if not (r and r["inherent"]):
            return False, "Discover-first: rate this threat yourself before seeing reference ratings."
        return True, ""
    if kind == "control_reference":
        if not [c for c in m.controls_for(ws, ref) if c.get("origin") == "learner"]:
            return False, "Discover-first: propose at least one control of your own for this threat before seeing reference controls."
        return True, ""
    if kind == "gap_feedback":
        qs = _own(ws["questions"])
        if len(qs) < 3 or not _own_threats(ws):
            return False, "Raise at least 3 of your own questions and record a threat before comparing with the instructor's gap list."
        return True, ""
    return False, f"Unknown reference kind '{kind}'."


def _log_reveal(ws, kind, ref):
    if not any(r["kind"] == kind and r.get("ref") == ref for r in ws["reveals"]):
        ws["reveals"].append({"kind": kind, "ref": ref, "at": m.now(),
                              "hypothesis_recorded_first": any(True for _ in ws["hypotheses"])})


def get_reference(ws, kind, ref=None):
    """The ONLY way application code obtains instructor reference content."""
    ok, why = reveal_status(ws, kind, ref)
    if not ok:
        raise m.RevealLocked(why)
    lab = ws["lab_id"]
    prof = tm_labs.profile(lab)
    if kind == "worked_example":
        return tm_labs.worked_example(lab)
    if kind == "dfd_reference":
        model = tm_labs.reference_model(lab)
        mode = prof["reference_dfd"]
        _log_reveal(ws, kind, ref)
        if mode == "inventory":
            model = {"elements": model["elements"], "flows": [], "boundaries": []}
        return {"mode": mode, "model": model,
                "note": {"load": "Starter DFD: review every element, flow and protocol - it is a starting point, not the answer.",
                         "inventory": "Component inventory only. Flows, protocols and trust boundaries are yours to decide.",
                         "compare": "Reference DFD for comparison only. It is the lab author's drawing and is also incomplete or arguable in places."}[mode]}
    if kind == "library_suggestions":
        lvl = assist_level(ws, "threats")
        _log_reveal(ws, kind, ref)
        items = tm_library.suggest_patterns(ws, ref, with_drafts=(lvl == "full"))
        for it in items:
            if lvl == "full":
                it["worked_example"] = tm_library.PATTERN_BY_ID[it["pattern_id"]]["worked_example"]
        return {"level": lvl, "items": items, "context": [tm_library.TAG_DESC[t] for t in sorted(tm_library.context_tags(ws, ref)) if t in tm_library.TAG_DESC],
                "note": {"full": "Guided: each suggestion includes a draft you can start from - rewrite it for your system.",
                         "reduced": "Assistance is fading: you see why each pattern applies, but you write the threat yourself.",
                         "none": "Independent: reference only. You write the threat yourself."}[lvl]}
    if kind == "library_browse":
        lvl = assist_level(ws, "threats")
        _log_reveal(ws, kind, ref)
        return {"level": lvl, "patterns": tm_library.PATTERNS, "trees": tm_library.TREES}
    if kind == "tree_templates":
        lvl = assist_level(ws, "trees")
        t = m.find(ws["threats"], ref)
        _log_reveal(ws, kind, ref)
        items = tm_library.suggest_trees(ws, t)
        for it in items:
            if lvl == "full":
                it["worked_example"] = tm_library.TREE_BY_ID[it["tree_id"]]["worked_example"]
        return {"level": lvl, "items": items}
    if kind == "attack_tree":
        import lab_data
        _log_reveal(ws, kind, ref)
        tr = lab_data.ATTACK_TREES[lab]
        return {"title": tr["title"], "description": tr["description"], "dot": _tree_dot(tr["tree"]),
                "note": "One author's view of attack paths. Use it to challenge your own threats, not to copy."}
    if kind in ("stride_suggestions", "reference_comparison"):
        _log_reveal(ws, kind, ref)
        return _reference_threats_for(ws, ref, comparison=(kind == "reference_comparison"))
    if kind == "mapping_suggestions":
        t = m.find(ws["threats"], ref)
        _log_reveal(ws, kind, ref)
        return {"attack": tm_catalog.search("ATT&CK", stride_letter=t["stride"], limit=12),
                "capec": tm_catalog.search("CAPEC", limit=12),
                "note": "Candidates sorted by STRIDE alignment. Alignment is a sort hint only: map only what your attack path supports."}
    if kind == "risk_reference":
        _log_reveal(ws, kind, ref)
        return [{"ref_id": x["ref_id"], "summary": x["summary"], "likelihood": x["likelihood"], "impact": x["impact"], "why": x["why"]}
                for x in _related_reference(ws, ref, with_rating=True)]
    if kind == "control_reference":
        t = m.find(ws["threats"], ref)
        import lab_data
        _log_reveal(ws, kind, ref)
        rel = _related_reference(ws, ref)
        owasp = lab_data.OWASP_STRIDE_MAP.get(m.STRIDE[t["stride"]], {})
        return {"related_reference_threats": [{"ref_id": x["ref_id"], "examples": x["mitigation_examples"]} for x in rel],
                "owasp": owasp.get("owasp", []), "owasp_detail": owasp.get("owasp_detail", ""),
                "note": "Supporting material only. STRIDE-to-OWASP is a teaching aid, not an authoritative one-to-one mapping; "
                        "also consult NIST SP 800-53/218, ASVS and your cloud provider's guidance."}
    if kind == "gap_feedback":
        _log_reveal(ws, kind, ref)
        return gap_feedback(ws)
    raise m.RevealLocked("Unknown reference")


def _tree_dot(root):
    lines, n = ["digraph T { rankdir=TB; node [fontname=Helvetica,fontsize=10,shape=box];"], [0]
    def walk(node):
        n[0] += 1
        me = f"n{n[0]}"
        label = str(node.get("label", "")).replace('"', "'").replace("\n", "\\n")
        if node.get("difficulty"):
            label += f"\\n({node['difficulty']})"
        shape = {"goal": "doubleoctagon", "or": "diamond", "and": "hexagon"}.get(node.get("type"), "box")
        lines.append(f'{me} [label="{label}", shape={shape}];')
        for ch in node.get("children", []):
            lines.append(f"{me} -> {walk(ch)};")
        return me
    walk(root)
    lines.append("}")
    return "\n".join(lines)


def _resolve_ref_targets(ws, rt):
    ids = []
    for t in rt["targets"]:
        if t["kind"] == "element":
            e = m.element_by_name(ws, t["name"])
            if e:
                ids.append(e["id"])
        else:
            a, b = m.element_by_name(ws, t["source"]), m.element_by_name(ws, t["destination"])
            if a and b:
                ids += [f["id"] for f in m.flows(ws) if f["source"] == a["id"] and f["destination"] == b["id"]]
    return ids


def _related_reference(ws, threat_id, with_rating=False):
    import lab_data
    t = m.find(ws["threats"], threat_id)
    out = []
    raw = {x["id"]: x for x in lab_data.PREDEFINED_THREATS.get(ws["lab_id"], [])}
    for rt in tm_labs.reference_threats(ws["lab_id"]):
        ids = _resolve_ref_targets(ws, rt)
        if ids and set(ids) & set(t["targets"]) and rt["stride_letter"] == t["stride"]:
            x = dict(rt)
            if with_rating:
                x.update({"likelihood": raw[rt["ref_id"]]["likelihood"], "impact": raw[rt["ref_id"]]["impact"], "why": raw[rt["ref_id"]]["why_this_risk"]})
            out.append(x)
    return out


def _reference_threats_for(ws, ref, comparison=False):
    learner = ws["threats"]
    rows = []
    for rt in tm_labs.reference_threats(ws["lab_id"]):
        ids = _resolve_ref_targets(ws, rt)
        row = {"ref_id": rt["ref_id"], "stride": rt["stride"], "summary": rt["summary"], "explanation": rt["explanation"],
               "resolved_target_ids": ids, "unresolved": rt["unresolved_targets"]}
        if comparison:
            same = [t["id"] for t in learner if set(t["targets"]) & set(ids) and t["stride"] == rt["stride_letter"]]
            alt = [t["id"] for t in learner if set(t["targets"]) & set(ids) and t["stride"] != rt["stride_letter"]]
            if rt["unresolved_targets"] and not ids:
                row["status"] = "reference_target_not_in_dfd"
                row["guidance"] = ("The reference threat refers to " + ", ".join(rt["unresolved_targets"]) +
                                   ", which is not in the lab's DFD. Consider whether your DFD should include it.")
            elif same:
                row["status"], row["learner_threats"] = "covered", same
                row["guidance"] = "You analysed this element/flow with the same STRIDE category."
            elif alt:
                row["status"], row["learner_threats"] = "alternative_framing", alt
                row["guidance"] = "You analysed this element/flow under a different STRIDE category. Check whether both categories are justified."
            else:
                row["status"] = "not_addressed"
                row["guidance"] = "Not addressed in your model. This is not automatically a gap - re-read your STRIDE reasoning for this element/flow."
        rows.append(row)
    if comparison:
        ref_ids = set()
        for rt in tm_labs.reference_threats(ws["lab_id"]):
            ref_ids |= set(_resolve_ref_targets(ws, rt))
        novel = [t["id"] for t in learner if not (set(t["targets"]) & ref_ids)]
        return {"rows": rows, "learner_threats_outside_reference": novel,
                "note": "Threats outside the reference are valid alternatives if their reasoning holds; they are flagged for reviewer attention, not marked wrong."}
    return rows


def gap_feedback(ws):
    gaps = tm_labs.known_gaps(ws["lab_id"])
    qs = [q["text"].lower() for q in _own(ws["questions"])] + [a["text"].lower() for a in ws["scope"]["assumptions"] if a.get("origin") == "learner"]
    out = []
    for g in gaps:
        hit = any(any(k in q for k in g["keywords"]) for q in qs)
        out.append({"id": g["id"], "topic": g["topic"], "status": "possibly raised (reviewer to confirm)" if hit else "not raised"})
    return out


# ═════════════════════════════════════════════════════════════════════════════════════
# Integrity
# ═════════════════════════════════════════════════════════════════════════════════════
def integrity_issues(ws):
    out = []
    ids = [r["id"] for coll in ("threats", "mappings", "risks", "controls", "questions") for r in ws[coll]]
    ids += [r["id"] for coll in (m.elements(ws), m.flows(ws), m.boundaries(ws)) for r in coll]
    seen = set()
    for i in ids:
        if i in seen:
            out.append(m.issue("error", "id.duplicate", f"Duplicate ID {i}", i))
        seen.add(i)
    reused = seen & set(ws["deleted_ids"])
    for i in sorted(reused):
        out.append(m.issue("error", "id.reused", f"ID {i} was deleted but is in use again", i))
    for f in m.flows(ws):
        for k in ("source", "destination"):
            if not m.find(m.elements(ws), f[k]):
                out.append(m.issue("error", "flow.endpoint", f"{f['id']} {k} {f[k]} does not exist", f["id"]))
    for b in m.boundaries(ws):
        for x in b["members"]:
            if not m.find(m.elements(ws), x):
                out.append(m.issue("error", "boundary.member", f"{b['id']} member {x} does not exist", b["id"]))
    for t in ws["threats"]:
        for x in t["targets"]:
            if not m.get_target(ws, x):
                out.append(m.issue("error", "threat.target", f"{t['id']} references unknown {x}", t["id"]))
        for a in t.get("assumption_ids", []):
            if not m.find(ws["scope"]["assumptions"], a):
                out.append(m.issue("warning", "threat.assumption", f"{t['id']} references unknown assumption {a}", t["id"]))
    for mp in ws["mappings"]:
        if not m.find(ws["threats"], mp["threat_id"]):
            out.append(m.issue("error", "mapping.threat", f"{mp['id']} references unknown threat {mp['threat_id']}", mp["id"]))
    for r in ws["risks"]:
        if not m.find(ws["threats"], r["threat_id"]):
            out.append(m.issue("error", "risk.threat", f"{r['id']} references unknown threat {r['threat_id']}", r["id"]))
        res = r.get("residual") or {}
        for c in res.get("basis_control_ids", []):
            if not m.find(ws["controls"], c):
                out.append(m.issue("error", "risk.control", f"{r['id']} residual relies on unknown control {c}", r["id"]))
    for c in ws["controls"]:
        if not c["threat_ids"]:
            out.append(m.issue("error", "control.unlinked", f"{c['id']} is not linked to any threat", c["id"]))
        for t in c["threat_ids"]:
            if not m.find(ws["threats"], t):
                out.append(m.issue("error", "control.threat", f"{c['id']} references unknown threat {t}", c["id"]))
        if c["status"] == "verified" and not (c.get("verification") and c["verification"].get("evidence")):
            out.append(m.issue("error", "control.verified_no_evidence", f"{c['id']} is 'verified' without evidence", c["id"]))
    for tid, tr in ws["attack_trees"].items():
        if not m.find(ws["threats"], tid):
            out.append(m.issue("error", "tree.threat", f"Attack tree for unknown threat {tid}", tid))
        ids_ = [n["id"] for n in tr["nodes"]]
        if len(ids_) != len(set(ids_)):
            out.append(m.issue("error", "tree.duplicate_step", f"Attack tree {tid} has duplicate step IDs", tid))
        for n in tr["nodes"]:
            if n["parent"] is not None and n["parent"] not in ids_:
                out.append(m.issue("error", "tree.parent", f"{n['id']} has unknown parent {n['parent']}", n["id"]))
        if len([n for n in tr["nodes"] if n["parent"] is None]) != 1:
            out.append(m.issue("error", "tree.root", f"Attack tree {tid} must have exactly one goal", tid))
    for c in ws["controls"]:
        for sid in c.get("step_ids", []):
            if not any(m._step_of_threat(ws, t, sid) for t in c["threat_ids"]):
                out.append(m.issue("error", "control.step", f"{c['id']} is linked to unknown or foreign attack step {sid}", c["id"]))
    for mp in ws["mappings"]:
        if mp.get("step_id") and not m._step_of_threat(ws, mp["threat_id"], mp["step_id"]):
            out.append(m.issue("error", "mapping.step", f"{mp['id']} refers to unknown attack step {mp['step_id']}", mp["id"]))
    for q in ws["questions"]:
        for x in q["related"]:
            if not (m.get_target(ws, x) or m.find(ws["threats"], x) or m.find(ws["controls"], x)):
                out.append(m.issue("warning", "question.related", f"{q['id']} references unknown {x}", q["id"]))
    return out


# ═════════════════════════════════════════════════════════════════════════════════════
# Gates
# ═════════════════════════════════════════════════════════════════════════════════════
def _e(code, msg, step, ref=None):
    return m.issue("error", code, msg, ref, step)


def _w(code, msg, step, ref=None):
    return m.issue("warning", code, msg, ref, step)


def prerequisites(ws, step):
    """Minimum upstream artefacts needed to do this step at all (navigation guidance, not completion)."""
    els, fls = m.elements(ws), m.flows(ws)
    if step == 3 and (len(els) < 2 or not fls):
        return ["Step 2 first: the DFD needs at least two elements and one flow before threats can be tied to IDs."]
    if step == 4 and (len(els) < 2 or not fls):
        return ["Step 2 first: boundaries and crossings come from your DFD."]
    if step in (5, 6) and not ws["threats"]:
        return ["Step 3 first: record at least one threat statement."]
    if step == 7 and not [r for r in ws["risks"] if r["inherent"]]:
        return ["Step 6 first: controls are prioritised by inherent risk - rate at least one threat."]
    if step == 8 and not ws["risks"]:
        return ["Step 6 first: residual risk is assessed against an inherent rating."]
    return []


def gate_scope(ws):
    sc, B = ws["scope"], []
    if len(sc["purpose"]) < 40:
        B.append(_e("scope.purpose", "State the system purpose and business context in a full sentence or two.", 1))
    if not sc["in_scope"]:
        B.append(_e("scope.in", "List the in-scope components/boundaries.", 1))
    if not sc["exclusions"]:
        B.append(_e("scope.out", "Record at least one exclusion (and why) - or explain that nothing is excluded.", 1))
    if not sc["objectives"]:
        B.append(_e("scope.obj", "Add at least one security objective.", 1))
    if not sc["assets"]:
        B.append(_e("scope.assets", "Identify the important assets.", 1))
    if not any(s["accountable"] for s in sc["stakeholders"]):
        B.append(_e("scope.stake", "Name at least one accountable stakeholder/reviewer.", 1))
    if not sc["facts"]:
        B.append(_e("scope.facts", "Record the confirmed facts you are relying on.", 1))
    if not sc["assumptions"]:
        B.append(_e("scope.assump", "Record assumptions separately from facts (even 'no further assumptions' needs a validated statement).", 1))
    if not sc["success_criteria"]:
        B.append(_e("scope.success", "Define success criteria for this threat model.", 1))
    if not sc["data_sensitivity"] and not sc["regulatory"]:
        B.append(_e("scope.data", "Describe data sensitivity and any regulatory constraints.", 1))
    if sc["version"] == 0:
        B.append(_e("scope.version", "Commit the scope as version 1 (with a change note).", 1))
    W = []
    if sc["version"] and m.scope_changed_since_commit(ws):
        W.append(_w("scope.uncommitted", "Scope has changes since the last committed version.", 1))
    for a in sc["assumptions"]:
        if a["status"] == "needs validation" and not a.get("validation_owner"):
            W.append(_w("scope.assump_owner", f"{a['id']}: assumption needs a validation owner.", 1, a["id"]))
    for x in sc["exclusions"]:
        if not x.get("reason") or "migrated" in x.get("reason", ""):
            W.append(_w("scope.excl_reason", f"{x['id']}: add the reason for this exclusion.", 1, x["id"]))
    return B, W


def gate_dfd(ws):
    iss = m.dfd_issues(ws)
    B = [i for i in iss if i["severity"] == "error"]
    W = [i for i in iss if i["severity"] == "warning"]
    if ws["dfd"]["version"] == 0:
        B.append(_e("dfd.version", "Commit the DFD as version 1 (with a change note).", 2))
    elif m.dfd_changed_since_commit(ws):
        W.append(_w("dfd.uncommitted", "DFD has changes since the last committed version - commit to record them.", 2))
    return B, W


def gate_stride(ws):
    B, W = [], []
    cov = m.stride_coverage(ws)
    if cov["by_status"]["unconsidered"]:
        B.append(_e("stride.unconsidered", f"{cov['by_status']['unconsidered']} STRIDE applicability prompt(s) not yet considered.", 3))
    if cov["by_status"]["stale"]:
        B.append(_e("stride.stale", f"{cov['by_status']['stale']} STRIDE disposition(s) were made before the model changed - re-check them.", 3))
    if cov["by_status"]["deferred"]:
        W.append(_w("stride.deferred", f"{cov['by_status']['deferred']} prompt(s) are deferred - resolve or justify them.", 3))
    for t in ws["threats"]:
        for e in m.threat_issues(ws, t):
            B.append(_e("threat.invalid", f"{t['id']}: {e}", 3, t["id"]))
        if t.get("stale"):
            B.append(_e("threat.stale", f"{t['id']} is stale: {t['stale'][-1]['reason']}", 3, t["id"]))
        if "[" in m.statement_text(ws, t) and "]" in m.statement_text(ws, t) and not t.get("statement_override"):
            B.append(_e("threat.placeholder", f"{t['id']}: statement still has template placeholders.", 3, t["id"]))
        if m.departs_from_standard(ws, t):
            W.append(_w("threat.departure", f"{t['id']} departs from the standard applicability model - reviewer should read the departure rationale.", 3, t["id"]))
    need_tree = tm_labs.profile(ws["lab_id"])["require_attack_trees"]
    for t in ws["threats"]:
        an = m.tree_analysis(ws, t["id"])
        if not an["exists"]:
            (B if need_tree else W).append((_e if need_tree else _w)("tree.missing", f"{t['id']}: build an attack tree (the steps an attacker would take)" + ("" if need_tree else " - optional in this lab, but it makes risk and control decisions traceable"), 3, t["id"]))
        else:
            for iss in an["structure_issues"]:
                B.append(_e("tree.structure", f"{t['id']} attack tree: {iss}.", 3, t["id"]))
            tr = m.get_tree(ws, t["id"])
            if tr.get("stale"):
                B.append(_e("tree.stale", f"{t['id']} attack tree is stale: {tr['stale'][-1]['reason']}", 3, t["id"]))
    if not ws["threats"] and not B:
        W.append(_w("stride.no_threats", "No threats recorded; every prompt was documented as not applicable or mitigated - reviewer should confirm.", 3))
    return B, W


def gate_boundaries(ws):
    B, W = [], []
    if not m.boundaries(ws):
        if ws["dfd"]["no_boundary_rationale"]:
            W.append(_w("tb.single_domain", "Single trust domain declared - reviewer should confirm.", 4))
            return B, W
        B.append(_e("tb.none", "No boundaries from Step 2 to validate.", 4))
        return B, W
    for inv in m.boundary_inventory(ws):
        b = inv["boundary"]
        if not inv["review"]:
            B.append(_e("tb.unreviewed", f"{b['id']} '{b['name']}': justify the boundary.", 4, b["id"]))
        elif inv["review"].get("stale"):
            B.append(_e("tb.stale", f"{b['id']} review is stale: {inv['review']['stale'][-1]['reason']}", 4, b["id"]))
        if not inv["crossings"]:
            W.append(_w("tb.no_crossing", f"{b['id']} '{b['name']}' has no crossing flows - is a flow missing, or is the boundary unnecessary?", 4, b["id"]))
        for c in inv["crossings"]:
            key = f"{b['id']}|{c['flow_id']}"
            if not c["review"]:
                B.append(_e("tb.crossing", f"{key}: document the trust assumption, control and evidence at this crossing.", 4, key))
            elif c["review"].get("stale"):
                B.append(_e("tb.crossing_stale", f"{key} is stale: {c['review']['stale'][-1]['reason']}", 4, key))
    return B, W


def gate_mappings(ws):
    B, W = [], []
    for t in ws["threats"]:
        dec = m.mapping_decisions(ws, t["id"])
        for fw, d in dec.items():
            if d == "undecided":
                B.append(_e("map.undecided", f"{t['id']}: decide on {fw} (map it, or record 'no defensible mapping' with a reason).", 5, t["id"]))
    for mp in ws["mappings"]:
        if mp.get("stale"):
            B.append(_e("map.stale", f"{mp['id']} is stale: {mp['stale'][-1]['reason']}", 5, mp["id"]))
        if mp["catalogue_status"] == "unlisted-pending-verification":
            W.append(_w("map.unlisted", f"{mp['id']} ({mp['ref_id']}) is not in the local dataset - verify at the official source.", 5, mp["id"]))
    meta = tm_catalog.catalogue_meta()
    for fw in tm_catalog.FRAMEWORKS:
        if meta[fw]["status"] != "verified" and any(mp["framework"] == fw for mp in ws["mappings"]):
            W.append(_w("map.unverified_catalogue", f"The local {fw} dataset is '{meta[fw]['status']}' - run tools/verify_catalogues.py against the official source before relying on names/versions.", 5))
    return B, W


def gate_risk(ws):
    B, W = [], []
    for t in ws["threats"]:
        r = m.get_risk(ws, t["id"])
        if not r or not r["inherent"]:
            B.append(_e("risk.unrated", f"{t['id']}: inherent risk not assessed.", 6, t["id"]))
        elif r.get("stale"):
            B.append(_e("risk.stale", f"{r['id']} is stale: {r['stale'][-1]['reason']}", 6, r["id"]))
    for t in ws["threats"]:
        an = m.tree_analysis(ws, t["id"])
        if an["exists"] and an["unassessed"] and not an["structure_issues"]:
            B.append(_e("risk.steps", f"{t['id']}: validate {len(an['unassessed'])} attack step(s) - plausible or implausible, with a reason - before rating.", 6, t["id"]))
    rated = [r["inherent"]["score"] for r in ws["risks"] if r["inherent"]]
    if len(rated) >= 4 and len(set(rated)) == 1:
        W.append(_w("risk.flat", "All threats have the identical inherent score - reviewer should check the ratings differentiate.", 6))
    return B, W


def gate_controls(ws):
    B, W = [], []
    for t in ws["threats"]:
        r = m.get_risk(ws, t["id"])
        live = [c for c in m.controls_for(ws, t["id"]) if c["status"] != "rejected"]
        if r and r["inherent"] and r["inherent"]["band"] != "Low" and not live:
            B.append(_e("ctl.none", f"{t['id']} ({r['inherent']['band']}): propose at least one control (or reconsider the threat/rating).", 7, t["id"]))
    for t in ws["threats"]:
        r = m.get_risk(ws, t["id"])
        an = m.tree_analysis(ws, t["id"])
        if r and r["inherent"] and an["exists"] and an["viable"] and r["inherent"]["band"] != "Low":
            for p in an["easiest_tier"]:
                if p["state"] == "open":
                    B.append(_e("ctl.path", f"{t['id']}: no control is linked to the easiest attack path ({' + '.join(p['steps'])}). Link a control to one of its steps.", 7, t["id"]))
            others = [p for p in an["viable"] if p["state"] == "open" and p not in an["easiest_tier"]]
            if others:
                W.append(_w("ctl.path_other", f"{t['id']}: {len(others)} other viable attack path(s) have no linked control.", 7, t["id"]))
    for c in ws["controls"]:
        if c.get("stale"):
            B.append(_e("ctl.stale", f"{c['id']} is stale: {c['stale'][-1]['reason']}", 7, c["id"]))
        if c["status"] in ("planned", "implemented", "verified") and not c["owner"]:
            B.append(_e("ctl.owner", f"{c['id']}: {c['status']} control needs an owner.", 7, c["id"]))
        if c["status"] == "proposed" and not c["owner"]:
            W.append(_w("ctl.owner_proposed", f"{c['id']}: proposed control has no owner yet.", 7, c["id"]))
        if c["status"] == "implemented":
            W.append(_w("ctl.unverified", f"{c['id']} is implemented but not verified - it cannot support a risk reduction.", 7, c["id"]))
        if c["status"] == "verification_failed":
            W.append(_w("ctl.failed", f"{c['id']} FAILED verification: {c['verification']['evidence'][:80]}", 7, c["id"]))
    return B, W


def gate_residual(ws):
    B, W = [], []
    today_ = date.today()
    for t in ws["threats"]:
        r = m.get_risk(ws, t["id"])
        if not r or not r.get("residual"):
            B.append(_e("res.missing", f"{t['id']}: residual risk not assessed.", 8, t["id"]))
        elif not r.get("treatment"):
            B.append(_e("res.treatment", f"{t['id']}: record a treatment decision, owner and justification.", 8, t["id"]))
        elif r.get("stale"):
            B.append(_e("res.stale", f"{r['id']} is stale: {r['stale'][-1]['reason']}", 8, r["id"]))
    for q in ws["questions"]:
        if q["status"] == "open":
            if not q["owner"] or not q["due"]:
                B.append(_e("q.owner", f"{q['id']}: open question needs an owner and a due date.", 8, q["id"]))
            elif m.parse_date(q["due"]) and m.parse_date(q["due"]) < today_:
                W.append(_w("q.overdue", f"{q['id']} is overdue ({q['due']}).", 8, q["id"]))
    need = ws["lab_id"] in ("3", "4")
    if not ws["questions"]:
        (B if need else W).append((_e if need else _w)("q.none", "Record at least one open question (every model has unknowns).", 8))
    for r in ws["risks"]:
        tr = r.get("treatment")
        if tr and tr["decision"] == "accept" and m.parse_date(tr.get("review_by")) and m.parse_date(tr["review_by"]) < today_:
            W.append(_w("res.accept_expired", f"{r['id']}: accepted risk is past its review-by date.", 8, r["id"]))
    return B, W


def gate_review(ws):
    rp, B, W = ws["review"], [], []
    for k, label in (("model_owner", "model owner"), ("security_reviewer", "security reviewer"), ("required_approval", "required approval"),
                     ("required_evidence", "required evidence")):
        if len(rp[k]) < 3:
            B.append(_e("rev.field", f"Review plan: record the {label}.", 9))
    d = m.parse_date(rp["next_review"])
    if not d:
        B.append(_e("rev.next", "Set the next review date.", 9))
    elif d < date.today():
        B.append(_e("rev.next_past", "The next review date is in the past.", 9))
    if not rp["cadence"]:
        B.append(_e("rev.cadence", "Choose a lightweight review cadence.", 9))
    if not rp["full_triggers"]:
        B.append(_e("rev.full", "Define what triggers a full re-model.", 9))
    if not rp["change_triggers"]:
        B.append(_e("rev.trig", "Select change triggers (scope, architecture, dependency, identity, data-flow, control).", 9))
    if not ws["remodel"]["completed"]:
        B.append(_e("rev.remodel", "Complete the practical re-modelling exercise.", 9))
    for s in m.stale_items(ws):
        B.append(_e("rev.stale", f"{s['kind']} {s['id']} still needs revalidation.", 9, s["id"]))
    for i in integrity_issues(ws):
        if i["severity"] == "error":
            B.append(_e("rev.integrity", i["message"], 9, i["ref"]))
    return B, W


GATES = {1: gate_scope, 2: gate_dfd, 3: gate_stride, 4: gate_boundaries, 5: gate_mappings,
         6: gate_risk, 7: gate_controls, 8: gate_residual, 9: gate_review}


def _started(ws, step):
    rp = ws["review"]
    return {
        1: bool(ws["scope"]["purpose"] or ws["scope"]["in_scope"] or ws["scope"]["version"]),
        2: bool(_own(m.elements(ws)) or ws["dfd"]["version"]),
        3: bool(ws["threats"] or ws["stride_cells"] or ws["attack_trees"]),
        4: bool(ws["boundary_reviews"] or ws["crossing_reviews"]),
        5: bool(ws["mappings"]),
        6: bool([r for r in ws["risks"] if r["inherent"]]),
        7: bool(ws["controls"]),
        8: bool([r for r in ws["risks"] if r.get("residual") or r.get("treatment")] or ws["questions"]),
        9: bool(rp["model_owner"] or rp["next_review"] or rp["full_triggers"] or ws["remodel"]["completed"]),
    }[step]


def step_status(ws, step):
    pre = prerequisites(ws, step)
    if pre:
        return {"step": step, "state": "blocked", "blockers": [m.issue("error", "prereq", p, None, step) for p in pre], "warnings": []}
    B, W = GATES[step](ws)
    state = "complete" if not B and _started(ws, step) else "in_progress" if _started(ws, step) else "not_started"
    return {"step": step, "state": state, "blockers": B, "warnings": W}


def progress(ws):
    out = []
    for n, title, icon in STEPS:
        s = step_status(ws, n)
        s.update({"title": title, "icon": icon})
        out.append(s)
    return out


def lab_complete(ws):
    return all(p["state"] == "complete" for p in progress(ws))


def outstanding_actions(ws):
    acts = []
    for p in progress(ws):
        if p["state"] in ("in_progress", "not_started") or (p["state"] == "blocked"):
            for b in p["blockers"]:
                acts.append({"type": "gate", "step": p["step"], "ref": b.get("ref"), "action": b["message"]})
    for q in ws["questions"]:
        if q["status"] == "open":
            acts.append({"type": "question", "step": 8, "ref": q["id"], "owner": q["owner"], "due": q["due"], "action": q["text"]})
    for c in ws["controls"]:
        if c["status"] in ("proposed", "planned", "implemented", "verification_failed"):
            acts.append({"type": "control", "step": 7, "ref": c["id"], "owner": c["owner"], "action": f"{c['title']} is {c['status'].replace('_', ' ')}"})
    for s in m.stale_items(ws):
        acts.append({"type": "revalidate", "step": 9, "ref": s["id"], "action": f"Revalidate {s['kind']} {s['id']}: {s['reasons'][-1]}"})
    seen, uniq = set(), []
    for a in acts:
        k = (a["type"], a["ref"], a["action"])
        if k not in seen:
            seen.add(k)
            uniq.append(a)
    return uniq


# ═════════════════════════════════════════════════════════════════════════════════════
# Rubric (deterministic criteria + explicit reviewer flags; no unexplained percentages)
# ═════════════════════════════════════════════════════════════════════════════════════
def _crit(text, met, why, detail=""):
    return {"text": text, "met": met, "why": why, "detail": detail}


def _mentions_system(ws, text, t=None):
    text = (text or "").lower()
    names = [e["name"].lower() for e in m.elements(ws)] + [f["data"].lower() for f in m.flows(ws)] + [f["protocol"].lower() for f in m.flows(ws) if f["protocol"]]
    names += [a["name"].lower() for a in ws["scope"]["assets"]]
    return any(n and n in text for n in names)


def _specific(ws, t):
    a = t["action"]
    return len(a.split()) >= 8 and (_mentions_system(ws, a + " " + t["preconditions"] + " " + t["impact"]))


def rubric(ws):
    prof = tm_labs.profile(ws["lab_id"])
    sc, els, fls, thr = ws["scope"], m.elements(ws), m.flows(ws), ws["threats"]
    D = []
    def dim(key, label, crits, flags, reconsider_extra=None):
        met = sum(1 for c in crits if c["met"])
        total = len(crits)
        frac = met / total if total else 0
        level = "Not yet evidenced" if not met else "Strong" if frac == 1 else "Proficient" if frac >= 0.75 else "Developing"
        D.append({"key": key, "label": label, "criteria": crits, "met": met, "total": total, "level": level, "needs_review": flags,
                  "reconsider": [c["why"] for c in crits if not c["met"]], "strengths": [c["text"] for c in crits if c["met"]],
                  "expectation": prof["expectations"].get(key, "")})

    dim("scope", "Scope quality", [
        _crit("Purpose and context are stated", len(sc["purpose"]) >= 40, "Without a stated purpose you cannot judge what matters."),
        _crit("In-scope components and exclusions are explicit", bool(sc["in_scope"] and sc["exclusions"]), "Unstated boundaries are where reviews silently disagree."),
        _crit("Confirmed facts are separated from assumptions", bool(sc["facts"] and sc["assumptions"]), "Assumptions must be validated, facts need not be."),
        _crit("Each assumption needing validation has an owner", all(a.get("validation_owner") for a in sc["assumptions"] if a["status"] == "needs validation") and bool(sc["assumptions"]), "An assumption nobody validates is a hidden risk."),
        _crit("Objectives, assets and an accountable reviewer exist", bool(sc["objectives"] and sc["assets"] and any(s["accountable"] for s in sc["stakeholders"])), "Risk ratings need assets and objectives; decisions need an accountable person."),
        _crit("Scope is versioned", sc["version"] >= 1, "Versioned scope lets reviewers see what the model was based on."),
    ], ["Purpose and success criteria are free text - a reviewer should judge specificity."])

    ext = [e for e in els if e["type"] == "external_entity"]
    cross = {c["flow_id"] for c in m.crossings(ws)}
    dim("dfd", "DFD completeness and accuracy", [
        _crit("External entities, processes and data stores are present", all(any(e["type"] == t for e in els) for t in m.ELEMENT_TYPES), "A model without all three element types is usually missing a store or an actor."),
        _crit("Every flow has protocol and data classification", bool(fls) and all(f["protocol"] and f["classification"] for f in fls), "Protocol and classification decide which STRIDE threats are plausible."),
        _crit("No disconnected elements", bool(els) and not [i for i in m.dfd_issues(ws) if i["code"] == "element.disconnected"], "A disconnected element means flows are missing."),
        _crit("Trust boundaries drawn (or single domain justified)", bool(m.boundaries(ws)) or bool(ws["dfd"]["no_boundary_rationale"]), "Boundaries are where trust assumptions change."),
        _crit("Boundary-crossing flows record how the caller is authenticated", bool(cross) and all(m.find(fls, f)["authenticated"] for f in cross), "Identity at crossings drives spoofing and elevation threats."),
        _crit("DFD is versioned and up to date", ws["dfd"]["version"] >= 1 and not m.dfd_changed_since_commit(ws), "Reviewers need to know which DFD the threats refer to."),
    ] + ([_crit("You inferred at least one element the brief did not draw (marked as assumption)", any(e["assumed"] for e in els), "Unfamiliar systems always contain implied components - finding them is the skill.")] if ws["lab_id"] == "4" else []),
        ["External-entity justifications are free text."] if ext else [])

    cov = m.stride_coverage(ws)
    dim("stride", "STRIDE applicability and reasoning", [
        _crit("Every applicability prompt was considered", bool(cov["total"]) and not cov["by_status"]["unconsidered"], "Prompts are where you look; skipping them leaves blind spots."),
        _crit("No prompt is left deferred", bool(cov["total"]) and not cov["by_status"]["deferred"], "Deferred means undecided."),
        _crit("Recorded threats are valid and linked to existing DFD IDs", bool(thr) and not [t for t in thr if m.threat_issues(ws, t)], "Untraceable threats cannot be maintained."),
        _crit("Departures from the standard model are explained", all(not m.departs_from_standard(ws, t) or len(t["departure_rationale"]) >= 25 for t in thr), "Departing from STRIDE-per-element is legitimate only with a reason."),
    ], [f"{t['id']}: departs from the standard model - reviewer should read the reasoning." for t in thr if m.departs_from_standard(ws, t)] +
       [f"{t['id']}: rationale is short." for t in thr if len(t["rationale"]) < 40])

    dim("statements", "Threat-statement specificity and plausibility", [
        _crit("Statements have no unfilled template placeholders", bool(thr) and all("[" not in m.statement_text(ws, t) for t in thr), "A template with gaps is not yet a threat."),
        _crit("Actions are concrete and refer to this system", bool(thr) and all(_specific(ws, t) for t in thr), "Generic threats ('hacker steals data') do not lead to testable controls."),
        _crit("Each threat names an asset and a security property", bool(thr) and all(t["assets"] and t["security_property"] for t in thr), "Impact must attach to something that matters."),
        _crit("Confidence and evidence/uncertainty are stated", bool(thr) and all(t["confidence"] and (t["evidence"] or t["uncertainties"]) for t in thr), "Uncertainty is part of the answer."),
    ], [f"{t['id']}: plausibility cannot be judged automatically - reviewer to read." for t in thr] if thr else [])

    mapped = [mp for mp in ws["mappings"] if mp["outcome"] == "mapped"]
    dim("mappings", "ATT&CK / CAPEC mapping quality", [
        _crit("Every threat has a decision for ATT&CK and for CAPEC", bool(thr) and all(d != "undecided" for t in thr for d in m.mapping_decisions(ws, t["id"]).values()), "Deciding not to map is fine; not deciding is not."),
        _crit("Mappings cite the scenario in their rationale", bool(mapped) and all(_mentions_system(ws, mp["rationale"] + " " + mp["behaviour"]) for mp in mapped) or (not mapped and bool(ws["mappings"])), "A mapping that never mentions the system was probably chosen from the STRIDE label."),
        _crit("No mapping relies on an unlisted/unverified ID", not [mp for mp in ws["mappings"] if mp["catalogue_status"] == "unlisted-pending-verification"], "IDs and names must come from an authoritative source."),
        _crit("'No defensible mapping' decisions have reasons", all(len(mp["rationale"]) >= 30 for mp in ws["mappings"] if mp["outcome"] == "no_defensible_mapping"), "Absence of a mapping is a finding, so explain it."),
    ], ["Catalogue provenance: " + "; ".join(f"{fw} {v['status']}" for fw, v in tm_catalog.catalogue_meta().items())] + ["Mapping appropriateness is a reviewer judgement."] if ws["mappings"] else [])

    rk = [m.get_risk(ws, t["id"]) for t in thr]
    dim("risk", "Inherent-risk reasoning and prioritisation", [
        _crit("Every threat has an inherent rating", bool(thr) and all(r and r["inherent"] for r in rk), "Prioritisation needs a rating for each threat."),
        _crit("Likelihood and impact each have a rationale", bool(thr) and all(r and r["inherent"] and r["inherent"]["likelihood_rationale"] and r["inherent"]["impact_rationale"] for r in rk), "A bare number cannot be challenged."),
        _crit("Business context and evidence/uncertainty are recorded", bool(thr) and all(r and r["inherent"] and r["inherent"]["business_context"] and (r["inherent"]["evidence"] or r["inherent"]["uncertainty"]) for r in rk), "Context turns a number into a decision."),
        _crit("No rating is stale", not [r for r in ws["risks"] if r.get("stale")], "Ratings built on a changed DFD must be re-checked."),
    ] + ([_crit("Attack steps were validated before rating", all(not m.tree_analysis(ws, t["id"])["unassessed"] for t in thr if m.get_tree(ws, t["id"])), "Likelihood needs evidence about which steps are plausible here.")] if ws["attack_trees"] else []),
        ["Rationales are free text - reviewer should check consistency across threats."] if thr else [])

    dim("controls", "Control effectiveness and verification", [
        _crit("Every Medium-or-above threat has a proposed control", bool(thr) and all(m.controls_for(ws, t["id"]) for t, r in zip(thr, rk) if r and r["inherent"] and r["inherent"]["band"] != "Low") and bool(ws["controls"]), "A risk with no control is an implicit acceptance."),
        _crit("Controls state an objective and function", bool(ws["controls"]) and all(c["objective"] and c["function"] for c in ws["controls"]), "Objective says which trust assumption the control enforces."),
        _crit("Controls beyond 'proposed' have owners", bool(ws["controls"]) and all(c["owner"] for c in ws["controls"] if c["status"] != "proposed"), "Unowned controls do not get built."),
        _crit("Implemented controls have been verified or have a verification plan", bool(ws["controls"]) and all(c["status"] != "implemented" for c in ws["controls"]), "Implemented is not the same as effective."),
        _crit("No control failed verification without follow-up", not [c for c in ws["controls"] if c["status"] == "verification_failed"], "A failed verification means the risk is not reduced."),
    ] + ([_crit("Controls are linked to the attack steps they address", all(c.get("step_ids") for c in ws["controls"] if c["status"] != "rejected" and any(m.get_tree(ws, t) for t in c["threat_ids"])), "A control that cannot be tied to a step cannot be shown to cut a path.")] if ws["attack_trees"] else []),
        ["Whether a control actually addresses the failed trust assumption is a reviewer judgement."] if ws["controls"] else [])

    rs = [r for r in ws["risks"] if r.get("residual")]
    dim("residual", "Residual-risk justification and ownership", [
        _crit("Every threat has a residual assessment and a treatment", bool(thr) and all((r := m.get_risk(ws, t["id"])) and r.get("residual") and r.get("treatment") for t in thr), "Residual risk is what the organisation actually carries."),
        _crit("Reductions rely on verified controls", all(not (r["residual"]["score"] < r["inherent"]["score"]) or any(m.find(ws["controls"], c) and m.find(ws["controls"], c)["status"] == "verified" for c in r["residual"].get("basis_control_ids", [])) for r in rs), "Selected or implemented controls do not reduce risk until verified."),
        _crit("Every treatment decision has an accountable owner and justification", all(r.get("treatment") and r["treatment"]["owner"] and r["treatment"]["justification"] for r in rs if r.get("treatment")) and bool(rs), "Acceptance without an owner is neglect."),
        _crit("Open questions have owners and due dates", all(q["owner"] and q["due"] for q in ws["questions"] if q["status"] == "open") and bool(ws["questions"]), "Unowned questions never get answered."),
    ],
        ["Residual rationales are free text - reviewer should check they follow from the evidence."] if rs else [])

    rp = ws["review"]
    dim("review", "Review planning and change impact", [
        _crit("Owner, security reviewer and next review date are set", bool(rp["model_owner"] and rp["security_reviewer"] and m.parse_date(rp["next_review"])), "A model nobody owns decays."),
        _crit("Cadence and re-model triggers are defined", bool(rp["cadence"] and rp["full_triggers"] and rp["change_triggers"]), "Triggers keep the model current between reviews."),
        _crit("Approval and evidence requirements are defined", bool(rp["required_approval"] and rp["required_evidence"]), "Reviews need an agreed bar."),
        _crit("The re-modelling exercise was completed", ws["remodel"]["completed"], "Practising change impact is the point of Step 9."),
        _crit("Nothing is stale", not m.stale_items(ws), "Stale analysis must be revalidated before the model is called current."),
    ], [])
    return D


def what_the_rubric_cannot_judge():
    return ("Automatic checks verify structure, traceability, evidence and consistency. They cannot decide whether a threat is plausible, "
            "whether a mapping is the best fit or whether a rationale is sound. Items marked 'needs reviewer' are for an instructor or peer.")
