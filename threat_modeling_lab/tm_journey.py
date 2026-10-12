"""The learner's baseline: where am I, what is done, what should I do NEXT (Streamlit-free).

next_actions() is derived from the SAME completion gates the rest of the app uses, so the prompt can
never disagree with what the gates will accept. It is also what the journey tests follow.
"""
import tm_assess as a
import tm_labs
import tm_library
import tm_model as m

PHASES = [
    ("Understand", "Agree what you are modelling", [1, 2]),
    ("Analyse", "Find and describe the threats", [3, 4, 5]),
    ("Decide", "Rate, control and decide", [6, 7, 8]),
    ("Sustain", "Keep it current and deliver", [9]),
]
STEP_ARTEFACT = {1: "Scope statement (versioned)", 2: "Data-flow diagram (versioned)", 3: "Threat register with attack trees", 4: "Boundary inventory",
                 5: "ATT&CK / CAPEC mappings", 6: "Prioritised inherent-risk register", 7: "Control plan with verification evidence",
                 8: "Residual-risk register and open questions", 9: "Review plan, report and exports"}
STEP_WHY = {
    1: "Everything later is judged against this scope.", 2: "Every threat points at an ID in this diagram.",
    3: "Threats are the unit that gets rated, controlled and reported.", 4: "Trust changes at boundaries; reviewers ask for the evidence.",
    5: "Mappings link your threat to what defenders already know.", 6: "Prioritisation decides where limited effort goes.",
    7: "Only verified controls can justify lower risk.", 8: "Decision-makers sign off residual risk, not intentions.",
    9: "Without owners and triggers the model decays."}

# code -> (imperative headline, where to do it). Falls back to the gate's own message.
PROMPTS = {
    "scope.purpose": "Write what the system is for and why it matters", "scope.in": "List what is in scope", "scope.out": "Record what is out of scope, and why",
    "scope.obj": "Add a security objective", "scope.assets": "Name the assets that matter", "scope.stake": "Name an accountable reviewer",
    "scope.facts": "Record the facts you can rely on", "scope.assump": "Record what you are assuming", "scope.success": "Say what 'done' looks like",
    "scope.data": "Describe data sensitivity or regulation", "scope.version": "Commit scope version 1",
    "dfd.empty": "Add the first elements of the diagram", "dfd.no_process": "Add at least one process", "dfd.no_boundary": "Draw a trust boundary (or say why there is none)",
    "dfd.version": "Commit DFD version 1", "flow.incomplete": "Complete the flow details", "element.disconnected": "Connect the element with a flow",
    "stride.unconsidered": "Work through the STRIDE prompts", "stride.stale": "Re-check a STRIDE decision after a model change", "threat.invalid": "Fix a threat record", "tree.missing": "Build an attack tree for a threat",
    "tree.structure": "Fix the attack tree", "tree.stale": "Revalidate the attack tree", "threat.stale": "Revalidate the threat",
    "tb.unreviewed": "Justify a trust boundary", "tb.crossing": "Document a boundary crossing", "map.undecided": "Decide on ATT&CK / CAPEC for a threat",
    "risk.unrated": "Rate a threat's inherent risk", "risk.steps": "Validate the attack steps", "ctl.none": "Propose a control", "ctl.path": "Link a control to the easiest attack path",
    "ctl.owner": "Give the control an owner", "res.missing": "Assess residual risk", "res.treatment": "Record a treatment decision", "q.owner": "Give the open question an owner and due date",
    "q.none": "Record what you still do not know", "rev.field": "Complete the review plan", "rev.remodel": "Do the re-modelling exercise", "rev.stale": "Revalidate the stale record",
}


def _hint(ws, code):
    lvl_t, lvl_tr = a.assist_level(ws, "threats"), a.assist_level(ws, "trees")
    if code == "stride.unconsidered":
        return ("Open 'Suggestions' for an element to see library examples that fit it." if lvl_t == "full" else
                "For each prompt either write a threat or say why it does not apply." if lvl_t == "reduced" else "")
    if code == "tree.missing":
        return ("Start from a suggested template, then edit it to your system." if lvl_tr == "full" else
                "Sketch the attack path first; templates are offered for comparison." if lvl_tr == "reduced" else "")
    if code == "risk.steps":
        return "Mark each step plausible or implausible using facts about THIS system; the cheapest viable path informs likelihood."
    if code == "ctl.path":
        return "Open the control and tick the attack steps it would stop."
    return ""


def next_actions(ws, limit=3):
    """Ordered list of concrete next actions (first incomplete step in canonical order)."""
    for iss in a.integrity_issues(ws):
        if iss["severity"] == "error":
            return [{"step": 9, "code": "integrity", "headline": "Repair a data problem", "detail": iss["message"], "why": "Exports cannot be trusted until this is fixed.", "hint": "", "ref": iss["ref"]}]
    for p in a.progress(ws):
        if p["state"] == "complete":
            continue
        out = []
        for b in p["blockers"][:limit]:
            out.append({"step": p["step"], "code": b["code"], "headline": PROMPTS.get(b["code"], "Resolve this item"), "detail": b["message"],
                        "why": STEP_WHY[p["step"]], "hint": _hint(ws, b["code"]), "ref": b.get("ref")})
        if not out:      # started=False with no blockers cannot happen, but never return an empty prompt
            out.append({"step": p["step"], "code": "start", "headline": f"Start Step {p['step']}", "detail": a.STEP_TITLES[p["step"]], "why": STEP_WHY[p["step"]], "hint": "", "ref": None})
        return out
    return [{"step": 9, "code": "done", "headline": "All nine steps pass their completion checks", "detail": "Review the assessment, download your exports, then move to the next lab.",
             "why": "The model is complete and consistent.", "hint": "", "ref": None}]


def _step_summary(ws, n):
    thr = ws["threats"]
    if n == 1:
        sc = ws["scope"]
        return f"{len(sc['facts'])} facts, {len(sc['assumptions'])} assumptions, v{sc['version']}"
    if n == 2:
        return f"{len(m.elements(ws))} elements, {len(m.flows(ws))} flows, {len(m.boundaries(ws))} boundaries, v{ws['dfd']['version']}"
    if n == 3:
        cov = m.stride_coverage(ws)
        return f"{len(thr)} threats, {len(ws['attack_trees'])} attack trees, {cov['total'] - len(cov['open'])}/{cov['total']} prompts considered"
    if n == 4:
        inv = m.boundary_inventory(ws)
        return f"{sum(1 for i in inv if i['validated'])}/{len(inv)} boundaries validated"
    if n == 5:
        return f"{sum(1 for t in thr if all(d != 'undecided' for d in m.mapping_decisions(ws, t['id']).values()))}/{len(thr)} threats decided"
    if n == 6:
        return f"{len([r for r in ws['risks'] if r['inherent']])}/{len(thr)} rated"
    if n == 7:
        c = m.control_state_counts(ws)
        return f"{len(ws['controls'])} controls, {c['verified']} verified"
    if n == 8:
        dec = len([r for r in ws["risks"] if r.get("treatment")])
        return f"{dec}/{len(thr)} decisions, {len([q for q in ws['questions'] if q['status'] == 'open'])} open questions"
    return "plan complete" if not a.gate_review(ws)[0] else ("exercise done" if ws["remodel"]["completed"] else "not started")


def journey(ws):
    prog = {p["step"]: p for p in a.progress(ws)}
    phases = []
    for name, tagline, steps in PHASES:
        phases.append({"name": name, "tagline": tagline, "steps": [
            {"step": n, "title": a.STEP_TITLES[n], "state": prog[n]["state"], "artefact": STEP_ARTEFACT[n], "summary": _step_summary(ws, n),
             "blockers": len(prog[n]["blockers"]), "warnings": len(prog[n]["warnings"])} for n in steps]})
    prof = tm_labs.profile(ws["lab_id"])
    return {"lab": ws["lab_id"], "role": prof["role"], "purpose": prof["purpose"], "phases": phases, "next": next_actions(ws),
            "complete": all(p["state"] == "complete" for p in prog.values()),
            "assist": {"mode": ws["settings"]["assist_mode"], "locked": prof["assist_locked"],
                       "levels": {k: a.assist_level(ws, k) for k in a.SKILL_LABEL},
                       "competence": ws["competence"]},
            "expectation_note": prof["expectations"]}


def register_rows(ws):
    """The single persistent threat register: one row per threat, growing columns as the journey progresses."""
    rows = []
    for t in sorted(ws["threats"], key=lambda t: t["id"]):
        r = m.get_risk(ws, t["id"]) or {}
        inh, res, tr = r.get("inherent"), r.get("residual"), r.get("treatment")
        an = m.tree_analysis(ws, t["id"])
        ctl = m.controls_for(ws, t["id"])
        dec = m.mapping_decisions(ws, t["id"])
        flags = []
        if t.get("stale") or r.get("stale") or any(c.get("stale") for c in ctl) or (m.get_tree(ws, t["id"]) or {}).get("stale"):
            flags.append("stale")
        if t.get("orphaned_targets"):
            flags.append("orphaned")
        if t.get("library_ref"):
            flags.append("from example")
        rows.append({
            "ID": t["id"], "STRIDE": m.STRIDE[t["stride"]], "Where": "; ".join(m.target_name(ws, x) for x in t["targets"]),
            "Threat": (m.statement_text(ws, t)[:140] + ("..." if len(m.statement_text(ws, t)) > 140 else "")),
            "Attack tree": (f"{an['assessed']}/{an['leaves']} steps validated, {len(an['viable'])} viable path(s)" if an["exists"] else "-"),
            "ATT&CK": dec["ATT&CK"].replace("_", " "), "CAPEC": dec["CAPEC"].replace("_", " "),
            "Inherent": f"{inh['band']} ({inh['score']})" if inh else "-",
            "Controls": (f"{len(ctl)} ({sum(1 for c in ctl if c['status'] == 'verified')} verified)" if ctl else "-"),
            "Residual": f"{res['band']} ({res['score']})" if res else "-",
            "Decision": (f"{tr['decision']} - {tr['owner']}" if tr else "-"), "Flags": ", ".join(flags)})
    return rows
