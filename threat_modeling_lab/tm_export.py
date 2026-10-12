"""Reports and machine-readable exports generated from the canonical workspace only.

Everything (JSON, CSV, Markdown, PDF) is rendered from the same workspace via build_model_export()
or build_report_blocks(). Unresolved decisions, stale records and failed verifications are never
omitted; missing mandatory data is listed under export_meta.completeness.omissions.
"""
import csv
import io
import json

import tm_assess as a
import tm_catalog
import tm_labs
import tm_model as m

EXPORT_SCHEMA = "threat-model-export/1"
REGISTER_COLUMNS = ["threat_id", "title", "stride", "targets", "target_names", "statement", "inherent_likelihood", "inherent_impact",
                    "inherent_score", "inherent_band", "priority", "urgency", "controls", "verified_controls", "failed_verification_controls",
                    "attack_mapping", "capec_mapping", "residual_likelihood", "residual_impact", "residual_score", "residual_band",
                    "residual_basis_controls", "remaining_attack_paths", "treatment", "risk_owner", "decision_date", "justification",
                    "acceptance_conditions", "escalation_to", "review_by", "open_questions", "attack_tree", "viable_attack_paths", "open_attack_paths", "stale", "row_status"]


def completeness(ws):
    prog = a.progress(ws)
    omissions = []
    for p in prog:
        for b in p["blockers"]:
            omissions.append({"step": p["step"], "step_title": p["title"], "ref": b.get("ref"), "issue": b["message"]})
    for i in a.integrity_issues(ws):
        if i["severity"] == "error":
            omissions.append({"step": None, "step_title": "integrity", "ref": i["ref"], "issue": i["message"]})
    return {"complete": not omissions, "omissions": omissions,
            "steps": [{"step": p["step"], "title": p["title"], "state": p["state"]} for p in prog]}


def _mapping_cell(ws, tid, fw):
    ms = [x for x in ws["mappings"] if x["threat_id"] == tid and x["framework"] == fw]
    if not ms:
        return "UNDECIDED"
    out = []
    for x in ms:
        out.append(f"{x['ref_id']} {x['name']} [{x['catalogue_status']}]" if x["outcome"] == "mapped" else "NO DEFENSIBLE MAPPING: " + x["rationale"])
    return " | ".join(out)


def risk_register_rows(ws):
    rows = []
    for t in sorted(ws["threats"], key=lambda t: t["id"]):
        r = m.get_risk(ws, t["id"]) or {}
        inh, res, tr = r.get("inherent") or {}, r.get("residual") or {}, r.get("treatment") or {}
        ctl = m.controls_for(ws, t["id"])
        failed = [c["id"] for c in ctl if c["status"] == "verification_failed"]
        problems = []
        if not inh:
            problems.append("inherent risk not assessed")
        if inh and not res:
            problems.append("residual not assessed")
        if res and not tr:
            problems.append("no treatment decision")
        if t.get("stale") or r.get("stale"):
            problems.append("STALE - revalidate")
        qs = [q["id"] for q in ws["questions"] if t["id"] in q["related"] and q["status"] == "open"]
        an = m.tree_analysis(ws, t["id"])
        rows.append({
            "threat_id": t["id"], "title": t["title"], "stride": m.STRIDE.get(t["stride"], ""), "targets": ";".join(t["targets"]),
            "target_names": "; ".join(m.target_name(ws, x) for x in t["targets"]), "statement": m.statement_text(ws, t),
            "inherent_likelihood": inh.get("likelihood", ""), "inherent_impact": inh.get("impact", ""), "inherent_score": inh.get("score", ""),
            "inherent_band": inh.get("band", ""), "priority": inh.get("priority", ""), "urgency": inh.get("urgency", ""),
            "controls": ";".join(f"{c['id']}:{c['status']}" for c in ctl), "verified_controls": ";".join(c["id"] for c in ctl if c["status"] == "verified"),
            "failed_verification_controls": ";".join(failed), "attack_mapping": _mapping_cell(ws, t["id"], "ATT&CK"),
            "capec_mapping": _mapping_cell(ws, t["id"], "CAPEC"), "residual_likelihood": res.get("likelihood", ""),
            "residual_impact": res.get("impact", ""), "residual_score": res.get("score", ""), "residual_band": res.get("band", ""),
            "residual_basis_controls": ";".join(res.get("basis_control_ids", [])), "remaining_attack_paths": res.get("remaining_attack_paths", ""),
            "treatment": tr.get("decision", ""), "risk_owner": tr.get("owner", ""), "decision_date": tr.get("decision_date", ""),
            "justification": tr.get("justification", ""), "acceptance_conditions": tr.get("acceptance_conditions", ""),
            "escalation_to": tr.get("escalation_to", ""), "review_by": tr.get("review_by", ""), "open_questions": ";".join(qs),
            "attack_tree": (f"{an['assessed']}/{an['leaves']} steps validated" if an["exists"] else "none"),
            "viable_attack_paths": len(an["viable"]) if an["exists"] else "", "open_attack_paths": len(an["remaining"]) if an["exists"] else "",
            "stale": "yes" if (t.get("stale") or r.get("stale")) else "no", "row_status": "complete" if not problems else "; ".join(problems)})
    rows.sort(key=lambda x: (-(x["inherent_score"] if x["inherent_score"] != "" else -1), x["threat_id"]))
    return rows


def to_csv(rows, columns=None):
    columns = columns or (list(rows[0].keys()) if rows else REGISTER_COLUMNS)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({k: ("" if r.get(k) is None else r.get(k)) for k in columns})
    return buf.getvalue()


def risk_register_csv(ws):
    return to_csv(risk_register_rows(ws), REGISTER_COLUMNS)


def build_model_export(ws):
    comp = completeness(ws)
    crossing = m.crossings(ws)
    threats = [{**t, "statement": m.statement_text(ws, t), "generated_statement": m.build_statement(ws, t),
                "target_names": [m.target_name(ws, x) for x in t["targets"]],
                "departs_from_standard_stride": m.departs_from_standard(ws, t)} for t in ws["threats"]]
    return {
        "export_meta": {"schema": EXPORT_SCHEMA, "generated_at": m.now(), "lab_id": ws["lab_id"], "lab_name": tm_labs.lab_name(ws["lab_id"]),
                        "learner": ws["learner"], "workspace_version": ws["workspace_version"], "completeness": comp,
                        "catalogues": tm_catalog.catalogue_meta(), "risk_model": {k: (v if k != "bands" else [list(b) for b in v]) for k, v in m.RISK_MODEL.items()},
                        "statement_of_limits": a.what_the_rubric_cannot_judge()},
        "scope": {k: v for k, v in ws["scope"].items()},
        "dfd": {"version": ws["dfd"]["version"], "elements": ws["dfd"]["elements"], "flows": ws["dfd"]["flows"], "boundaries": ws["dfd"]["boundaries"],
                "crossings": crossing, "assumptions": ws["dfd"]["assumptions"], "no_boundary_rationale": ws["dfd"]["no_boundary_rationale"]},
        "boundary_reviews": ws["boundary_reviews"], "crossing_reviews": ws["crossing_reviews"],
        "stride": {"standard_applicability": m.APPLICABILITY, "cells": [{"target": k.split(":")[0], "stride": k.split(":")[1], **v} for k, v in ws["stride_cells"].items()],
                   "coverage": {k: v for k, v in m.stride_coverage(ws).items() if k != "open"}, "open_cells": [list(c) for c in m.stride_coverage(ws)["open"]]},
        "attack_trees": {tid: {"template_id": tr["template_id"], "rev": tr["rev"], "nodes": tr["nodes"], "stale": tr.get("stale", []),
                               "analysis": {k: v for k, v in m.tree_analysis(ws, tid).items()}} for tid, tr in ws["attack_trees"].items()},
        "assistance": {"mode": ws["settings"]["assist_mode"], "competence": ws["competence"],
                       "threats_started_from_library": [t["id"] for t in ws["threats"] if t.get("library_ref")]},
        "threats": threats, "mappings": ws["mappings"], "risks": ws["risks"], "controls": ws["controls"], "questions": ws["questions"],
        "review_plan": ws["review"], "remodel_exercise": ws["remodel"],
        "versions": [{k: v for k, v in x.items() if k != "snapshot"} for x in ws["versions"]], "change_log": ws["changelog"],
        "discover_first": {"enabled": ws["settings"]["discover_first"], "hypotheses": ws["hypotheses"], "reveals": ws["reveals"]},
        "unresolved": {"stale_records": m.stale_items(ws), "open_questions": [q for q in ws["questions"] if q["status"] == "open"],
                       "controls_not_verified": [c["id"] for c in ws["controls"] if c["status"] in ("proposed", "planned", "implemented")],
                       "open_attack_paths": [{"threat": tid, "paths": [" + ".join(p["steps"]) for p in m.tree_analysis(ws, tid)["remaining"]]} for tid in ws["attack_trees"] if m.tree_analysis(ws, tid)["remaining"]],
                       "failed_verification": [{"id": c["id"], "evidence": c["verification"]["evidence"]} for c in ws["controls"] if c["status"] == "verification_failed"],
                       "outstanding_actions": a.outstanding_actions(ws)},
        "validation": {"integrity": a.integrity_issues(ws), "rubric": a.rubric(ws)},
    }


def model_json(ws):
    return json.dumps(build_model_export(ws), indent=2, ensure_ascii=False, default=str)


def check_export_consistency(ws, export=None):
    """Return a list of problems; empty means the exports agree with each other and the workspace."""
    export = export or build_model_export(ws)
    rows = risk_register_rows(ws)
    probs = []
    ids = {x["id"] for k in ("threats", "mappings", "risks", "controls", "questions") for x in export[k]}
    ids |= {x["id"] for k in ("elements", "flows", "boundaries") for x in export["dfd"][k]}
    if len(rows) != len(export["threats"]):
        probs.append("risk register row count differs from threat count")
    if {r["threat_id"] for r in rows} != {t["id"] for t in export["threats"]}:
        probs.append("risk register threat IDs differ from model threat IDs")
    for r in rows:
        for cid in [c.split(":")[0] for c in r["controls"].split(";") if c]:
            if cid not in ids:
                probs.append(f"register {r['threat_id']} references unknown control {cid}")
        for tid in [x for x in r["targets"].split(";") if x]:
            if tid not in ids:
                probs.append(f"register {r['threat_id']} references unknown target {tid}")
    for t in export["threats"]:
        for x in t["targets"]:
            if x not in ids:
                probs.append(f"threat {t['id']} references unknown {x}")
    for mp in export["mappings"]:
        if mp["threat_id"] not in ids:
            probs.append(f"mapping {mp['id']} references unknown threat")
    for c in export["controls"]:
        if c["status"] == "verified" and not (c.get("verification") or {}).get("evidence"):
            probs.append(f"control {c['id']} verified without evidence")
    steps = {n["id"] for tr in export["attack_trees"].values() for n in tr["nodes"]}
    for c in export["controls"]:
        for sid in c.get("step_ids", []):
            if sid not in steps:
                probs.append(f"control {c['id']} references unknown attack step {sid}")
    for mp in export["mappings"]:
        if mp.get("step_id") and mp["step_id"] not in steps:
            probs.append(f"mapping {mp['id']} references unknown attack step {mp['step_id']}")
    for tid in export["attack_trees"]:
        if tid not in {t["id"] for t in export["threats"]}:
            probs.append(f"attack tree for unknown threat {tid}")
    claimed = export["export_meta"]["completeness"]
    if claimed["complete"] and export["unresolved"]["stale_records"]:
        probs.append("export marked complete but stale records exist")
    if not claimed["complete"] and not claimed["omissions"]:
        probs.append("export marked incomplete without listing omissions")
    for r in rows:
        if r["row_status"] == "complete" and (r["inherent_band"] == "" or r["residual_band"] == "" or r["treatment"] == ""):
            probs.append(f"register {r['threat_id']} marked complete with missing fields")
    return probs


# ── Report blocks (rendered to Markdown and PDF) ───────────────────────────────────────
def _tbl(header, rows):
    return ("table", [header] + [[("" if c is None else str(c)) for c in r] for r in rows])


def build_report_blocks(ws):
    exp = build_model_export(ws)
    comp = exp["export_meta"]["completeness"]
    sc, B = ws["scope"], []
    B.append(("h1", f"Threat model report - {tm_labs.lab_name(ws['lab_id'])}"))
    B.append(("p", f"Learner/workspace: {ws['learner']}  |  Generated: {exp['export_meta']['generated_at']}  |  Scope v{sc['version']}  |  DFD v{ws['dfd']['version']}"))
    if comp["complete"]:
        B.append(("p", "STATUS: all nine steps meet their completion gates."))
    else:
        B.append(("p", f"STATUS: INCOMPLETE - {len(comp['omissions'])} open item(s). This report does not hide them."))
        B.append(("bullets", [f"Step {o['step']} - {o['issue']}" if o["step"] else o["issue"] for o in comp["omissions"][:40]]))
    B.append(("h2", "1. Scope, goals, assumptions and exclusions"))
    B.append(("p", f"Purpose: {sc['purpose'] or '(not recorded)'}"))
    B.append(("p", f"Business context: {sc['business_context'] or '(not recorded)'}  |  Data sensitivity: {sc['data_sensitivity'] or '(not recorded)'}"))
    B.append(("bullets", ["In scope: " + (", ".join(sc["in_scope"]) or "(none)")] + [f"Out of scope ({x['id']}): {x['text']} - {x['reason'] or 'no reason recorded'}" for x in sc["exclusions"]]
              + ["Objective: " + o for o in sc["objectives"]] + ["Regulatory: " + r for r in sc["regulatory"]] + ["Success criterion: " + s for s in sc["success_criteria"]]))
    B.append(_tbl(["ID", "Asset", "Sensitivity", "Note"], [[x["id"], x["name"], x["sensitivity"], x["note"]] for x in sc["assets"]]))
    B.append(_tbl(["ID", "Confirmed fact", "Source"], [[x["id"], x["text"], x["source"]] for x in sc["facts"]]))
    B.append(_tbl(["ID", "Assumption", "Status", "Validation owner"], [[x["id"], x["text"], x["status"], x["validation_owner"]] for x in sc["assumptions"]]))
    B.append(_tbl(["ID", "Stakeholder", "Role", "Accountable"], [[x["id"], x["name"], x["role"], "yes" if x["accountable"] else ""] for x in sc["stakeholders"]]))
    B.append(("h2", "2. Data-flow diagram and trust boundaries"))
    B.append(_tbl(["ID", "Type", "Name", "Domain", "Description"], [[e["id"], m.KIND_LABEL[e["type"]], e["name"] + (" (assumed)" if e["assumed"] else ""), e["security_domain"], e["description"]] for e in m.elements(ws)]))
    B.append(_tbl(["ID", "From", "To", "Data", "Protocol", "Class", "Auth"], [[f["id"], f["source"], f["destination"], f["data"], f["protocol"], f["classification"], f["authenticated"]] for f in m.flows(ws)]))
    B.append(_tbl(["ID", "Boundary", "Members", "Description"], [[b["id"], b["name"], ", ".join(b["members"]), b["description"]] for b in m.boundaries(ws)]))
    if ws["dfd"]["assumptions"]:
        B.append(("bullets", ["Architecture assumption: " + x for x in ws["dfd"]["assumptions"]]))
    B.append(("h2", "3. STRIDE analysis and threat statements"))
    B.append(("p", "STRIDE-per-element applicability prompts are prompts, not proof that a threat exists."))
    B.append(_tbl(["ID", "STRIDE", "Targets", "Statement", "Confidence", "Stale"], [[t["id"], m.STRIDE.get(t["stride"], ""), ", ".join(t["targets"]), t["statement"], t["confidence"], "yes" if t.get("stale") else ""] for t in exp["threats"]]))
    nd = [(k, v) for k, v in ws["stride_cells"].items()]
    if nd:
        B.append(_tbl(["Target:STRIDE", "Disposition", "Rationale"], [[k, v["disposition"], v["rationale"]] for k, v in nd]))
    for tid, tr in ws["attack_trees"].items():
        an = m.tree_analysis(ws, tid)
        B.append(("h3", f"Attack tree {tid}" + (f" (template {tr['template_id']})" if tr["template_id"] else " (own design)")))
        B.append(("p", f"{an['assessed']}/{an['leaves']} leaf steps validated; {len(an['viable'])} viable path(s); easiest path effort "
                       f"{an['easiest']['cost'] if an['easiest'] else 'n/a'}; {len(an['cut'])} cut by verified controls; {len(an['remaining'])} remaining."))
        ctl_of = {}
        for c in ws["controls"]:
            for sid in c.get("step_ids", []):
                ctl_of.setdefault(sid, []).append(f"{c['id']}:{c['status']}")
        map_of = {}
        for mp in ws["mappings"]:
            if mp.get("step_id") and mp["outcome"] == "mapped":
                map_of.setdefault(mp["step_id"], []).append(mp["ref_id"])
        B.append(_tbl(["Step", "Type", "Attack step", "Status", "Effort", "Rationale", "Mappings", "Controls"],
                      [[n["id"], n["logic"] if n["type"] != "leaf" else "leaf", ("  " * _depth(tr, n)) + n["label"], n["status"] if n["type"] == "leaf" else "", n["difficulty"] or "",
                        n["rationale"], ", ".join(map_of.get(n["id"], [])), ", ".join(ctl_of.get(n["id"], []))] for n in tr["nodes"]]))
    B.append(("h2", "4. Trust-boundary validation"))
    for inv in m.boundary_inventory(ws):
        b = inv["boundary"]
        rv = inv["review"] or {}
        B.append(("h3", f"{b['id']} {b['name']} - {'validated' if inv['validated'] else 'NOT validated'}"))
        B.append(("bullets", [f"Why it exists: {rv.get('why_exists', '(missing)')}", f"Trust change: {rv.get('trust_change', '(missing)')}",
                              f"Properties: {', '.join(rv.get('properties', [])) or '(missing)'}", f"Controls required: {rv.get('controls_required', '(missing)')}",
                              f"Evidence needed: {rv.get('evidence_needed', '(missing)')}"]
                  + [f"Crossing {c['flow_id']}: " + (f"{c['review']['assumption']} / control: {c['review']['control']} / evidence: {c['review']['evidence']}" if c["review"] else "(not documented)") for c in inv["crossings"]]))
    B.append(("h2", "5. ATT&CK and CAPEC mappings"))
    B.append(("p", "Catalogue status: " + "; ".join(f"{fw}: {v['status']} ({v['declared_version']})" for fw, v in exp["export_meta"]["catalogues"].items())))
    B.append(_tbl(["ID", "Threat", "Framework", "Outcome", "Ref", "Name", "Catalogue", "Rationale", "Confidence"],
                  [[x["id"], x["threat_id"], x["framework"], x["outcome"], x["ref_id"], x["name"], x["catalogue_status"], x["rationale"], x["confidence"]] for x in ws["mappings"]]))
    B.append(("h2", "6. Inherent risk register"))
    rows = risk_register_rows(ws)
    B.append(_tbl(["Threat", "Title", "L", "I", "Score", "Band", "Priority", "Row status"], [[r["threat_id"], r["title"], r["inherent_likelihood"], r["inherent_impact"], r["inherent_score"], r["inherent_band"], r["priority"], r["row_status"]] for r in rows]))
    B.append(("h2", "7. Control plan"))
    B.append(_tbl(["ID", "Threats", "Attack steps", "Title", "Function", "Owner", "Status", "Verification", "Limitations"],
                  [[c["id"], ",".join(c["threat_ids"]), ",".join(c.get("step_ids", [])), c["title"], c["function"], c["owner"], c["status"],
                    (f"{c['verification']['result']} {c['verification']['date']}: {c['verification']['evidence']}" if c.get("verification") else "none"), c["limitations"]] for c in ws["controls"]]))
    B.append(("h2", "8. Residual risk, decisions and open questions"))
    B.append(_tbl(["Threat", "Residual", "Band", "Treatment", "Owner", "Date", "Justification", "Escalation"],
                  [[r["threat_id"], r["residual_score"], r["residual_band"], r["treatment"], r["risk_owner"], r["decision_date"], r["justification"], r["escalation_to"]] for r in rows]))
    for tid, tr in ws["attack_trees"].items():
        an = m.tree_analysis(ws, tid)
        if an["exists"] and an["viable"]:
            B.append(("p", f"{tid} attack paths after verified controls - cut: {m.describe_paths(ws, tid, an['cut']) or 'none'}. Remaining: {m.describe_paths(ws, tid, an['remaining']) or 'none'}."))
    B.append(_tbl(["ID", "Question", "Owner", "Due", "Status", "Related"], [[q["id"], q["text"], q["owner"], q["due"], q["status"], ",".join(q["related"])] for q in ws["questions"]]))
    B.append(("h2", "9. Review plan and version history"))
    rp = ws["review"]
    B.append(("bullets", [f"Model owner: {rp['model_owner'] or '(missing)'}", f"Security reviewer: {rp['security_reviewer'] or '(missing)'}", f"Next review: {rp['next_review'] or '(missing)'}",
                          f"Cadence: {rp['cadence'] or '(missing)'}", "Full re-model triggers: " + ("; ".join(rp["full_triggers"]) or "(missing)"),
                          "Change triggers: " + ("; ".join(rp["change_triggers"]) or "(missing)"), f"Required approval: {rp['required_approval'] or '(missing)'}",
                          f"Required evidence: {rp['required_evidence'] or '(missing)'}", f"Re-modelling exercise: {'completed ' + ws['remodel']['completed_on'] if ws['remodel']['completed'] else 'NOT completed'}"]))
    B.append(_tbl(["Kind", "Version", "At", "Author", "Note"], [[v["kind"], v["version"], v["at"], v["author"], v["note"]] for v in ws["versions"]]))
    B.append(("h2", "Outstanding actions"))
    B.append(_tbl(["Type", "Ref", "Owner", "Action"], [[x["type"], x["ref"], x.get("owner", ""), x["action"]] for x in a.outstanding_actions(ws)]))
    B.append(("h2", "Limits of automatic assessment"))
    B.append(("p", a.what_the_rubric_cannot_judge()))
    return B


def _depth(tr, n):
    d, cur = 0, n
    while cur["parent"]:
        cur = next(x for x in tr["nodes"] if x["id"] == cur["parent"])
        d += 1
    return d


def report_markdown(ws):
    out = []
    for kind, c in build_report_blocks(ws):
        if kind == "h1":
            out.append(f"# {c}\n")
        elif kind == "h2":
            out.append(f"\n## {c}\n")
        elif kind == "h3":
            out.append(f"\n### {c}\n")
        elif kind == "p":
            out.append(c + "\n")
        elif kind == "bullets":
            out.append("\n".join("- " + x for x in c) + "\n")
        elif kind == "table":
            if len(c) > 1:
                esc = lambda s: str(s).replace("|", "\\|").replace("\n", " ")
                out.append("| " + " | ".join(c[0]) + " |\n|" + "---|" * len(c[0]) + "\n" + "\n".join("| " + " | ".join(esc(x) for x in r) + " |" for r in c[1:]) + "\n")
    return "\n".join(out)


def report_pdf(ws):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import landscape, letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from xml.sax.saxutils import escape
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(letter), leftMargin=30, rightMargin=30, topMargin=30, bottomMargin=30,
                            title="Threat model report")
    ss = getSampleStyleSheet()
    cell = ParagraphStyle("cell", parent=ss["BodyText"], fontSize=7, leading=8.5)
    head = ParagraphStyle("head", parent=cell, textColor=colors.white, fontName="Helvetica-Bold")
    story = []
    for kind, c in build_report_blocks(ws):
        if kind in ("h1", "h2", "h3"):
            story += [Spacer(1, 6), Paragraph(escape(c), ss[{"h1": "Title", "h2": "Heading2", "h3": "Heading3"}[kind]])]
        elif kind == "p":
            story.append(Paragraph(escape(c), ss["BodyText"]))
        elif kind == "bullets":
            story += [Paragraph("&bull; " + escape(x), ss["BodyText"]) for x in c]
        elif kind == "table" and len(c) > 1:
            data = [[Paragraph(escape(h), head) for h in c[0]]] + [[Paragraph(escape(x), cell) for x in r] for r in c[1:]]
            w = (landscape(letter)[0] - 60) / len(c[0])
            t = Table(data, colWidths=[w] * len(c[0]), repeatRows=1)
            t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F6F66")), ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                                   ("VALIGN", (0, 0), (-1, -1), "TOP")]))
            story += [t, Spacer(1, 4)]
    doc.build(story)
    return buf.getvalue()


def dfd_dot(ws, highlight=None):
    """Graphviz DOT source for the learner's own DFD (rendered client-side by st.graphviz_chart)."""
    esc = lambda s: str(s).replace('"', "'")
    shape = {"external_entity": "box", "process": "ellipse", "datastore": "cylinder"}
    lines = ["digraph DFD {", "rankdir=LR; compound=true; fontname=Helvetica; node [fontname=Helvetica,fontsize=11]; edge [fontname=Helvetica,fontsize=9];"]
    inside = set()
    for b in m.boundaries(ws):
        lines.append(f'subgraph "cluster_{b["id"]}" {{ label="{esc(b["id"])} {esc(b["name"])}"; style=dashed; color="#B0413A";')
        for x in b["members"]:
            e = m.find(m.elements(ws), x)
            if e:
                lines.append(f'"{x}" [label="{esc(e["id"])}\\n{esc(e["name"])}", shape={shape[e["type"]]}];')
                inside.add(x)
        lines.append("}")
    for e in m.elements(ws):
        if e["id"] not in inside:
            lines.append(f'"{e["id"]}" [label="{esc(e["id"])}\\n{esc(e["name"])}", shape={shape[e["type"]]}];')
    cross = {c["flow_id"] for c in m.crossings(ws)}
    for f in m.flows(ws):
        col = "#B0413A" if f["id"] in cross else "#444444"
        both = ', dir=both' if f["direction"] == "bidirectional" else ""
        lines.append(f'"{f["source"]}" -> "{f["destination"]}" [label="{esc(f["id"])} {esc(f["data"])}\\n{esc(f["protocol"])}", color="{col}"{both}];')
    lines.append("}")
    return "\n".join(lines)


def tree_dot(ws, threat_id):
    """Graphviz DOT for one threat's attack tree. Colour = learner's validation; shape = AND/OR logic."""
    tr = ws["attack_trees"].get(threat_id)
    if not tr:
        return ""
    esc = lambda s: str(s).replace('"', "'")
    wrap = lambda s: "\\n".join([s[i:i + 28] for i in range(0, len(s), 28)][:4])
    out = ["digraph T { rankdir=TB; node [fontname=Helvetica,fontsize=10,style=filled,fillcolor=white];"]
    for n in tr["nodes"]:
        if n["type"] == "leaf":
            fill = {"plausible": "#F8D7D3", "implausible": "#E3E3E3", "unassessed": "#FFFFFF"}[n["status"]]
            extra = f"\\neffort {n['difficulty']}" if n["difficulty"] else ""
            out.append(f'"{n["id"]}" [label="{n["id"]}\\n{esc(wrap(n["label"]))}{extra}", shape=box, fillcolor="{fill}"];')
        else:
            shape = {"goal": "doubleoctagon", "or": "diamond", "and": "hexagon"}[n["type"] if n["type"] != "goal" else "goal"]
            tag = n["logic"].upper()
            out.append(f'"{n["id"]}" [label="{n["id"]} {tag}\\n{esc(wrap(n["label"]))}", shape={shape}, fillcolor="#E6F0EE"];')
        if n["parent"]:
            out.append(f'"{n["parent"]}" -> "{n["id"]}";')
    out.append("}")
    return "\n".join(out)
