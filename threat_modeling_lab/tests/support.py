"""Helpers that complete a lab THROUGH THE SAME PUBLIC API the UI uses (no private shortcuts)."""
import os
import sys
from datetime import date, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import tm_assess as a  # noqa: E402
import tm_labs  # noqa: E402
import tm_library  # noqa: E402
import tm_model as m  # noqa: E402

FUTURE = (date.today() + timedelta(days=45)).isoformat()


def build_dfd(ws, lab):
    ref = tm_labs.reference_model(lab)
    for e in ref["elements"]:
        m.add_element(ws, e["type"], e["name"], e["description"] or "described by the lab brief", e["security_domain"],
                      justification="Needed by the business process in the brief" if e["type"] == "external_entity" else "")
    for f in ref["flows"]:
        s, d = m.element_by_name(ws, f["source"]), m.element_by_name(ws, f["destination"])
        m.add_flow(ws, s["id"], d["id"], f["data"], f["protocol"], classification="Confidential", authenticated="Caller identity checked at the receiving component")
    for b in ref["boundaries"]:
        m.add_boundary(ws, b["name"], b["description"], [m.element_by_name(ws, x)["id"] for x in b["members"]])
    if lab == "4":  # an inferred element the brief did not draw
        m.add_element(ws, "datastore", "Audit Log Store", "Inferred: PHI access must be auditable", assumed=True)
        m.add_flow(ws, m.element_by_name(ws, "Device Data Svc")["id"], m.element_by_name(ws, "Audit Log Store")["id"], "Audit events", "HTTPS", classification="Restricted",
                   authenticated="Service identity")
    m.set_dfd_notes(ws, assumptions=["Cloud services are managed by the operator; the home network is untrusted"])


def build_scope(ws, lab):
    sc = tm_labs.scenario(lab)
    m.set_scope_text(ws, "purpose", f"Threat model of {sc['title']}: {sc['description']}, used to decide security work before the next release.")
    m.set_scope_text(ws, "business_context", sc["business_context"])
    m.set_scope_text(ws, "data_sensitivity", "Contains regulated personal data; integrity of records matters as much as confidentiality.")
    for c in sc["components"]:
        m.add_scope_string(ws, "in_scope", c["name"])
    for o in sc["objectives"] if not ws["scope"]["objectives"] else []:
        m.add_scope_string(ws, "objectives", o)
    m.add_scope_string(ws, "success_criteria", "All High and Critical threats have a verified control or an escalated decision")
    for r in sc["compliance"] if not ws["scope"]["regulatory"] else []:
        m.add_scope_string(ws, "regulatory", r)
    for asset in sc["assets"]:
        if not any(m.norm(x["name"]) == m.norm(asset) for x in ws["scope"]["assets"]):
            m.add_scope_item(ws, "assets", {"name": asset, "sensitivity": "High", "note": ""})
    m.add_scope_item(ws, "stakeholders", {"name": "Product owner", "role": "Accountable for the model", "accountable": True})
    m.add_scope_item(ws, "assumptions", {"text": "Managed cloud services are patched by the provider", "status": "needs validation",
                                         "validation_owner": "Platform lead", "validation_method": "Review provider attestation"})
    m.add_scope_item(ws, "exclusions", {"text": "Corporate IT network", "reason": "Covered by a separate review"})
    m.commit_scope(ws, "Initial scope", "tester")


def build_threats(ws, lab, n=3):
    """Create learner threats on real DFD IDs. Statements reference the system so heuristics accept them."""
    ref = tm_labs.reference_threats(lab)
    made = []
    for rt in ref:
        ids = a._resolve_ref_targets(ws, rt)
        if not ids or len(made) >= n:
            continue
        name = m.target_name(ws, ids[0])
        asset = ws["scope"]["assets"][0]["name"]
        tid = m.add_threat(ws, stride=rt["stride_letter"], source="A remote attacker with network access to the exposed interface",
                           preconditions=f"the exposed interface of {name} is reachable and relies on a single control",
                           action=f"abuse the weakness described as '{rt['summary'][:60]}' against {name} to bypass the intended check",
                           targets=ids[:1], security_property=m.PROPERTY_FOR_STRIDE[rt["stride_letter"]],
                           impact="loss of trust in the records and regulatory exposure", assets=[asset],
                           evidence="Design review of the brief", rationale=f"{m.STRIDE[rt['stride_letter']]} applies to {name}; the brief shows no compensating control.",
                           confidence="Medium", uncertainties="Exact deployment configuration unknown",
                           departure_rationale="Scenario-specific analysis of an attack path that applies beyond the standard prompt." if m.departs_from_standard(ws, {"stride": rt["stride_letter"], "targets": ids[:1]}) else "")
        made.append(tid)
    return made


def build_trees(ws):
    """Threat 1 and 3: from the suggested library template. Threat 2: designed from scratch. (Step 3)"""
    for i, t in enumerate(ws["threats"]):
        if m.get_tree(ws, t["id"]):
            continue
        if i % 2 == 0:
            tpl = tm_library.suggest_trees(ws, t)[0]["tree_id"]
            m.create_attack_tree(ws, t["id"], tpl)
        else:
            m.create_attack_tree(ws, t["id"], goal=f"Achieve the effect described in {t['id']}")
            root = m.get_tree(ws, t["id"])["nodes"][0]["id"]
            m.add_step(ws, t["id"], root, "Reach the exposed interface from the network")
            m.add_step(ws, t["id"], root, "Abuse the missing check described in the threat")


def validate_trees(ws):
    """Judge every leaf step (Step 6)."""
    for t in ws["threats"]:
        tr = m.get_tree(ws, t["id"])
        if not tr:
            continue
        leaves = [n for n in tr["nodes"] if n["type"] == "leaf"]
        for j, n in enumerate(leaves):
            if n["status"] != "unassessed":
                continue
            if j % 3 == 2:
                m.assess_step(ws, n["id"], "implausible", None, "A documented design control in this system prevents this step; see the design review.")
            else:
                m.assess_step(ws, n["id"], "plausible", 2 + (j % 2), "Reachable with moderate effort given the exposure described in the brief.")
        if not m.tree_analysis(ws, t["id"])["viable"]:
            for n in leaves:
                m.assess_step(ws, n["id"], "plausible", 3, "Re-assessed: the design offers no compensating control for this step.")


def consider_remaining_cells(ws):
    for tid, L in m.applicable_cells(ws):
        if m.cell_status(ws, tid, L)["status"] == "unconsidered":
            m.set_stride_cell(ws, tid, L, "not_applicable", f"No credible {m.STRIDE[L].lower()} scenario for {m.target_name(ws, tid)} beyond recorded threats in this scope.")


def review_boundaries(ws):
    for inv in m.boundary_inventory(ws):
        b = inv["boundary"]
        m.set_boundary_review(ws, b["id"], "Separates components with different owners and exposure.", "Callers outside are no longer trusted to be well-formed or authentic.",
                              ["Identity", "Input validation", "Integrity"], "Authenticate and validate at the crossing; log decisions.", "Pen-test report and configuration review.")
        for c in inv["crossings"]:
            m.set_crossing_review(ws, b["id"], c["flow_id"], "Sender identity must be proven; payload is untrusted.", "Mutual authentication and schema validation.", "Config export and negative tests.")


def map_threats(ws):
    for t in ws["threats"]:
        m.add_no_mapping(ws, t["id"], "ATT&CK", "The attack path in this scenario is design-level misuse; no specific adversary technique is evidenced.")
        m.add_no_mapping(ws, t["id"], "CAPEC", "No catalogued pattern fits the scenario closely enough to map confidently without forcing it.")


def rate_risks(ws):
    for i, t in enumerate(ws["threats"]):
        if m.get_risk(ws, t["id"]) and m.get_risk(ws, t["id"])["inherent"] and not m.get_risk(ws, t["id"]).get("stale"):
            continue
        m.set_inherent_risk(ws, t["id"], 3 + (i % 2), "Reachable path with moderate effort and no compensating control.", 4,
                            "Regulated data and customer trust are affected.", "Regulated business with external users", "Design review", "")


def propose_and_verify_controls(ws, verify=True):
    for i, t in enumerate(ws["threats"]):
        if m.controls_for(ws, t["id"]):
            continue
        an = m.tree_analysis(ws, t["id"])
        cut = sorted({p["steps"][0] for p in an["easiest_tier"]}) if an["exists"] else []
        cid = m.add_control(ws, [t["id"]], f"Control for {t['id']}", "Enforce the failed trust assumption at the interface.",
                            "Implement server-side checks at the receiving component and log decisions.", "preventive", owner="Engineering lead", step_ids=cut)
        if verify:
            m.set_control_status(ws, cid, "implemented")
            m.record_verification(ws, cid, "Negative test against the interface", "Test run TR-%d: bypass attempt rejected, log entry seen" % i,
                                  date.today().isoformat(), "pass", "QA")


def rate_and_control(ws, verify=True):
    rate_risks(ws)
    propose_and_verify_controls(ws, verify)


def residual(ws):
    for i, t in enumerate(ws["threats"]):
        ctl = m.controls_for(ws, t["id"])[0]
        inh = m.get_risk(ws, t["id"])["inherent"]
        if ctl["status"] == "verified":
            m.set_residual_risk(ws, t["id"], max(1, inh["likelihood"] - 1), "Verified control blocks the demonstrated bypass path.", inh["impact"],
                                "Impact is unchanged: the control does not limit what is exposed.", [ctl["id"]], "Authenticated insider misuse remains possible.",
                                "Control covers the tested interface only.", "Verified negative test shows the bypass path is closed.")
        else:
            m.set_residual_risk(ws, t["id"], inh["likelihood"], "No verified control, so likelihood is unchanged.", inh["impact"], "Impact unchanged.", [],
                                "Original attack path remains.", "Control not verified.")
        m.set_treatment(ws, t["id"], "mitigate", "Engineering lead", "Controls are planned and verified where possible; residual tracked in the register.")
    m.add_question(ws, "Who confirms that the provider patches managed components within the agreed window?", owner="Platform lead", due=FUTURE)
    m.add_question(ws, "Is traffic between internal components encrypted in every environment?", owner="Platform lead", due=FUTURE, related=[ws["threats"][0]["id"]])
    m.add_question(ws, "What firmware or client update path exists and who signs releases?", owner="Product owner", due=FUTURE)


def review_plan(ws):
    m.set_review_plan(ws, model_owner="Product owner", security_reviewer="Security architect", next_review=FUTURE, cadence=m.CADENCES[1],
                      full_triggers=["Major architecture change", "New trust boundary"], change_triggers=["Identity change", "New data flow", "Dependency change"],
                      required_approval="Security architect sign-off", required_evidence="Updated DFD version and revalidation notes")


def remodel(ws):
    f = m.flows(ws)[0]
    m.update_flow(ws, f["id"], protocol=f["protocol"] + " v2")
    for s in m.stale_items(ws):
        m.revalidate(ws, s["kind"], s["id"], "Re-checked after the protocol change; analysis still holds.")
    m.commit_dfd(ws, "Protocol changed during re-modelling exercise", "tester")
    m.complete_remodel_exercise(ws, "Changed a flow protocol; the affected threat, mapping, risk and control were revalidated and no decision changed.")


def complete_lab(lab, discover_first=None):
    ws = m.new_workspace(lab)
    if discover_first is not None and not tm_labs.profile(lab)["discover_first_locked"]:
        a.set_discover_first(ws, discover_first)
    build_scope(ws, lab)
    build_dfd(ws, lab)
    m.commit_dfd(ws, "Initial DFD", "tester")
    build_threats(ws, lab)
    build_trees(ws)
    consider_remaining_cells(ws)
    review_boundaries(ws)
    map_threats(ws)
    validate_trees(ws)
    rate_and_control(ws)
    residual(ws)
    review_plan(ws)
    remodel(ws)
    return ws
