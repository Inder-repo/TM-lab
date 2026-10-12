"""The nine canonical steps. Each page reads/writes the single canonical workspace."""
from datetime import date, timedelta

import pandas as pd
import streamlit as st

import tm_assess as a
import tm_catalog
import tm_export as x
import tm_labs
import tm_library
import tm_model as m
import tm_journey
from ui_common import (S, attempt, bump, discover_panel, element_options, flash, frame, gate_panel, go, kv, label, nav, nonce, show_flash,
                       prerequisite_block, save, scope_items, scope_strings, target_options, token, ws)


def _df(rows, cols=None):
    if rows:
        st.dataframe(pd.DataFrame(rows, columns=cols) if cols else pd.DataFrame(rows), use_container_width=True, hide_index=True)


# ═══════════════════════════════════════════════════════════════════════════════════════
# STEP 1
# ═══════════════════════════════════════════════════════════════════════════════════════
def step1():
    w = ws()
    prof = tm_labs.profile(w["lab_id"])
    frame(1, "How to agree what is being assessed before analysing it.",
          "Write the purpose, boundaries, objectives, assets, stakeholders, facts, assumptions and exclusions; then commit a version.",
          "Reviews fail most often because people assumed different scopes. A versioned scope lets you show what the analysis was based on.",
          "A versioned scope statement.",
          "Facts you can cite are separate from assumptions someone must validate; every exclusion has a reason; an accountable person is named.")
    with st.expander("Lab brief", expanded=True):
        st.markdown(tm_labs.brief(w["lab_id"]))
        st.caption(f"Lab role: **{prof['role']}** - {prof['purpose']}")
    st.info(f"Expectation for this lab: {prof['expectations']['scope']}")
    sc = w["scope"]
    with st.form(kv(w, "scope_text")):
        purpose = st.text_area("System purpose and business context", value=sc["purpose"], height=90)
        ctx = st.text_input("Business context (size, criticality, constraints)", value=sc["business_context"])
        sens = st.text_input("Data sensitivity", value=sc["data_sensitivity"], placeholder="e.g. payment card data, health records, credentials")
        if st.form_submit_button("Save text fields"):
            m.set_scope_text(w, "purpose", purpose)
            m.set_scope_text(w, "business_context", ctx)
            m.set_scope_text(w, "data_sensitivity", sens)
            save()
            flash("Scope text saved.")
            st.rerun()
    c1, c2 = st.columns(2)
    with c1:
        scope_strings(w, "in_scope", "System boundaries and in-scope components", "e.g. Checkout API and its database")
        scope_strings(w, "objectives", "Security objectives", "e.g. Order integrity: no unauthorised price change")
        scope_strings(w, "regulatory", "Regulatory constraints", "e.g. PCI-DSS, GDPR")
        scope_strings(w, "success_criteria", "Success criteria for this threat model", "e.g. Every High threat has an owner and a verified control")
    with c2:
        scope_items(w, "assets", "Important assets", [("name", "Asset", None, "text"), ("sensitivity", "Sensitivity", None, "text")])
        scope_items(w, "stakeholders", "Stakeholders and accountable reviewers", [("name", "Name/role holder", None, "text"), ("role", "Role", None, "text"), ("accountable", "Accountable", None, "bool")])
        scope_items(w, "dependencies", "External dependencies", [("name", "Dependency", None, "text"), ("note", "Note", None, "text")])
    st.markdown("---")
    c1, c2 = st.columns(2)
    with c1:
        scope_items(w, "facts", "\u2705 Confirmed facts (you can cite where they come from)", [("text", "Fact", None, "text"), ("source", "Source", None, "text")])
    with c2:
        scope_items(w, "assumptions", "\u2753 Assumptions that need validation",
                    [("text", "Assumption", None, "text"), ("status", "Status", m.ASSUMPTION_STATUS, "select"), ("validation_owner", "Validation owner", None, "text"), ("validation_method", "How to validate", None, "text")])
    scope_items(w, "exclusions", "Exclusions (what is out of scope, and why)", [("text", "Excluded", None, "text"), ("reason", "Reason", None, "text")])
    if w["lab_id"] in ("3", "4"):
        st.markdown("---")
        st.markdown("**What do you need to know that the brief does not say?** Record questions now; they are the same questions you will assign and track in Step 8.")
        with st.form(kv(w, "q1", nonce(w, "q1")), clear_on_submit=True):
            q = st.text_input("Question about the brief", key=kv(w, "q1in", nonce(w, "q1")))
            if st.form_submit_button("Add question"):
                ok, _ = attempt(m.add_question, w, q, token=token(w, "q1"), rerun=False)
                if ok:
                    bump(w, "q1")
                    st.rerun()
        for qq in w["questions"]:
            st.write(f"`{qq['id']}` {qq['text']}")
    st.markdown("---")
    st.subheader("Commit a scope version")
    if m.scope_changed_since_commit(w):
        st.warning("Scope has changes that are not in a committed version." if sc["version"] else "No committed version yet.")
    else:
        st.success(f"Scope v{sc['version']} is current.")
    with st.form(kv(w, "scope_commit")):
        note = st.text_input("What changed? (version note)")
        if st.form_submit_button("Commit scope version", type="primary"):
            attempt(m.commit_scope, w, note, S.get("_sid", ""), ok="Scope version committed.")
    _df([{"Version": v["version"], "When": v["at"], "Note": v["note"]} for v in w["versions"] if v["kind"] == "scope"])
    gate_panel(1)
    nav(1)


# ═══════════════════════════════════════════════════════════════════════════════════════
# STEP 2
# ═══════════════════════════════════════════════════════════════════════════════════════
def _dfd_chart(w):
    if m.elements(w):
        try:
            st.graphviz_chart(x.dfd_dot(w), use_container_width=True)
        except Exception as exc:  # rendering must never block editing
            st.caption(f"Diagram could not be drawn ({exc}). Tables below remain editable.")


def step2():
    w = ws()
    prof = tm_labs.profile(w["lab_id"])
    frame(2, "How to turn a system description into a diagram you can reason about: external entities, processes, data stores, flows and trust boundaries.",
          "Add and edit elements, flows (source, destination, protocol, direction, data classification) and boundaries; resolve the validation findings; commit a version.",
          "Every threat you write later will point at an ID from this diagram. A missing flow is a missing threat.",
          "A versioned DFD plus architecture assumptions.",
          "No flow is incomplete, nothing is disconnected, every external dependency is explained, and each boundary has members.")
    st.info(f"Expectation for this lab: {prof['expectations']['dfd']}")
    _dfd_chart(w)
    t_el, t_fl, t_tb, t_val, t_ref = st.tabs(["Elements", "Data flows", "Trust boundaries", "Validation & version", "Reference / starter"])
    with t_el:
        _elements_tab(w)
    with t_fl:
        _flows_tab(w)
    with t_tb:
        _boundaries_tab(w)
    with t_val:
        _dfd_validation_tab(w)
    with t_ref:
        _dfd_reference_tab(w)
    gate_panel(2)
    nav(2)


def _elements_tab(w):
    n = nonce(w, "el")
    with st.form(kv(w, "el_add", n), clear_on_submit=True):
        c = st.columns(3)
        et = c[0].selectbox("Type", m.ELEMENT_TYPES, format_func=lambda t: m.KIND_LABEL[t], key=kv(w, "el_t", n))
        nm = c[1].text_input("Name", key=kv(w, "el_n", n))
        dom = c[2].text_input("Security domain (optional)", key=kv(w, "el_d", n), placeholder="e.g. Internet, DMZ, Internal")
        desc = st.text_input("Description", key=kv(w, "el_desc", n))
        just = st.text_input("For external entities: why does this dependency exist?", key=kv(w, "el_j", n))
        assumed = st.checkbox("This element is inferred / assumed (not stated in the brief)", key=kv(w, "el_a", n))
        if st.form_submit_button("Add element", type="primary"):
            ok, _ = attempt(m.add_element, w, et, nm, desc, dom, just, token=token(w, "el"), assumed=assumed, rerun=False)
            if ok:
                bump(w, "el")
                st.rerun()
    _df([{"ID": e["id"], "Type": m.KIND_LABEL[e["type"]], "Name": e["name"], "Domain": e["security_domain"], "Assumed": "yes" if e["assumed"] else "", "Rev": e["rev"]} for e in m.elements(w)])
    if not m.elements(w):
        return
    sel = st.selectbox("Edit or delete an element", [""] + element_options(w), format_func=lambda i: "-" if not i else label(w, i), key=kv(w, "el_sel"))
    if sel:
        e = m.find(m.elements(w), sel)
        aff = m.impact_analysis(w, sel)
        st.caption(f"If this changes: {len(aff['threats'])} threat(s), {len(aff['mappings'])} mapping(s), {len(aff['risks'])} risk record(s), {len(aff['controls'])} control(s) will be flagged for revalidation.")
        with st.form(kv(w, "el_edit", sel, e["rev"])):
            c = st.columns(3)
            ntype = c[0].selectbox("Type", m.ELEMENT_TYPES, index=m.ELEMENT_TYPES.index(e["type"]), format_func=lambda t: m.KIND_LABEL[t])
            nname = c[1].text_input("Name", value=e["name"])
            ndom = c[2].text_input("Security domain", value=e["security_domain"])
            ndesc = st.text_input("Description", value=e["description"])
            njust = st.text_input("Justification (external entities)", value=e["justification"])
            nass = st.checkbox("Inferred / assumed", value=e["assumed"])
            if st.form_submit_button("Save changes"):
                ok, ch = attempt(m.update_element, w, sel, type=ntype, name=nname, security_domain=ndom, description=ndesc, justification=njust, assumed=nass, rerun=False)
                if ok:
                    flash(f"{sel} updated; {len(m.stale_items(w))} record(s) now need revalidation." if ch else "No change.", "warning" if ch else "info")
                    st.rerun()
        conf = st.checkbox(f"I understand deleting {sel} also deletes its flows and orphans threats that refer to it", key=kv(w, "el_del_c", sel))
        if st.button("Delete element", key=kv(w, "el_del", sel), disabled=not conf):
            attempt(m.delete_element, w, sel, ok=f"{sel} deleted. Affected records are flagged.")


def _flows_tab(w):
    els = element_options(w)
    if len(els) < 2:
        st.info("Add at least two elements first.")
        return
    n = nonce(w, "fl")
    with st.form(kv(w, "fl_add", n), clear_on_submit=True):
        c = st.columns(3)
        src = c[0].selectbox("Source", els, format_func=lambda i: label(w, i), key=kv(w, "fl_s", n))
        dst = c[1].selectbox("Destination", els, index=1, format_func=lambda i: label(w, i), key=kv(w, "fl_d", n))
        dirn = c[2].selectbox("Direction", m.DIRECTIONS, key=kv(w, "fl_dir", n))
        c = st.columns(3)
        data = c[0].text_input("Data carried", key=kv(w, "fl_data", n))
        proto = c[1].text_input("Protocol", key=kv(w, "fl_p", n), placeholder="e.g. HTTPS, mTLS, MQTT/TLS")
        cls = c[2].selectbox("Data classification", [""] + m.CLASSIFICATIONS, key=kv(w, "fl_c", n))
        auth = st.text_input("How is the caller authenticated? (optional but recommended)", key=kv(w, "fl_a", n))
        notes = st.text_input("Notes", key=kv(w, "fl_n", n))
        if st.form_submit_button("Add flow", type="primary"):
            ok, _ = attempt(m.add_flow, w, src, dst, data, proto, dirn, cls, auth, notes, token=token(w, "fl"), rerun=False)
            if ok:
                bump(w, "fl")
                st.rerun()
    _df([{"ID": f["id"], "From": label(w, f["source"]), "To": label(w, f["destination"]), "Data": f["data"], "Protocol": f["protocol"], "Dir": f["direction"],
          "Class": f["classification"], "Auth": f["authenticated"]} for f in m.flows(w)])
    if not m.flows(w):
        return
    sel = st.selectbox("Edit or delete a flow", [""] + [f["id"] for f in m.flows(w)], format_func=lambda i: "-" if not i else label(w, i), key=kv(w, "fl_sel"))
    if sel:
        f = m.find(m.flows(w), sel)
        with st.form(kv(w, "fl_edit", sel, f["rev"])):
            c = st.columns(3)
            ns = c[0].selectbox("Source", els, index=els.index(f["source"]), format_func=lambda i: label(w, i))
            nd = c[1].selectbox("Destination", els, index=els.index(f["destination"]), format_func=lambda i: label(w, i))
            ndir = c[2].selectbox("Direction", m.DIRECTIONS, index=m.DIRECTIONS.index(f["direction"]))
            c = st.columns(3)
            ndata = c[0].text_input("Data", value=f["data"])
            nproto = c[1].text_input("Protocol", value=f["protocol"])
            ncls = c[2].selectbox("Classification", [""] + m.CLASSIFICATIONS, index=([""] + m.CLASSIFICATIONS).index(f["classification"]))
            nauth = st.text_input("Authentication", value=f["authenticated"])
            if st.form_submit_button("Save changes"):
                ok, ch = attempt(m.update_flow, w, sel, source=ns, destination=nd, direction=ndir, data=ndata, protocol=nproto, classification=ncls, authenticated=nauth, rerun=False)
                if ok:
                    flash(f"{sel} updated; dependent records flagged for revalidation." if ch else "No change.", "warning" if ch else "info")
                    st.rerun()
        if st.button("Delete flow", key=kv(w, "fl_del", sel)):
            attempt(m.delete_flow, w, sel, ok=f"{sel} deleted.")


def _boundaries_tab(w):
    els = element_options(w)
    n = nonce(w, "tb")
    with st.form(kv(w, "tb_add", n), clear_on_submit=True):
        nm = st.text_input("Boundary name", key=kv(w, "tb_n", n))
        mem = st.multiselect("Elements inside this boundary", els, format_func=lambda i: label(w, i), key=kv(w, "tb_m", n))
        desc = st.text_input("What changes at this boundary? (one line - justified in Step 4)", key=kv(w, "tb_d", n))
        if st.form_submit_button("Add trust boundary", type="primary"):
            ok, _ = attempt(m.add_boundary, w, nm, desc, mem, token=token(w, "tb"), rerun=False)
            if ok:
                bump(w, "tb")
                st.rerun()
    cr = m.crossings(w)
    _df([{"ID": b["id"], "Boundary": b["name"], "Members": ", ".join(b["members"]), "Crossing flows": ", ".join(c["flow_id"] for c in cr if c["boundary_id"] == b["id"])} for b in m.boundaries(w)])
    st.caption("Crossing flows are computed from membership. You will justify them once, in Step 4.")
    if m.boundaries(w):
        sel = st.selectbox("Edit or delete a boundary", [""] + [b["id"] for b in m.boundaries(w)], key=kv(w, "tb_sel"))
        if sel:
            b = m.find(m.boundaries(w), sel)
            with st.form(kv(w, "tb_edit", sel, b["rev"])):
                nn = st.text_input("Name", value=b["name"])
                nm = st.multiselect("Members", els, default=b["members"], format_func=lambda i: label(w, i))
                nd = st.text_input("Description", value=b["description"])
                if st.form_submit_button("Save changes"):
                    attempt(m.update_boundary, w, sel, name=nn, members=nm, description=nd, ok="Boundary updated; affected crossings flagged.")
            if st.button("Delete boundary", key=kv(w, "tb_del", sel)):
                attempt(m.delete_boundary, w, sel, ok="Boundary deleted.")


def _dfd_validation_tab(w):
    iss = m.dfd_issues(w)
    if not iss:
        st.success("No structural problems found. (This does not prove the DFD is complete - ask what is missing.)")
    for i in iss:
        (st.error if i["severity"] == "error" else st.warning)(i["message"])
    with st.form(kv(w, "dfd_notes")):
        ass = st.text_area("Architecture assumptions (one per line)", value="\n".join(w["dfd"]["assumptions"]))
        nb = st.text_input("If there is no trust boundary: why is this a single trust domain?", value=w["dfd"]["no_boundary_rationale"])
        if st.form_submit_button("Save assumptions"):
            m.set_dfd_notes(w, assumptions=ass.split("\n"), no_boundary_rationale=nb)
            save()
            flash("DFD notes saved.")
            st.rerun()
    st.markdown("**Version**")
    if w["dfd"]["version"] and not m.dfd_changed_since_commit(w):
        st.success(f"DFD v{w['dfd']['version']} is current.")
    with st.form(kv(w, "dfd_commit")):
        note = st.text_input("What changed? (version note)")
        if st.form_submit_button("Commit DFD version", type="primary"):
            attempt(m.commit_dfd, w, note, S.get("_sid", ""), ok="DFD version committed.")
    _df([{"Version": v["version"], "When": v["at"], "Note": v["note"]} for v in w["versions"] if v["kind"] == "dfd"])


def _dfd_reference_tab(w):
    prof = tm_labs.profile(w["lab_id"])
    st.caption({"load": "Lab 1 offers a starter DFD you can load and then review critically.",
                "inventory": "Lab 2 offers a component inventory only - flows and boundaries are yours.",
                "compare": "This lab offers a read-only reference drawing to compare with your own DFD."}[prof["reference_dfd"]])

    def render(data):
        st.info(data["note"])
        model = data["model"]
        _df([{"Name": e["name"], "Type": m.KIND_LABEL[e["type"]], "Description": e["description"]} for e in model["elements"]])
        if model["flows"]:
            _df([{"From": f["source"], "To": f["destination"], "Data": f["data"], "Protocol": f["protocol"]} for f in model["flows"]])
        if data["mode"] in ("load", "inventory"):
            if st.button("Load into my DFD (existing items are never duplicated)", key=kv(w, "load_ref")):
                added = m.load_reference_dfd(w, model)
                save()
                flash(f"Loaded {added['elements']} element(s), {added['flows']} flow(s), {added['boundaries']} boundary(ies). Review them - they are editable.")
                st.rerun()
        else:
            mine = {m.norm(e["name"]) for e in m.elements(w)}
            missing = [e["name"] for e in model["elements"] if m.norm(e["name"]) not in mine]
            extra = [e["name"] for e in m.elements(w) if m.norm(e["name"]) not in {m.norm(r["name"]) for r in model["elements"]}]
            st.write("In the reference but not in yours:", ", ".join(missing) or "nothing")
            st.write("In yours but not in the reference (may be valid additions):", ", ".join(extra) or "nothing")

    discover_panel(w, "2", "Before looking at any reference: what components, data stores and trust changes do you expect in this system, and why?",
                   "dfd_reference", show=render)


# ═══════════════════════════════════════════════════════════════════════════════════════
# STEP 3
# ═══════════════════════════════════════════════════════════════════════════════════════
def step3():
    w = ws()
    prof = tm_labs.profile(w["lab_id"])
    frame(3, "STRIDE as a systematic prompt set, how to turn a prompt into a specific threat statement, and how to break a threat into the attacker's steps (an attack tree).",
          "Pick an element or flow, write a structured threat for it (starting from a library example if you are in guided mode), then open its attack tree. Work through the STRIDE coverage tab so no prompt is skipped.",
          "A threat that names an actor, precondition, action, target and impact - broken into attacker steps - can be rated, mapped, mitigated and verified. 'Hackers steal data' cannot.",
          "Threat register entries (stable IDs, linked to DFD IDs), an attack tree per threat, and a STRIDE disposition for every applicability prompt.",
          "Every prompt is dispositioned with a reason, each threat is specific to this system, departures from the standard model are explained, and attack steps are concrete.")
    if prerequisite_block(3):
        nav(3)
        return
    st.info(f"Expectation for this lab: {prof['expectations']['stride']}")
    t_reg, t_cov, t_ref = st.tabs(["Threat register workspace", "STRIDE coverage", "Reference & library"])
    with t_reg:
        _threat_workspace(w)
    with t_cov:
        st.markdown("**STRIDE-per-element applicability prompts** - prompts for where to look, *not* proof that a threat exists:")
        _df([{"Element type": m.KIND_LABEL[k], **{m.STRIDE[L]: ("\u25CF" if L in v else "\u2014") for L in m.STRIDE_ORDER}} for k, v in m.APPLICABILITY.items()])
        st.caption("You may analyse outside the standard prompts where the scenario warrants it - but you must explain why (departure rationale).")
        _stride_sheet(w)
    with t_ref:
        _threat_reference(w)
        _library_browse(w)
    gate_panel(3)
    nav(3)


def _threat_workspace(w):
    if a.reveal_status(w, "worked_example")[0]:
        ex = a.get_reference(w, "worked_example")
        with st.expander("Worked example (Lab 1)"):
            st.markdown(f"**{ex['title']}**\n\n*Given* {ex['preconditions']}, *{ex['source']}* could {ex['action']}, resulting in {ex['impact']} to {ex['asset']}.\n\n{ex['why']}")
    ids = target_options(w)
    st.markdown("**1. Pick where to look**")
    focus = st.selectbox("Element or flow", ids, format_func=lambda i: label(w, i), key=kv(w, "focus"))
    ctx = [tm_library.TAG_DESC[t] for t in sorted(tm_library.context_tags(w, focus)) if t in tm_library.TAG_DESC]
    st.caption("What your model says about it: " + ("; ".join(ctx) if ctx else "nothing specific yet - add protocol, classification and boundaries in Step 2 for better suggestions."))
    _library_suggestions(w, focus)
    st.markdown("**2. Write the threat**")
    _threat_builder(w, focus)
    st.markdown("**3. Your threats - edit them and open their attack trees**")
    _threat_list(w)


def _library_suggestions(w, focus):
    lvl = a.assist_level(w, "threats")
    ok, why = a.reveal_status(w, "library_suggestions", focus)
    st.caption(f"Assistance for threat writing: **{lvl}** (mode: {w['settings']['assist_mode']})")
    if lvl == "none" and w["settings"]["discover_first"]:
        cur = w["hypotheses"].get("3", {}).get("text", "")
        txt = st.text_area("Before the library: what could go wrong in this system, and why?", value=cur, key=kv(w, "hyp3", nonce(w, "hyp3")), height=70)
        if st.button("Save my threat hypothesis", key=kv(w, "hyp3btn")):
            attempt(a.set_hypothesis, w, "3", txt, ok="Hypothesis saved.")
    if not ok:
        st.info("\U0001F512 " + why)
        return
    with st.expander(f"Library suggestions for this element/flow ({lvl})", expanded=(lvl == "full")):
        data = a.get_reference(w, "library_suggestions", focus)
        save()
        st.caption(data["note"])
        if not data["items"]:
            st.write("No library pattern fits this element.")
        for it in data["items"]:
            tag = "" if it["specific"] else " *(generic - no specific signal in your model)*"
            st.markdown(f"**{it['pattern_id']} {it['name']}** - {m.STRIDE[it['stride']]}{tag}")
            st.caption("Suggested because: " + "; ".join(it["reasons"]))
            st.caption("Applies when: " + it["applies_when"] + "  |  Does not apply when: " + it["not_applicable_when"])
            if "worked_example" in it:
                if st.checkbox(f"Show the worked example for {it['pattern_id']}", key=kv(w, "wex", it["pattern_id"], focus)):
                    ex = it["worked_example"]
                    st.markdown(f"*{ex['system']}*\n\n{ex['statement']}\n\n**Why it is strong:** {ex['why_it_is_strong']}")
            if "draft" in it and st.button(f"Start from {it['pattern_id']}", key=kv(w, "usepat", it["pattern_id"], focus)):
                S[kv(w, "prefill")] = {**it["draft"], "pattern_id": it["pattern_id"], "assist_level": lvl}
                st.rerun()


def _field_kw(key, **kw):
    """Pass defaults only when the widget has no state yet (avoids Streamlit's default-vs-session-state warning)."""
    return {} if key in S else kw


def _builder_widgets(w, base, cur):
    """Shared by add and edit. Not inside a form, so the statement preview is live."""
    ids = target_options(w)
    f = {}
    K = lambda n: kv(w, base, n)
    c = st.columns(2)
    k = K("stride")
    f["stride"] = c[0].selectbox("STRIDE category", list(m.STRIDE_ORDER), format_func=lambda l: f"{l} - {m.STRIDE[l]}", key=k,
                                 **_field_kw(k, index=list(m.STRIDE_ORDER).index(cur.get("stride", "S"))))
    k = K("targets")
    f["targets"] = c[1].multiselect("Affected DFD elements / flows", ids, format_func=lambda i: label(w, i), key=k,
                                    **_field_kw(k, default=[t for t in cur.get("targets", []) if t in ids]))
    src_opts = m.THREAT_SOURCES + ["Other (describe below)"]
    c = st.columns(2)
    k = K("srcpick")
    idx = src_opts.index(cur["source"]) if cur.get("source") in src_opts else (len(src_opts) - 1 if cur.get("source") else 0)
    pick = c[0].selectbox("Threat source / actor", src_opts, key=k, **_field_kw(k, index=idx))
    k = K("srcother")
    other = c[1].text_input("Other source (if chosen)", key=k, **_field_kw(k, value=cur.get("source", "") if idx == len(src_opts) - 1 else ""))
    f["source"] = other if pick.startswith("Other") else pick
    k = K("pre")
    f["preconditions"] = st.text_input("Preconditions / relevant assumptions (Given ...)", key=k, **_field_kw(k, value=cur.get("preconditions", "")))
    k = K("act")
    f["action"] = st.text_area("Attack action or failure scenario (... could ...)", height=70, key=k, **_field_kw(k, value=cur.get("action", "")))
    c = st.columns(2)
    k = K("prop")
    default_prop = cur.get("security_property") or m.PROPERTY_FOR_STRIDE[f["stride"]]
    f["security_property"] = c[0].selectbox("Security property affected", m.SECURITY_PROPERTIES, key=k, **_field_kw(k, index=m.SECURITY_PROPERTIES.index(default_prop)))
    asset_names = [x["name"] for x in w["scope"]["assets"]]
    k = K("assets")
    f["assets"] = c[1].multiselect("Asset(s) affected (defined in Step 1)", asset_names, key=k, **_field_kw(k, default=[x for x in cur.get("assets", []) if x in asset_names]))
    k = K("imp")
    f["impact"] = st.text_input("Business or technical impact (... resulting in ...)", key=k, **_field_kw(k, value=cur.get("impact", "")))
    k = K("rat")
    f["rationale"] = st.text_area("Rationale: why is this plausible here?", height=70, key=k, **_field_kw(k, value=cur.get("rationale", "")))
    c = st.columns(2)
    k = K("evi")
    f["evidence"] = c[0].text_input("Evidence (design doc, test, advisory...)", key=k, **_field_kw(k, value=cur.get("evidence", "")))
    k = K("unc")
    f["uncertainties"] = c[1].text_input("Unresolved uncertainties", key=k, **_field_kw(k, value=cur.get("uncertainties", "")))
    k = K("conf")
    f["confidence"] = st.selectbox("Confidence", m.CONFIDENCE, key=k, **_field_kw(k, index=m.CONFIDENCE.index(cur["confidence"]) if cur.get("confidence") in m.CONFIDENCE else 1))
    if f["targets"] and m.departs_from_standard(w, f):
        st.warning(f"{m.STRIDE[f['stride']]} is not a standard prompt for these target types. Explain why this scenario warrants it.")
    k = K("dep")
    f["departure_rationale"] = st.text_input("Departure rationale (only if departing from standard applicability)", key=k, **_field_kw(k, value=cur.get("departure_rationale", "")))
    return f


def _threat_builder(w, focus):
    n = nonce(w, "thr")
    base = f"tb{n}"
    K = lambda f_: kv(w, base, f_)
    pf = S.pop(kv(w, "prefill"), None)
    if pf:
        assets = [x["name"] for x in w["scope"]["assets"]]
        for fld, val in {"stride": pf["stride"], "targets": pf["targets"], "srcpick": "Other (describe below)", "srcother": pf["source"], "pre": pf["preconditions"],
                         "act": pf["action"], "prop": pf["security_property"], "assets": [x for x in pf.get("assets", []) if x in assets], "imp": pf["impact"]}.items():
            S[K(fld)] = val
        S[kv(w, "libref")] = {"pattern_id": pf["pattern_id"], "assist_level": pf["assist_level"]}
        st.success(f"Draft loaded from {pf['pattern_id']}. Rewrite it for YOUR system, then add rationale, evidence and confidence.")
    elif K("targets") not in S:
        S[K("targets")] = [focus]
    f = _builder_widgets(w, base, {})
    st.markdown("**Statement preview** (generated from the structured fields)")
    st.info(m.build_statement(w, f))
    if st.button("Add threat", type="primary", key=K("add")):
        ok, tid = attempt(m.add_threat, w, token=token(w, "thr"), rerun=False, library_ref=S.get(kv(w, "libref")), **f)
        if ok:
            S.pop(kv(w, "libref"), None)
            flash(f"{tid} recorded. Open it below to build its attack tree.")
            bump(w, "thr")
            st.rerun()


def _threat_list(w):
    if not w["threats"]:
        st.info("No threats yet. Recording none is acceptable only if every prompt is documented as not applicable.")
        return
    _df([{"ID": t["id"], "STRIDE": m.STRIDE[t["stride"]], "Targets": ", ".join(t["targets"]), "Statement": m.statement_text(w, t),
          "Attack tree": ("yes" if m.get_tree(w, t["id"]) else "-"), "Confidence": t["confidence"], "Stale": "\u26A0" if t.get("stale") else "",
          "Origin": "from example" if t.get("library_ref") else t["origin"]} for t in w["threats"]])
    sel = st.selectbox("Open a threat (edit, revalidate, attack tree, delete)", [""] + [t["id"] for t in w["threats"]], key=kv(w, "thr_sel"))
    if not sel:
        return
    t = m.find(w["threats"], sel)
    if t.get("stale"):
        st.warning("Needs revalidation: " + "; ".join(s["reason"] for s in t["stale"][-3:]))
        note = st.text_input("What did you re-check, and what did you conclude?", key=kv(w, "thr_reval", sel))
        if st.button("Mark revalidated", key=kv(w, "thr_revalbtn", sel)):
            attempt(m.revalidate, w, "threat", sel, note, ok=f"{sel} revalidated.")
    if t.get("orphaned_targets"):
        st.error(f"Targets removed from the DFD: {t['orphaned_targets']}. Choose replacement targets below.")
    t_edit, t_tree = st.tabs([f"{sel}: statement", f"{sel}: attack tree"])
    with t_edit:
        base = f"ed_{sel}_{t['updated']}"
        f = _builder_widgets(w, base, t)
        st.markdown("**Structured statement** (always regenerated from the fields above):")
        st.info(m.build_statement(w, f))
        ov = st.text_area("Edited wording (optional - the structured fields are kept either way)", value=t["statement_override"], height=80, key=kv(w, base, "ov"))
        c1, c2, c3 = st.columns(3)
        if c1.button("Save changes", key=kv(w, base, "save"), type="primary"):
            attempt(m.update_threat, w, sel, statement_override=ov, ok=f"{sel} saved; its tree, mappings, risk and controls were flagged for re-check if the substance changed.", **f)
        if c2.button("Reset wording to generated", key=kv(w, base, "reset")):
            m.reset_statement(w, sel)
            save()
            st.rerun()
        if c3.button("Delete threat", key=kv(w, base, "del")):
            attempt(m.delete_threat, w, sel, ok=f"{sel} deleted with its tree, mappings and risk record.")
    with t_tree:
        _attack_tree_ui(w, t)


def _attack_tree_ui(w, t):
    tid = t["id"]
    tr = m.get_tree(w, tid)
    lvl = a.assist_level(w, "trees")
    if not tr:
        st.info("An attack tree breaks the attacker's goal into the steps they must take (OR = any one is enough, AND = all are needed). "
                "You will validate each step in Step 6, map it in Step 5, and link controls to it in Step 7.")
        if lvl == "none" and w["settings"]["discover_first"]:
            cur = w["hypotheses"].get(f"3:{tid}", {}).get("text", "")
            txt = st.text_area("Sketch the attack path in your own words (steps, in order)", value=cur, key=kv(w, "hyp3t", tid), height=70)
            if st.button("Save attack-path sketch", key=kv(w, "hyp3tb", tid)):
                attempt(a.set_hypothesis, w, f"3:{tid}", txt, ok="Sketch saved.")
        ok, why = a.reveal_status(w, "tree_templates", tid)
        if ok:
            data = a.get_reference(w, "tree_templates", tid)
            save()
            for it in data["items"]:
                st.markdown(f"**{it['tree_id']} {it['name']}** - goal: {it['goal']}")
                st.caption("Suggested because: " + "; ".join(it["reasons"]) + "  |  Applies when: " + it["applies_when"] + "  |  Does not apply when: " + it["not_applicable_when"])
                if "worked_example" in it:
                    ex = it["worked_example"]
                    with st.expander(f"Worked example ({it['tree_id']}): {ex['system']}"):
                        st.write(ex["reading"])
                        for sid, asx in ex["assessments"].items():
                            st.write(f"- {sid}: **{asx['status']}**" + (f" (effort {asx['difficulty']})" if asx.get("difficulty") else "") + f" - {asx['rationale']}")
                        st.write("**Reading the result:** " + ex["outcome"])
                if st.button(f"Use template {it['tree_id']} (then edit it)", key=kv(w, "usetree", tid, it["tree_id"])):
                    attempt(m.create_attack_tree, w, tid, it["tree_id"], ok=f"Attack tree created for {tid}. Edit it to match your system.")
        else:
            st.info("\U0001F512 " + why)
        with st.form(kv(w, "scratch", tid)):
            goal = st.text_input("...or start from scratch: the attacker's goal", value=t["title"])
            if st.form_submit_button("Create empty attack tree"):
                attempt(m.create_attack_tree, w, tid, None, goal, ok="Empty attack tree created.")
        return
    an = m.tree_analysis(w, tid)
    if tr.get("stale"):
        st.warning("Stale: " + tr["stale"][-1]["reason"])
        note = st.text_input("What did you re-check?", key=kv(w, "trrev_note", tid))
        if st.button("Mark attack tree revalidated", key=kv(w, "trrev", tid)):
            attempt(m.revalidate, w, "tree", tid, note, ok="Attack tree revalidated.")
    try:
        st.graphviz_chart(x.tree_dot(w, tid), use_container_width=True)
    except Exception as exc:
        st.caption(f"Diagram could not be drawn ({exc}).")
    _df([{"Step": n["id"], "Kind": n["logic"].upper() if n["type"] != "leaf" else "leaf", "Attack step": ("\u2003" * x_depth(tr, n)) + n["label"],
          "Validated": n["status"] if n["type"] == "leaf" else "", "Effort": n["difficulty"] or "",
          **({"Template hint": n["hint_difficulty"] or ""} if lvl == "full" and n["type"] == "leaf" else {})} for n in tr["nodes"]])
    st.caption(f"{an['assessed']}/{an['leaves']} leaf steps validated (done in Step 6). Issues: {'; '.join(an['structure_issues']) or 'none'}.")
    groups = [n for n in tr["nodes"] if n["type"] != "leaf"]
    with st.form(kv(w, "addstep", tid, tr["rev"])):
        c = st.columns([2, 1, 4])
        parent = c[0].selectbox("Add under", [g["id"] for g in groups], format_func=lambda i: f"{i} {next(g['label'] for g in groups if g['id'] == i)[:30]}")
        typ = c[1].selectbox("Kind", m.STEP_TYPES)
        lab_ = c[2].text_input("Attack step")
        if st.form_submit_button("Add step"):
            attempt(m.add_step, w, tid, parent, lab_, typ, ok="Step added.")
    pick = st.selectbox("Edit or delete a step", [""] + [n["id"] for n in tr["nodes"]], key=kv(w, "stpick", tid))
    if pick:
        n = next(n for n in tr["nodes"] if n["id"] == pick)
        with st.form(kv(w, "edstep", pick, n["label"], n["logic"])):
            nl = st.text_input("Wording", value=n["label"])
            nd = st.text_input("Description", value=n["description"])
            lg = st.selectbox("Logic for sub-steps", ["or", "and"], index=0 if n["logic"] != "and" else 1, disabled=(n["type"] == "leaf"))
            if st.form_submit_button("Save step"):
                attempt(m.update_step, w, pick, label=nl, description=nd, logic=None if n["type"] == "leaf" else lg, ok="Step updated; ratings that depend on it were flagged.")
        if n["parent"] and st.button("Delete this step (and its sub-steps)", key=kv(w, "delstep", pick)):
            attempt(m.delete_step, w, pick, ok="Step deleted; control and mapping links to it were removed and flagged.")
    if st.button("Delete the whole attack tree", key=kv(w, "deltree", tid)):
        attempt(m.delete_attack_tree, w, tid, ok="Attack tree deleted.")


def x_depth(tr, n):
    d, cur = 0, n
    while cur["parent"]:
        cur = next(y for y in tr["nodes"] if y["id"] == cur["parent"])
        d += 1
    return d


def _library_browse(w):
    st.markdown("---")
    st.markdown("**Browse the library** - 15 threat patterns and 6 attack-tree templates, each with applicability conditions and a worked example on a neutral system.")
    lvl = a.assist_level(w, "threats")
    ok, why = a.reveal_status(w, "library_browse")
    if not ok:
        st.info("\U0001F512 " + why)
        return
    if st.button("Open the library", key=kv(w, "libopen")):
        S[kv(w, "libshown")] = True
    if not S.get(kv(w, "libshown")):
        return
    data = a.get_reference(w, "library_browse")
    save()
    for p in data["patterns"]:
        with st.expander(f"{p['id']} {p['name']} ({m.STRIDE[p['stride']]})"):
            st.write("**Applies when:** " + p["applies_when"])
            st.write("**Does not apply when:** " + p["not_applicable_when"])
            ex = p["worked_example"]
            st.write(f"**Worked example** ({ex['system']}): {ex['statement']}")
            st.write("**Why it is strong:** " + ex["why_it_is_strong"])
            st.caption("Control themes: " + "; ".join(p["control_themes"]) + "  |  References (topic level - check current edition): " + "; ".join(p["references"]))
    for tr_ in data["trees"]:
        with st.expander(f"{tr_['id']} {tr_['name']} - {tr_['goal']}"):
            st.write("**Applies when:** " + tr_["applies_when"])
            st.write("**Does not apply when:** " + tr_["not_applicable_when"])
            st.write("**Worked example:** " + tr_["worked_example"]["system"] + " - " + tr_["worked_example"]["outcome"])


def _stride_sheet(w):
    sym = {"threat": "\u25CF ", "not_applicable": "N/A", "mitigated_by_design": "MbD", "deferred": "defer", "unconsidered": "\u25CB", "stale": "\u26A0 re-check"}
    rows = []
    for tid in target_options(w):
        kind = m.target_kind(w, tid)
        row = {"ID": tid, "Name": m.target_name(w, tid)}
        for L in m.STRIDE_ORDER:
            if L in m.applicable_letters(kind):
                cs = m.cell_status(w, tid, L)
                row[m.STRIDE[L]] = sym[cs["status"]] + (",".join(cs["threat_ids"]) if cs["threat_ids"] else "")
            else:
                row[m.STRIDE[L]] = "\u2014"
        rows.append(row)
    _df(rows)
    cov = m.stride_coverage(w)
    st.caption(f"\u25CB not yet considered \u00b7 \u25CF threat recorded \u00b7 N/A not applicable (reason recorded) \u00b7 MbD mitigated by design \u00b7 defer deferred. "
               f"{cov['total'] - len(cov['open'])} of {cov['total']} prompts dispositioned. This measures reasoning coverage, not threat count.")
    for key_, c_ in [(k_, v_) for k_, v_ in w["stride_cells"].items() if v_.get("stale")]:
        tgt_, L_ = key_.split(":")
        st.warning(f"{label(w, tgt_)} \u00b7 {m.STRIDE[L_]}: your earlier decision ({c_['disposition'].replace('_', ' ')}: {c_['rationale'][:60]}) predates a model change - {c_['stale'][-1]['reason']}")
        note_ = st.text_input("What did you re-check?", key=kv(w, "cellrev_note", key_))
        if st.button("Decision still holds", key=kv(w, "cellrev", key_)):
            attempt(m.revalidate, w, "cell", key_, note_, ok="STRIDE decision revalidated.")
    with st.form(kv(w, "cell", nonce(w, "cell")), clear_on_submit=True):
        c = st.columns(3)
        tid = c[0].selectbox("Element / flow", target_options(w), format_func=lambda i: label(w, i), key=kv(w, "cell_t", nonce(w, "cell")))
        L = c[1].selectbox("STRIDE category", list(m.STRIDE_ORDER), format_func=lambda l: m.STRIDE[l], key=kv(w, "cell_l", nonce(w, "cell")))
        disp = c[2].selectbox("Disposition", ["not_applicable", "mitigated_by_design", "deferred"], format_func=lambda d: d.replace("_", " "), key=kv(w, "cell_d", nonce(w, "cell")))
        why = st.text_input("Reason (required unless deferred - 'N/A' alone is not a reason)", key=kv(w, "cell_r", nonce(w, "cell")))
        st.caption("To record a threat for a prompt, use the Threat statement builder tab.")
        if st.form_submit_button("Record disposition"):
            ok, _ = attempt(m.set_stride_cell, w, tid, L, disp, why, rerun=False)
            if ok:
                bump(w, "cell")
                st.rerun()



def _threat_reference(w):
    def render_threats(rows):
        for r in rows:
            note = f" - unresolved targets: {', '.join(r['unresolved'])}" if r["unresolved"] else ""
            st.write(f"**{r['ref_id']}** ({r['stride']}) {r['summary']}{note}")
    discover_panel(w, "3", "Before seeing reference threats: what do you think the most serious ways this system could fail are, and why?",
                   "stride_suggestions", show=render_threats, label_btn="Show reference threats")
    st.markdown("---")

    def render_tree(data):
        st.caption(data["note"])
        st.markdown(f"**{data['title']}** - {data['description']}")
        st.graphviz_chart(data["dot"], use_container_width=True)
    discover_panel(w, "3", "", "attack_tree", show=render_tree, label_btn="Show an example attack tree", ask=False)   # same hypothesis as above




# ═══════════════════════════════════════════════════════════════════════════════════════
# STEP 4
# ═══════════════════════════════════════════════════════════════════════════════════════
def step4():
    w = ws()
    frame(4, "How trust assumptions change at a boundary, and what must be true at each crossing.",
          "For each boundary defined in Step 2, justify it; then document the assumption, control and evidence for each crossing flow.",
          "Boundary crossings are where identity, authorisation and validation decisions are made. Reviewers ask for evidence that those decisions hold.",
          "A validated boundary inventory with documented crossing assumptions.",
          "Each justification explains what changes (not just that a boundary exists), and each crossing names a control and the evidence that would validate it.")
    if prerequisite_block(4):
        nav(4)
        return
    st.info("A trust boundary is **not** a threat. It is where you ask what changes. Boundaries and crossings come from Step 2 - nothing is re-mapped here. "
            "Zone/criticality scores no longer drive STRIDE.")
    if not m.boundaries(w):
        st.warning("No boundaries defined in Step 2. Add them there, or record why the system is a single trust domain.")
    for inv in m.boundary_inventory(w):
        b, rv = inv["boundary"], inv["review"] or {}
        tick = "\u2705" if inv["validated"] else "\u26AA"
        members = ", ".join(b["members"])
        with st.expander(f"{tick} {b['id']} \u00b7 {b['name']} \u2014 members: {members}", expanded=not inv["validated"]):
            if rv.get("stale"):
                st.warning("Stale: " + rv["stale"][-1]["reason"])
                note = st.text_input("What did you re-check?", key=kv(w, "tbrev_note", b["id"]))
                if st.button("Mark revalidated", key=kv(w, "tbrev_btn", b["id"])):
                    attempt(m.revalidate, w, "boundary_review", b["id"], note, ok="Boundary review revalidated.")
            with st.form(kv(w, "tbrev", b["id"], rv.get("at", "new"))):
                why = st.text_area("Why does this boundary exist?", value=rv.get("why_exists", ""), height=60)
                chg = st.text_area("What trust assumption changes when crossing it?", value=rv.get("trust_change", ""), height=60)
                props = st.multiselect("Which properties matter here?", m.BOUNDARY_PROPERTIES, default=rv.get("properties", []))
                ctl = st.text_area("What controls are required at the crossing?", value=rv.get("controls_required", ""), height=60)
                evi = st.text_area("What evidence would validate these assumptions?", value=rv.get("evidence_needed", ""), height=60)
                if st.form_submit_button("Save boundary justification"):
                    attempt(m.set_boundary_review, w, b["id"], why, chg, props, ctl, evi, ok="Boundary justification saved.")
            if not inv["crossings"]:
                st.caption("No flows cross this boundary. Is a flow missing in Step 2, or is the boundary unnecessary?")
            for c in inv["crossings"]:
                fl, cr = c["flow"], c["review"] or {}
                thr = [t["id"] for t in w["threats"] if fl["id"] in t["targets"]]
                st.markdown(f"**{fl['id']}** {m.target_name(w, fl['id'])} \u00b7 {c['direction']} \u00b7 protocol: {fl['protocol'] or '?'} \u00b7 threats already recorded here: {', '.join(thr) or 'none'}")
                if cr.get("stale"):
                    st.warning("Stale: " + cr["stale"][-1]["reason"])
                    note = st.text_input("What did you re-check?", key=kv(w, "crrev_note", b["id"], fl["id"]))
                    if st.button("Mark revalidated", key=kv(w, "crrev_btn", b["id"], fl["id"])):
                        attempt(m.revalidate, w, "crossing", f"{b['id']}|{fl['id']}", note, ok="Crossing revalidated.")
                with st.form(kv(w, "cr", b["id"], fl["id"], cr.get("at", "new"))):
                    cols = st.columns(3)
                    ass = cols[0].text_area("Trust assumption at this crossing", value=cr.get("assumption", ""), height=70)
                    con = cols[1].text_area("Control at this crossing", value=cr.get("control", ""), height=70)
                    evi = cols[2].text_area("Evidence that would validate it", value=cr.get("evidence", ""), height=70)
                    if st.form_submit_button("Save crossing"):
                        attempt(m.set_crossing_review, w, b["id"], fl["id"], ass, con, evi, ok="Crossing documented.")
    gate_panel(4)
    nav(4)


# ═══════════════════════════════════════════════════════════════════════════════════════
# STEP 5
# ═══════════════════════════════════════════════════════════════════════════════════════
def step5():
    w = ws()
    prof = tm_labs.profile(w["lab_id"])
    frame(5, "The difference between STRIDE (nature of the threat), ATT&CK (adversary tactics and techniques), CAPEC (recurring attack patterns) and your threat statement (what could happen HERE).",
          "For each threat, describe the attack path, then map it to ATT&CK and/or CAPEC only where the path supports it - or record 'no defensible mapping' with a reason.",
          "Mappings let detection and testing teams reuse existing knowledge. A forced mapping sends them to the wrong place.",
          "Mapping records with identifier, official name, source, rationale and confidence - or documented non-mappings.",
          "The rationale refers to this system's attack path (not just the STRIDE label), and the ID/name come from the catalogue.")
    if prerequisite_block(5):
        nav(5)
        return
    st.info(f"Expectation for this lab: {prof['expectations']['mappings']}")
    _df([{"Framework": "STRIDE", "Answers": "What kind of threat is it?", "Granularity": "6 categories"},
         {"Framework": "MITRE ATT&CK", "Answers": "Which adversary tactic/technique would be used?", "Granularity": "Tactics -> techniques"},
         {"Framework": "CAPEC", "Answers": "Which recurring attack pattern does it resemble?", "Granularity": "Attack patterns"},
         {"Framework": "Threat statement", "Answers": "What could happen in THIS system?", "Granularity": "System-specific"}])
    meta = tm_catalog.catalogue_meta()
    for fw, v in meta.items():
        if v["status"] != "verified":
            st.warning(f"{fw} dataset: **{v['status']}** ({v['declared_version']}). Entries are a curated teaching subset and have not been validated against the official source in this build; "
                       "run `python tools/verify_catalogues.py` with the official STIX bundle to verify. Exports carry this status.")
        else:
            st.success(f"{fw} dataset verified on {v['verified_on']} ({v['declared_version']}).")
    for t in w["threats"]:
        dec = m.mapping_decisions(w, t["id"])
        icon = "\u2705" if all(d != "undecided" for d in dec.values()) else "\u26AA"
        with st.expander(f"{icon} {t['id']} \u00b7 {m.STRIDE[t['stride']]} \u2014 {m.statement_text(w, t)[:110]}", expanded=icon == "\u26AA" and len(w["threats"]) <= 3):
            st.write(m.statement_text(w, t))
            if t.get("stale"):
                st.warning("Threat is stale - revalidate it in Step 3 first.")
            _mapping_ui(w, t, dec)
    gate_panel(5)
    nav(5)


def _mapping_ui(w, t, dec):
    for mp in [x for x in w["mappings"] if x["threat_id"] == t["id"]]:
        c1, c2 = st.columns([9, 1])
        if mp["outcome"] == "mapped":
            c1.markdown(f"**{mp['framework']} {mp['ref_id']} \u2014 {mp['name']}** \u00b7 [{mp['catalogue_status']}] \u00b7 confidence {mp['confidence']}" + (f" \u00b7 step {mp['step_id']}" if mp.get("step_id") else "") + f"  \n_{mp['relationship']}_  \nBehaviour: {mp['behaviour']}  \nRationale: {mp['rationale']}  \n{mp['url']}")
        else:
            c1.markdown(f"**{mp['framework']}: no defensible mapping** \u2014 {mp['rationale']}")
        if mp.get("stale"):
            note = c1.text_input("What did you re-check?", key=kv(w, "mprev_note", mp["id"]))
            if c1.button("Mark revalidated", key=kv(w, "mprev", mp["id"])):
                attempt(m.revalidate, w, "mapping", mp["id"], note, ok="Mapping revalidated.")
        if c2.button("\u2716", key=kv(w, "mpdel", mp["id"]), help="Remove this decision"):
            attempt(m.delete_mapping, w, mp["id"])
    hyp_key = f"5:{t['id']}"
    if w["settings"]["discover_first"]:
        cur = w["hypotheses"].get(hyp_key, {}).get("text", "")
        txt = st.text_area("Describe the attack path in your own words (adversary steps, in order)", value=cur, key=kv(w, "hyp5", t["id"]), height=80)
        if st.button("Save attack-path hypothesis", key=kv(w, "hyp5b", t["id"])):
            attempt(a.set_hypothesis, w, hyp_key, txt, ok="Saved.")

    def render(data):
        st.caption(data["note"])
        _df([{"ID": e["id"], "Technique": e["name"], "Tactics": ", ".join(e["tactics"]), "STRIDE hint": e["stride"]} for e in data["attack"]])
        _df([{"ID": e["id"], "Pattern": e["name"], "Note": e["note"]} for e in data["capec"]])
        tr_ = m.get_tree(w, t["id"])
        rows_ = [{"Step": n["id"], "Attack step": n["label"], "Candidate ATT&CK": ", ".join(n["attack_ids"]), "Candidate CAPEC": ", ".join(n["capec_ids"])}
                 for n in (tr_["nodes"] if tr_ else []) if n["type"] == "leaf" and (n["attack_ids"] or n["capec_ids"])]
        if rows_:
            _df(rows_)
            st.caption("Candidates attached to the template's steps. They are prompts, not mappings: justify each one yourself, or record that it does not fit.")
    ok, why = a.reveal_status(w, "mapping_suggestions", t["id"])
    if ok:
        if st.button("Show candidate techniques/patterns", key=kv(w, "sug", t["id"])):
            S[kv(w, "sugshow", t["id"])] = True
        if S.get(kv(w, "sugshow", t["id"])):
            render(a.get_reference(w, "mapping_suggestions", t["id"]))
            save()
    else:
        st.caption("\U0001F512 " + why)
    n = nonce(w, "map" + t["id"])
    c = st.columns([1, 2])
    fw = c[0].radio("Framework", list(tm_catalog.FRAMEWORKS), key=kv(w, "fw", t["id"], n), horizontal=True)
    q = c[1].text_input("Search the catalogue (name, ID or tactic)", key=kv(w, "q", t["id"], n, fw))
    results = tm_catalog.search(fw, q, limit=60)
    other = "Other ID (not in local dataset)"
    pick = st.selectbox("Entry", [e["id"] for e in results] + [other], format_func=lambda i: i if i == other else f"{i} \u00b7 {tm_catalog.official_name(fw, i)}", key=kv(w, "pick", t["id"], n, fw))
    tr_ = m.get_tree(w, t["id"])
    leaf_ids = [x_["id"] for x_ in (tr_["nodes"] if tr_ else []) if x_["type"] == "leaf"]
    with st.form(kv(w, "mapf", t["id"], n, fw), clear_on_submit=True):
        sid = st.selectbox("Attack step this mapping explains (optional - recommended)", [""] + leaf_ids, key=kv(w, "msid", t["id"], n, fw),
                           format_func=lambda i: "whole threat" if not i else f"{i} {next(x_['label'] for x_ in tr_['nodes'] if x_['id'] == i)[:50]}")
        ref = st.text_input("Identifier (if 'Other')", disabled=(pick != other), key=kv(w, "oid", t["id"], n, fw)) if pick == other else pick
        lname = st.text_input("Exact official name (only for IDs outside the local dataset - copy from the official site)", key=kv(w, "oname", t["id"], n, fw)) if pick == other else ""
        beh = st.text_input("Specific adversary behaviour / attack pattern in THIS scenario", key=kv(w, "beh", t["id"], n, fw))
        rel = st.selectbox("Relationship to the threat statement", m.RELATIONSHIPS, key=kv(w, "rel", t["id"], n, fw))
        rat = st.text_area("Why does this fit this attack path? (cite the scenario)", height=80, key=kv(w, "rat5", t["id"], n, fw))
        cc = st.columns(2)
        conf = cc[0].selectbox("Confidence", m.CONFIDENCE, index=1, key=kv(w, "cf", t["id"], n, fw))
        evi = cc[1].text_input("Supporting evidence", key=kv(w, "ev5", t["id"], n, fw))
        if st.form_submit_button("Add mapping", type="primary"):
            ok2, _ = attempt(m.add_mapping, w, t["id"], fw, ref, beh, rel, rat, conf, evi, lname, token=token(w, "map" + t["id"]), rerun=False, step_id=sid or None)
            if ok2:
                bump(w, "map" + t["id"])
                st.rerun()
    if dec[fw] == "undecided":
        with st.form(kv(w, "nomap", t["id"], n, fw), clear_on_submit=True):
            why_not = st.text_area(f"Or: no defensible {fw} mapping - why?", height=70, key=kv(w, "nm", t["id"], n, fw))
            if st.form_submit_button(f"Record 'no defensible {fw} mapping'"):
                ok2, _ = attempt(m.add_no_mapping, w, t["id"], fw, why_not, rerun=False)
                if ok2:
                    bump(w, "map" + t["id"])
                    st.rerun()


# ═══════════════════════════════════════════════════════════════════════════════════════
# STEP 6
# ═══════════════════════════════════════════════════════════════════════════════════════
def step6():
    w = ws()
    prof = tm_labs.profile(w["lab_id"])
    frame(6, "How to rate likelihood and impact transparently, and why inherent risk (before controls) is kept separate from residual risk.",
          "Rate each threat on the documented 5x5 model, with a rationale for each rating, the business context and your evidence or uncertainty.",
          "Prioritisation is how limited engineering time is allocated. A defensible rating can be challenged and revised; an unexplained one is just an opinion.",
          "A prioritised inherent-risk register.",
          "Each rating has a stated rationale, the scales are used consistently, and you have said what you are unsure about.")
    if prerequisite_block(6):
        nav(6)
        return
    st.info(f"Expectation for this lab: {prof['expectations']['risk']}")
    with st.expander("Risk model (documented and configurable in tm_model.RISK_MODEL)"):
        st.write(m.RISK_MODEL["method"] + f" Model version {m.RISK_MODEL['version']}.")
        _df([{"Level": k, "Likelihood": v, "Impact": m.RISK_MODEL["impact"][k]} for k, v in m.RISK_MODEL["likelihood"].items()])
        mat = m.risk_matrix()
        _df([{"Likelihood \\ Impact": 5 - i, **{f"I={j + 1}": f"{mat[i][j][0]} {mat[i][j][1]}" for j in range(5)}} for i in range(5)])
        _df([{"Band": b, "Priority": p[0], "Treatment urgency": p[1]} for b, p in m.RISK_MODEL["priority"].items()])
    for t in w["threats"]:
        r = m.get_risk(w, t["id"])
        inh = (r or {}).get("inherent") or {}
        done = bool(inh)
        tick = "\u2705" if done else "\u26AA"
        title = f"{tick} {t['id']} \u2014 {inh.get('band', 'not rated')} {inh.get('score', '')}"
        with st.expander(title + " \u00b7 " + m.statement_text(w, t)[:90], expanded=not done and len(w["threats"]) <= 3):
            st.write(m.statement_text(w, t))
            if r and r.get("stale"):
                st.warning("Stale: " + r["stale"][-1]["reason"])
                note = st.text_input("What did you re-check?", key=kv(w, "rkrev_note", t["id"]))
                if st.button("Mark revalidated", key=kv(w, "rkrev", t["id"])):
                    attempt(m.revalidate, w, "risk", r["id"], note, ok="Risk record revalidated.")
            _validate_steps_ui(w, t)
            with st.form(kv(w, "risk", t["id"], inh.get("rated_on", "new"), inh.get("score", 0))):
                c = st.columns(2)
                l = c[0].slider("Likelihood (1-5)", 1, 5, inh.get("likelihood", 3), help=" | ".join(f"{k}: {v}" for k, v in m.RISK_MODEL["likelihood"].items()))
                lr = c[0].text_area("Likelihood rationale", value=inh.get("likelihood_rationale", ""), height=70)
                i = c[1].slider("Impact (1-5)", 1, 5, inh.get("impact", 3), help=" | ".join(f"{k}: {v}" for k, v in m.RISK_MODEL["impact"].items()))
                ir = c[1].text_area("Impact rationale", value=inh.get("impact_rationale", ""), height=70)
                ctx = st.text_input("Relevant business context", value=inh.get("business_context", ""))
                cc = st.columns(2)
                evi = cc[0].text_input("Evidence", value=inh.get("evidence", ""))
                unc = cc[1].text_input("Uncertainty", value=inh.get("uncertainty", ""))
                st.caption(f"Result: {l} x {i} = {l * i} \u2192 {m.risk_band(l * i)} ({m.RISK_MODEL['priority'][m.risk_band(l * i)][0]})")
                if st.form_submit_button("Save inherent rating", type="primary"):
                    attempt(m.set_inherent_risk, w, t["id"], l, lr, i, ir, ctx, evi, unc, ok=f"{t['id']} rated.")

            def show(rows):
                for x in rows:
                    st.write(f"**{x['ref_id']}** reference rating: likelihood {x['likelihood']}, impact {x['impact']} - {x['why']} (different scale; compare your reasoning, not the labels).")
            ok, why = a.reveal_status(w, "risk_reference", t["id"])
            if ok and done and st.button("Compare with reference reasoning", key=kv(w, "rkref", t["id"])):
                rows = a.get_reference(w, "risk_reference", t["id"])
                save()
                show(rows) if rows else st.caption("No reference threat matches this threat's target and STRIDE category.")
            elif not ok:
                st.caption("\U0001F512 " + why)
    reg = m.prioritised_register(w)
    if reg:
        st.subheader("Prioritised inherent-risk register")
        _df([{"Threat": r["threat_id"], "L": r["inherent"]["likelihood"], "I": r["inherent"]["impact"], "Score": r["inherent"]["score"], "Band": r["inherent"]["band"],
              "Priority": r["inherent"]["priority"], "Urgency": r["inherent"]["urgency"], "Stale": "\u26A0" if r.get("stale") else ""} for r in reg])
    gate_panel(6)
    nav(6)


def _validate_steps_ui(w, t):
    """Step 6: judge each leaf step of the threat's attack tree. These judgements are the evidence for likelihood."""
    tid = t["id"]
    tr = m.get_tree(w, tid)
    if not tr:
        st.caption("No attack tree for this threat (optional in this lab). You can rate it directly, or build a tree in Step 3.")
        return
    lvl = a.assist_level(w, "trees")
    leaves = [n for n in tr["nodes"] if n["type"] == "leaf"]
    st.markdown("**Validate the attack steps** - is each step realistic in THIS system, and how much effort does it take? (1 = trivial ... 5 = very hard)")
    with st.form(kv(w, "stepval", tid, tr["rev"], sum(1 for n in leaves if n["status"] != "unassessed"))):
        vals = {}
        for n in leaves:
            c = st.columns([3, 2, 2, 4])
            c[0].write(f"`{n['id']}` {n['label']}" + (f"  \n*template hint: effort {n['hint_difficulty']}*" if lvl == "full" and n["hint_difficulty"] else ""))
            stt = c[1].selectbox("Judgement", m.STEP_STATUS, index=m.STEP_STATUS.index(n["status"]), key=kv(w, "vs", n["id"], n["status"]))
            dif = c[2].slider("Effort", 1, 5, n["difficulty"] or 3, key=kv(w, "vd", n["id"], n["status"]))
            rat = c[3].text_input("Why (facts about this system)", value=n["rationale"], key=kv(w, "vr", n["id"], n["status"]))
            vals[n["id"]] = (stt, dif, rat, n)
        if st.form_submit_button("Save step validations", type="primary"):
            errors = []
            for sid, (stt, dif, rat, n) in vals.items():
                if stt == "unassessed" or (stt == n["status"] and rat == n["rationale"] and (stt == "implausible" or dif == n["difficulty"])):
                    continue
                try:
                    m.assess_step(w, sid, stt, dif if stt == "plausible" else None, rat)
                    a.note_attempt(w, "assess_step", True)
                except m.ValidationError as exc:
                    a.note_attempt(w, "assess_step", False)
                    errors += [f"{sid}: {e}" for e in exc.errors]
            save()
            if errors:
                for e in errors:
                    st.error(e)
            else:
                flash("Attack steps saved.")
                st.rerun()
    an = m.tree_analysis(w, tid)
    if an["exists"] and not an["structure_issues"]:
        if an["unassessed"]:
            st.warning(f"{len(an['unassessed'])} step(s) still unassessed - rating unlocks when every step is judged.")
        else:
            e = an["easiest"]
            st.success(f"{len(an['viable'])} viable path(s); {len(an['validated'])} fully validated. " +
                       (f"Easiest path: {' + '.join(e['steps'])} (effort {e['cost']}). Use this as evidence for your likelihood - it does not set the rating." if e else
                        "No viable path: every route is judged implausible. Check that against the threat itself before rating it Low."))


def _paths_table(w, tid):
    an = m.tree_analysis(w, tid)
    if an["exists"] and an["viable"]:
        lab = {n["id"]: n["label"] for n in m.get_tree(w, tid)["nodes"]}
        _df([{"Attack path": " + ".join(f"{i} {lab[i][:30]}" for i in p["steps"]), "Effort": p["cost"], "Control state": {"open": "no control", "planned": "control linked, not verified", "cut": "cut by verified control"}[p["state"]]} for p in an["viable"]])
    return an


# ═══════════════════════════════════════════════════════════════════════════════════════
# STEP 7
# ═══════════════════════════════════════════════════════════════════════════════════════
def step7():
    w = ws()
    prof = tm_labs.profile(w["lab_id"])
    frame(7, "How to turn a threat into a control that can be owned, built and verified - and why 'selected' is not 'implemented' is not 'verified'.",
          "Propose controls yourself first (reference examples unlock afterwards), assign owners, record implementation, then verify with evidence.",
          "Controls that nobody owns or tests give false assurance. Reviewers will ask for the evidence, not the intention.",
          "A prioritised, accountable control plan with verification evidence.",
          "Each control states the objective it enforces, who owns it, how it will be verified and what it does not cover.")
    if prerequisite_block(7):
        nav(7)
        return
    st.info(f"Expectation for this lab: {prof['expectations']['controls']}")
    cnt = m.control_state_counts(w)
    c = st.columns(5)
    for col, s in zip(c, ["proposed", "planned", "implemented", "verified", "verification_failed"]):
        col.metric(s.replace("_", " ").capitalize(), cnt[s])
    st.caption("Recording or selecting a control never changes a risk rating. Only a VERIFIED control can support a lower residual rating in Step 8.")
    order = [r["threat_id"] for r in m.prioritised_register(w)]
    for tid in order:
        t = m.find(w["threats"], tid)
        r = m.get_risk(w, tid)
        ctl = m.controls_for(w, tid)
        with st.expander(f"{tid} \u00b7 {r['inherent']['band']} ({r['inherent']['score']}) \u00b7 {len(ctl)} control(s) \u2014 {m.statement_text(w, t)[:80]}", expanded=not ctl):
            for cc in ctl:
                _control_card(w, cc)
            an = _paths_table(w, tid)
            tr_ = m.get_tree(w, tid)
            leaf_opts = [x_["id"] for x_ in (tr_["nodes"] if tr_ else []) if x_["type"] == "leaf" and x_["status"] != "implausible"]
            n = nonce(w, "ctl" + tid)
            with st.form(kv(w, "ctladd", tid, n), clear_on_submit=True):
                title = st.text_input("Control title", key=kv(w, "ct", tid, n))
                obj = st.text_area("Objective: which trust assumption or property does it enforce?", height=60, key=kv(w, "co", tid, n))
                imp = st.text_area("Proposed implementation", height=60, key=kv(w, "ci", tid, n))
                c1 = st.columns(3)
                fn = c1[0].selectbox("Function", m.CONTROL_FUNCTIONS, key=kv(w, "cf", tid, n))
                owner = c1[1].text_input("Owner", key=kv(w, "cow", tid, n))
                stt = c1[2].selectbox("Status", ["proposed", "planned"], key=kv(w, "cs", tid, n))
                lab_ = {x_["id"]: x_["label"] for x_ in (tr_["nodes"] if tr_ else [])}
                steps = st.multiselect("Attack steps this control stops (from this threat's tree)", leaf_opts, format_func=lambda i: f"{i} {lab_[i][:50]}", key=kv(w, "csteps", tid, n)) if leaf_opts else []
                c2 = st.columns(2)
                refs = c2[0].text_input("References (OWASP, NIST, cloud guidance - comma separated)", key=kv(w, "cr", tid, n))
                lim = c2[1].text_input("Limitations and dependencies", key=kv(w, "cl", tid, n))
                if st.form_submit_button("Propose control", type="primary"):
                    ok, _ = attempt(m.add_control, w, [tid], title, obj, imp, fn, owner, stt, "", None, [x for x in refs.split(",")], lim, "", token=token(w, "ctl" + tid), rerun=False, step_ids=steps)
                    if ok:
                        bump(w, "ctl" + tid)
                        st.rerun()

            def show(d):
                st.caption(d["note"])
                for x in d["related_reference_threats"]:
                    st.write(f"{x['ref_id']}: " + "; ".join(x["examples"]))
                if d["owasp"]:
                    st.write("OWASP Top 10 (teaching reference): " + "; ".join(d["owasp"]))
            ok, why = a.reveal_status(w, "control_reference", tid)
            if ok:
                if st.button("Show reference controls", key=kv(w, "cref", tid)):
                    show(a.get_reference(w, "control_reference", tid))
                    save()
            else:
                st.caption("\U0001F512 " + why)
    gate_panel(7)
    nav(7)


def _control_card(w, c):
    badge = {"proposed": "\U0001F4A1", "planned": "\U0001F4C5", "implemented": "\U0001F6E0", "verified": "\u2705", "verification_failed": "\u274C", "rejected": "\u26D4"}[c["status"]]
    st.markdown(f"{badge} **{c['id']} {c['title']}** \u00b7 {c['function']} \u00b7 owner: {c['owner'] or '*none*'} \u00b7 status: **{c['status'].replace('_', ' ')}** \u00b7 steps: {', '.join(c.get('step_ids', [])) or 'none linked'}  \nObjective: {c['objective']}  \nImplementation: {c['implementation']}")
    if c.get("verification"):
        v = c["verification"]
        st.write(f"Verification ({v['result']}, {v['date']}): {v['method']} - {v['evidence']}")
    if c.get("stale"):
        st.warning("Stale: " + c["stale"][-1]["reason"])
        note = st.text_input("What did you re-check?", key=kv(w, "crev_note", c["id"]))
        if st.button("Mark revalidated", key=kv(w, "crev", c["id"])):
            attempt(m.revalidate, w, "control", c["id"], note, ok="Control revalidated.")
    if st.checkbox(f"Edit, link steps, verify or delete {c['id']}", key=kv(w, "cedit", c["id"])):   # not an expander: Streamlit forbids nesting
        tids = [t_ for t_ in c["threat_ids"] if m.get_tree(w, t_)]
        opts = [(t_, n_["id"], n_["label"]) for t_ in tids for n_ in m.get_tree(w, t_)["nodes"] if n_["type"] == "leaf"]
        if opts:
            sel_steps = st.multiselect("Attack steps this control stops", [o[1] for o in opts], default=[x_ for x_ in c.get("step_ids", []) if x_ in [o[1] for o in opts]],
                                       format_func=lambda i: f"{i} {next(o[2] for o in opts if o[1] == i)[:50]}", key=kv(w, "csl", c["id"], len(c.get("step_ids", []))))
            if st.button("Save step links", key=kv(w, "cslb", c["id"])):
                attempt(m.set_control_steps, w, c["id"], sel_steps, ok="Control linked to the selected attack steps.")
        with st.form(kv(w, "cupd", c["id"], c["status"], c["owner"])):
            owner = st.text_input("Owner", value=c["owner"])
            lim = st.text_input("Limitations", value=c["limitations"])
            stt = st.selectbox("Set status", [s for s in m.CONTROL_STATUS if s not in ("verified", "verification_failed")], index=[s for s in m.CONTROL_STATUS if s not in ("verified", "verification_failed")].index(c["status"]) if c["status"] in m.CONTROL_STATUS and c["status"] not in ("verified", "verification_failed") else 0)
            if st.form_submit_button("Save"):
                try:
                    m.update_control(w, c["id"], owner=owner, limitations=lim)
                    if stt != c["status"]:
                        m.set_control_status(w, c["id"], stt)
                except m.ValidationError as exc:
                    for e in exc.errors:
                        st.error(e)
                else:
                    save()
                    flash("Control updated.")
                    st.rerun()
        if c["status"] in ("implemented", "verified", "verification_failed"):
            with st.form(kv(w, "cver", c["id"], c["status"])):
                st.markdown("**Verify** - a control is not verified until evidence exists.")
                meth = st.text_input("Verification method", value=(c.get("verification") or {}).get("method", ""))
                evi = st.text_area("Evidence (test result, config export, ticket, log reference)", value=(c.get("verification") or {}).get("evidence", ""), height=60)
                dt = st.date_input("Verification date", value=date.today(), max_value=date.today())
                res = st.radio("Result", ["pass", "fail"], horizontal=True)
                if st.form_submit_button("Record verification"):
                    attempt(m.record_verification, w, c["id"], meth, evi, dt.isoformat(), res, S.get("_sid", ""), ok="Verification recorded.")
        if st.button("Delete control", key=kv(w, "cdel", c["id"])):
            attempt(m.delete_control, w, c["id"], ok="Control deleted.")


# ═══════════════════════════════════════════════════════════════════════════════════════
# STEP 8
# ═══════════════════════════════════════════════════════════════════════════════════════
def step8():
    w = ws()
    prof = tm_labs.profile(w["lab_id"])
    frame(8, "How to reassess a risk after controls - using only what is verified - and how to make an auditable treatment decision.",
          "For each threat, rate residual likelihood and impact, name the remaining attack paths, then record the treatment, accountable owner and justification. Track open questions with owners and due dates.",
          "Decision-makers sign off on residual risk. An acceptance without an owner and a reason is not a decision.",
          "An auditable residual-risk register and outstanding-action list.",
          "Any reduction below inherent cites VERIFIED controls; acceptance names an owner, conditions and (for High/Critical) an escalation.")
    if prerequisite_block(8):
        nav(8)
        return
    st.info(f"Expectation for this lab: {prof['expectations']['residual']}")
    for r in sorted([r for r in w["risks"] if r["inherent"]], key=lambda r: -r["inherent"]["score"]):
        t = m.find(w["threats"], r["threat_id"])
        inh, res, tr = r["inherent"], r.get("residual") or {}, r.get("treatment") or {}
        state = "decided" if tr else "residual assessed" if res else "inherent only"
        with st.expander(f"{r['threat_id']} \u00b7 inherent {inh['band']} {inh['score']} \u2192 residual {res.get('band', '?')} {res.get('score', '')} \u00b7 {state}", expanded=not tr and len(w["risks"]) <= 3):
            st.write(m.statement_text(w, t))
            ctl = m.controls_for(w, t["id"])
            st.write("Linked controls: " + (", ".join(f"{c['id']} ({c['status'].replace('_', ' ')})" for c in ctl) or "none"))
            an8 = _paths_table(w, t["id"])
            if an8["exists"]:
                st.caption("Only paths cut by a VERIFIED control count as reduced. " + (f"Likelihood can only fall if the easiest path ({' + '.join(an8['easiest']['steps'])}) is cut." if an8["easiest"] else ""))
            if r.get("stale"):
                st.warning("Stale: " + r["stale"][-1]["reason"])
                note = st.text_input("What did you re-check?", key=kv(w, "rsrev_note", t["id"]))
                if st.button("Mark revalidated", key=kv(w, "rsrev", t["id"])):
                    attempt(m.revalidate, w, "risk", r["id"], note, ok="Risk record revalidated.")
            st.caption("Defaults equal the inherent rating. Lowering a value requires a VERIFIED control; implemented-but-unverified controls do not count.")
            with st.form(kv(w, "resid", t["id"], res.get("rated_on", "new"), res.get("score", 0))):
                c = st.columns(2)
                l = c[0].slider("Residual likelihood", 1, 5, res.get("likelihood", inh["likelihood"]))
                lr = c[0].text_area("Likelihood rationale", value=res.get("likelihood_rationale", ""), height=60)
                i = c[1].slider("Residual impact", 1, 5, res.get("impact", inh["impact"]))
                ir = c[1].text_area("Impact rationale", value=res.get("impact_rationale", ""), height=60)
                basis = st.multiselect("Controls this assessment relies on", [c_["id"] for c_ in ctl], default=[b for b in res.get("basis_control_ids", []) if m.find(w["controls"], b)],
                                       format_func=lambda cid: f"{cid} ({m.find(w['controls'], cid)['status'].replace('_', ' ')})")
                red = st.text_input("How do those verified controls reduce likelihood/impact, and what do they not cover?", value=res.get("reduction_basis", ""))
                rem = st.text_input("Remaining attack paths", value=res.get("remaining_attack_paths", "") or m.describe_paths(w, t["id"], an8["remaining"]))
                lim = st.text_input("Control limitations", value=res.get("control_limitations", ""))
                evi = st.text_input("Evidence", value=res.get("evidence", ""))
                if st.form_submit_button("Save residual assessment", type="primary"):
                    attempt(m.set_residual_risk, w, t["id"], l, lr, i, ir, basis, rem, lim, red, evi, "", ok="Residual assessment saved.")
            if res:
                with st.form(kv(w, "treat", t["id"], tr.get("decision_date", "new"), res.get("score", 0))):
                    c = st.columns(3)
                    dec = c[0].selectbox("Treatment decision", m.TREATMENTS, index=m.TREATMENTS.index(tr["decision"]) if tr else 0)
                    own = c[1].text_input("Accountable risk owner", value=tr.get("owner", ""))
                    dd = c[2].date_input("Decision date", value=date.fromisoformat(tr["decision_date"]) if tr else date.today())
                    just = st.text_area("Justification", value=tr.get("justification", ""), height=70)
                    c = st.columns(3)
                    cond = c[0].text_input("Acceptance conditions (if accepting)", value=tr.get("acceptance_conditions", ""))
                    esc = c[1].text_input("Escalated to (required to accept High/Critical)", value=tr.get("escalation_to", ""))
                    rb = c[2].text_input("Review-by date YYYY-MM-DD (if accepting)", value=tr.get("review_by", ""))
                    if st.form_submit_button("Record treatment decision", type="primary"):
                        attempt(m.set_treatment, w, t["id"], dec, own, just, dd.isoformat(), cond, esc, rb, ok="Decision recorded.")
    st.subheader("Open questions")
    n = nonce(w, "q8")
    with st.form(kv(w, "q8f", n), clear_on_submit=True):
        q = st.text_input("Question", key=kv(w, "q8t", n))
        c = st.columns(3)
        own = c[0].text_input("Owner", key=kv(w, "q8o", n))
        due = c[1].date_input("Due", value=date.today() + timedelta(days=14), key=kv(w, "q8d", n))
        rel = c[2].multiselect("Related to", [t["id"] for t in w["threats"]] + target_options(w), key=kv(w, "q8r", n))
        blk = st.checkbox("Blocks sign-off", key=kv(w, "q8b", n))
        if st.form_submit_button("Add question"):
            ok, _ = attempt(m.add_question, w, q, own, due.isoformat(), rel, blk, token=token(w, "q8"), rerun=False)
            if ok:
                bump(w, "q8")
                st.rerun()
    for q in w["questions"]:
        with st.expander(f"{q['id']} \u00b7 {q['status']} \u00b7 {q['text'][:80]}"):
            with st.form(kv(w, "q8u", q["id"], q["status"])):
                c = st.columns(3)
                own = c[0].text_input("Owner", value=q["owner"])
                due = c[1].text_input("Due (YYYY-MM-DD)", value=q["due"])
                stt = c[2].selectbox("Status", ["open", "closed"], index=0 if q["status"] == "open" else 1)
                ans = st.text_area("Answer / outcome", value=q["answer"], height=60)
                if st.form_submit_button("Update"):
                    attempt(m.update_question, w, q["id"], owner=own, due=due, status=stt, answer=ans, ok="Question updated.")
            if st.button("Delete", key=kv(w, "q8del", q["id"])):
                m.delete_question(w, q["id"])
                save()
                st.rerun()
    if w["lab_id"] == "4":
        def show(rows):
            st.caption("Keyword matching against your questions and assumptions - a prompt for the instructor, not a grade.")
            _df([{"Topic the brief omitted": r["topic"], "Status": r["status"]} for r in rows])
        discover_panel(w, "8", "Before comparing with the instructor's gap list: what are the three biggest things you still do not know?", "gap_feedback", show=show, label_btn="Compare with instructor gap list")
    st.subheader("Inherent vs residual")
    _df([{"Threat": r["threat_id"], "Inherent": f"{r['inherent']['band']} ({r['inherent']['score']})", "Residual": f"{r['residual']['band']} ({r['residual']['score']})" if r.get("residual") else "not assessed",
          "Treatment": (r.get("treatment") or {}).get("decision", ""), "Owner": (r.get("treatment") or {}).get("owner", "")} for r in w["risks"] if r["inherent"]])
    gate_panel(8)
    nav(8)


# ═══════════════════════════════════════════════════════════════════════════════════════
# STEP 9
# ═══════════════════════════════════════════════════════════════════════════════════════
def step9():
    w = ws()
    prof = tm_labs.profile(w["lab_id"])
    frame(9, "How a threat model stays current: owners, cadence, triggers - and how a change to the architecture ripples through threats, mappings, risks and controls.",
          "Complete the review plan, practise a real change (re-modelling exercise), revalidate what it affects, then review the assessment and export your deliverables.",
          "Systems change faster than review meetings. Without triggers and owners the model is out of date within a quarter.",
          "Review plan, version history, final report and machine-readable exports from one data model.",
          "Nothing is stale, every revalidation has a note, and the exports list anything unresolved instead of hiding it.")
    st.info(f"Expectation for this lab: {prof['expectations']['review']}")
    rp = w["review"]
    st.subheader("Review plan")
    with st.form(kv(w, "rev_plan", rp["next_review"], rp["model_owner"])):
        c = st.columns(3)
        own = c[0].text_input("Model owner", value=rp["model_owner"])
        sec = c[1].text_input("Security reviewer", value=rp["security_reviewer"])
        nxt = c[2].date_input("Next review date", value=date.fromisoformat(rp["next_review"]) if m.parse_date(rp["next_review"]) else date.today() + timedelta(days=30))
        cad = st.selectbox("Lightweight review cadence", m.CADENCES, index=m.CADENCES.index(rp["cadence"]) if rp["cadence"] in m.CADENCES else 1)
        full = st.multiselect("Full re-modelling triggers", ["New system or high-risk launch", "Major architecture change", "New trust boundary", "New access to sensitive data or privileged actions",
                                                              "Move to a new hosting platform or region", "Significant incident"] + [x for x in rp["full_triggers"]], default=rp["full_triggers"])
        chg = st.multiselect("Change triggers that require updating the model", ["Scope change", "Architecture change", "Dependency or third-party change", "Identity or authentication change",
                                                                                   "Data-flow change", "Control change or failed verification", "Regulatory change", "Assumption found false"] + [x for x in rp["change_triggers"]], default=rp["change_triggers"])
        c = st.columns(2)
        appr = c[0].text_input("Required approval", value=rp["required_approval"], placeholder="e.g. Security architect sign-off")
        evi = c[1].text_input("Required evidence for an update", value=rp["required_evidence"], placeholder="e.g. updated DFD version + revalidation notes")
        if st.form_submit_button("Save review plan", type="primary"):
            attempt(m.set_review_plan, w, model_owner=own, security_reviewer=sec, next_review=nxt.isoformat(), cadence=cad, full_triggers=list(dict.fromkeys(full)),
                    change_triggers=list(dict.fromkeys(chg)), required_approval=appr, required_evidence=evi, ok="Review plan saved.")
    st.subheader("Re-modelling exercise")
    st.markdown("1. Pick an element or flow and preview what a change would affect.  2. Make a real change in Step 2 (for example a flow's protocol or a boundary member).  "
                "3. Revalidate each flagged record below, with a note.  4. Commit the DFD version and complete the exercise.")
    ids = target_options(w)
    if ids:
        pick = st.selectbox("Preview change impact", [""] + ids, format_func=lambda i: "-" if not i else label(w, i), key=kv(w, "imp_pick"))
        if pick:
            aff = m.impact_analysis(w, pick)
            _df([{"Affected": k, "IDs": ", ".join(v) or "none"} for k, v in aff.items()])
    stale = m.stale_items(w)
    if stale:
        st.warning(f"{len(stale)} record(s) need revalidation. Open the owning step to revalidate each with a note.")
        _df([{"Kind": s["kind"], "ID": s["id"], "Why": s["reasons"][-1], "Where": {"threat": "Step 3", "tree": "Step 3", "cell": "Step 3", "crossing": "Step 4", "boundary_review": "Step 4", "mapping": "Step 5", "risk": "Step 6/8", "control": "Step 7"}.get(s["kind"], "?")} for s in stale])
        st.caption("Quick revalidation: use the same note for all, only when your re-check really was identical.")
        bulk = st.text_input("Revalidation note", key=kv(w, "bulk_note"))
        if st.button("Revalidate all listed records with this note", key=kv(w, "bulk_btn")):
            for s in stale:
                try:
                    m.revalidate(w, s["kind"], s["id"], bulk)
                except m.ValidationError as exc:
                    st.error("; ".join(exc.errors))
                    break
            else:
                save()
                st.rerun()
    with st.form(kv(w, "remodel")):
        sm = st.text_area("Summary: what changed, what it affected, what you decided", value=w["remodel"]["summary"], height=70)
        if st.form_submit_button("Complete re-modelling exercise"):
            attempt(m.complete_remodel_exercise, w, sm, ok="Exercise recorded.")
    st.subheader("Assessment")
    st.caption(a.what_the_rubric_cannot_judge())
    for d in a.rubric(w):
        with st.expander(f"{d['label']} \u2014 {d['level']} ({d['met']}/{d['total']} criteria)"):
            st.caption("Expectation for this lab: " + d["expectation"])
            for cr in d["criteria"]:
                st.write(("\u2705 " if cr["met"] else "\u274C ") + cr["text"])
            if d["reconsider"]:
                st.markdown("**Reconsider:** " + " ".join(d["reconsider"]))
            for fl in d["needs_review"]:
                st.write("\U0001F9D1\u200D\U0001F3EB Needs reviewer: " + fl)
    if w["lab_id"] in ("1", "2", "3", "4") and S.get(kv(w, "cmp")) is None and a.reveal_status(w, "reference_comparison")[0]:
        if st.button("Compare my threats with the reference set (alternatives are valid)", key=kv(w, "cmpbtn")):
            S[kv(w, "cmp")] = True
    if S.get(kv(w, "cmp")):
        data = a.get_reference(w, "reference_comparison")
        save()
        st.caption(data["note"])
        _df([{"Reference": r["ref_id"], "STRIDE": r["stride"], "Reference threat": r["summary"], "Status": r["status"].replace("_", " "), "Guidance": r["guidance"]} for r in data["rows"]])
    else:
        ok, why = a.reveal_status(w, "reference_comparison")
        if not ok:
            st.caption("\U0001F512 Reference comparison: " + why)
    st.subheader("How much help you used")
    from_lib = [t["id"] for t in w["threats"] if t.get("library_ref")]
    st.write(f"Mode: **{w['settings']['assist_mode']}**. Threats started from a library example: {', '.join(from_lib) or 'none'} "
             f"({len(from_lib)} of {len(w['threats'])}). This is reported, not penalised - independence is the goal over time.")
    _df([{"Skill": a.SKILL_LABEL[k], "Clean in a row": w["competence"].get(k, {}).get("streak", 0), "Rejected submissions": w["competence"].get(k, {}).get("errors", 0),
          "Assistance now": a.assist_level(w, k)} for k in a.SKILL_LABEL])
    st.subheader("Deliverables")
    comp = x.completeness(w)
    if comp["complete"]:
        st.success("All nine gates pass. Exports are complete.")
        if w["lab_id"] not in tm_state_completed():
            tm_state_completed().append(w["lab_id"])
            save()
    else:
        st.warning(f"{len(comp['omissions'])} open item(s). You can still export - the exports list every omission.")
    probs = x.check_export_consistency(w)
    if probs:
        st.error("Export consistency problems: " + "; ".join(probs))
    c = st.columns(4)
    c[0].download_button("\u2B07 Threat model (JSON)", x.model_json(w), file_name=f"threat_model_lab{w['lab_id']}.json", mime="application/json", use_container_width=True)
    c[1].download_button("\u2B07 Risk register (CSV)", x.risk_register_csv(w), file_name=f"risk_register_lab{w['lab_id']}.csv", mime="text/csv", use_container_width=True)
    c[2].download_button("\u2B07 Report (Markdown)", x.report_markdown(w), file_name=f"threat_model_report_lab{w['lab_id']}.md", mime="text/markdown", use_container_width=True)
    try:
        c[3].download_button("\u2B07 Report (PDF)", x.report_pdf(w), file_name=f"threat_model_report_lab{w['lab_id']}.pdf", mime="application/pdf", use_container_width=True)
    except Exception as exc:
        c[3].caption(f"PDF unavailable: {exc}")
    st.subheader("Outstanding actions")
    _df([{"Type": o["type"], "Step": o["step"], "Ref": o["ref"], "Owner": o.get("owner", ""), "Action": o["action"]} for o in a.outstanding_actions(w)])
    st.subheader("Version history")
    _df([{"Kind": v["kind"], "Version": v["version"], "When": v["at"], "Note": v["note"]} for v in w["versions"]])
    gate_panel(9)
    nav(9)


def tm_state_completed():
    return S["tm"]["completed_labs"]


def journey():
    w = ws()
    j = tm_journey.journey(w)
    st.header(f"Your journey - Lab {w['lab_id']}: {j['role']}")
    show_flash()
    st.caption(j["purpose"])
    first = j["next"][0]
    st.markdown(f"### \u25B6 Next: {first['headline']}")
    st.info(first["detail"] + (f"\n\nTip: {first['hint']}" if first["hint"] else ""))
    st.caption("Why it matters: " + first["why"])
    for extra in j["next"][1:]:
        st.write(f"Then: {extra['headline']} - {extra['detail']}")
    if first["code"] != "done":
        if st.button(f"\u25B6 Take me to Step {first['step']}", type="primary", key=kv(w, "j_go"), use_container_width=True):
            go(first["step"])
    with st.expander("Lab brief and what you will produce"):
        st.markdown(tm_labs.brief(w["lab_id"]))
        st.markdown("**You will produce:** " + "; ".join(f"{n}. {tm_journey.STEP_ARTEFACT[n]}" for n in range(1, 10)))
    st.markdown("### Where you are")
    cols = st.columns(4)
    icon = {"complete": "\u2705", "in_progress": "\U0001F7E1", "not_started": "\u26AA", "blocked": "\u26D4"}
    for col, ph in zip(cols, j["phases"]):
        with col:
            st.markdown(f"#### {ph['name']}")
            st.caption(ph["tagline"])
            for sp_ in ph["steps"]:
                st.markdown(f"**{icon[sp_['state']]} {sp_['step']}. {sp_['title']}**")
                st.caption(f"{sp_['artefact']} \u2014 {sp_['summary']}" + (f" \u2014 {sp_['blockers']} to resolve" if sp_["state"] != "complete" and sp_["blockers"] else ""))
                if st.button("Open", key=kv(w, "j_open", sp_["step"]), use_container_width=True):
                    go(sp_["step"])
    st.markdown("### How much help you get")
    st.write(f"Mode: **{j['assist']['mode']}**" + (" (locked for this lab)" if j["assist"]["locked"] else " - change it in the sidebar.") +
             " Guided starts you from worked examples; fading removes help skill by skill as your submissions are accepted first time; independent gives references only after your own attempt.")
    _df([{"Skill": a.SKILL_LABEL[k], "Assistance now": v, "Clean in a row": j["assist"]["competence"].get(k, {}).get("streak", 0)} for k, v in j["assist"]["levels"].items()])
    st.markdown("### Your shared model")
    if m.elements(w):
        try:
            st.graphviz_chart(x.dfd_dot(w), use_container_width=True)
        except Exception as exc:
            st.caption(f"Diagram could not be drawn ({exc}).")
    rows = tm_journey.register_rows(w)
    if rows:
        _df(rows)
    else:
        st.caption("Your threat register will appear here once you record threats in Step 3.")


PAGES = {0: journey, 1: step1, 2: step2, 3: step3, 4: step4, 5: step5, 6: step6, 7: step7, 8: step8, 9: step9}
