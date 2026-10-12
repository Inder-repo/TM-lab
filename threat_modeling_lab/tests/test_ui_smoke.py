"""UI-path tests using an in-memory Streamlit stub (see stub_streamlit.py). These prove the page code
executes and drives the canonical model correctly; they do NOT prove browser rendering or Streamlit
rerun semantics - see tests/test_apptest.py (runs only where Streamlit is installed) and docs/TESTING.md."""
import os
import runpy
import sys
import unittest

import support as sp
import stub_streamlit as stub

st = stub.install()
import tm_model as m  # noqa: E402
import ui_common  # noqa: E402
import ui_pages  # noqa: E402


def fresh(lab="1", complete=False, overrides=None, clicks=None):
    state = m.new_state()
    state["selected_lab"] = lab
    state["workspaces"][lab] = sp.complete_lab(lab) if complete else m.new_workspace(lab)
    st.session_state.clear()
    st.session_state.update({"tm": state, "_loaded": True, "_sid": "uitest" + lab})
    st._overrides.clear(); st._overrides.update(overrides or {})
    st._clicks.clear(); st._clicks.update(clicks or set())
    st._messages.clear(); st._frames.clear(); st._calls.clear()
    return state["workspaces"][lab]


def run(step):
    st._new_run()
    try:
        ui_pages.PAGES[step]()
        return False
    except stub.Rerun:
        return True


class PagesRender(unittest.TestCase):
    def test_every_page_renders_for_every_lab_fresh_and_complete(self):
        for lab in "1234":
            for complete in (False, True):
                fresh(lab, complete)
                for step in range(0, 10):
                    run(step)
        self.assertTrue(True)

    def test_completed_lab_exposes_all_downloads(self):
        fresh("3", complete=True)
        run(9)
        labels = [c[1] for c in st._calls if isinstance(c, tuple)]
        self.assertEqual(sum("Threat model (JSON)" in l or "Risk register (CSV)" in l or "Report (Markdown)" in l or "Report (PDF)" in l for l in labels), 4)
        self.assertIn("3", st.session_state["tm"]["completed_labs"])
        self.assertFalse([msg for k, msg in st._messages if "consistency problems" in msg])


class PagesRenderAtEveryPointOfTheJourney(unittest.TestCase):
    """Real learners live in the in-between states: partial trees, unverified controls, stale items, open questions."""

    def test_every_page_renders_at_every_state_the_bot_passes_through(self):
        import learner_bot as lb
        seen = {"n": 0, "stale": 0, "unassessed": 0, "unverified": 0}

        def render_all(bot):
            ws_ = bot.ws
            st.session_state.clear()
            st.session_state.update({"tm": bot.state, "_loaded": True, "_sid": "bot" + bot.lab})
            st._overrides.clear(); st._clicks.clear()
            seen["n"] += 1
            seen["stale"] += bool(m.stale_items(ws_))
            seen["unassessed"] += any(n["status"] == "unassessed" for t in ws_["attack_trees"].values() for n in t["nodes"] if n["type"] == "leaf")
            seen["unverified"] += any(c["status"] in ("proposed", "planned", "implemented") for c in ws_["controls"])
            for step in range(0, 10):
                run(step)
        for lab in "1234":
            lb.LearnerBot(lab, on_state=render_all).run()
        self.assertGreaterEqual(seen["n"], 40)
        self.assertGreater(seen["stale"], 0)
        self.assertGreater(seen["unassessed"], 0)


class PartialStatesRender(unittest.TestCase):
    def test_controls_in_every_status_and_partial_trees_render(self):
        from datetime import date
        w = fresh("3", complete=True)
        cs = w["controls"]
        cs[0]["status"], cs[0]["verification"] = "proposed", None
        cs[1]["status"], cs[1]["verification"] = "planned", None
        cs[2]["status"], cs[2]["verification"] = "implemented", None
        extra = m.add_control(w, [w["threats"][0]["id"]], "Failing control", "Enforce authorisation per object.", "Check ownership in the service.", "detective", owner="Eng")
        m.set_control_status(w, extra, "implemented")
        m.record_verification(w, extra, "Negative test", "TR-77: bypass succeeded in staging environment", date.today().isoformat(), "fail")
        leaf = [n for n in m.get_tree(w, w["threats"][0]["id"])["nodes"] if n["type"] == "leaf"][0]
        m.reset_step(w, leaf["id"])
        st._overrides.clear(); st._clicks.clear()
        for step in range(0, 10):
            run(step)
        blob = "\n".join(msg for _, msg in st._messages)
        self.assertIn("verification", blob.lower())


class GuidedJourneyThroughTheUI(unittest.TestCase):
    """Lab 1 (guided): start from a library example, rewrite it, add it, open the suggested attack-tree template and validate its steps -
    all through the page code and widget keys, as a learner clicking in the browser would."""

    def test_library_draft_to_validated_attack_tree(self):
        import tm_library as L
        w = fresh("1")
        sp.build_scope(w, "1"); sp.build_dfd(w, "1"); m.commit_dfd(w, "Initial DFD", "t")
        flow = next(f for f in m.flows(w) if f["protocol"].lower().startswith("http") and "https" not in f["protocol"].lower()) if any(
            f["protocol"].lower().startswith("http") and "https" not in f["protocol"].lower() for f in m.flows(w)) else m.flows(w)[0]
        sugg = [s for s in L.suggest_patterns(w, flow["id"]) if "draft" in s]
        self.assertTrue(sugg)
        pid = sugg[0]["pattern_id"]
        # 1. pick the flow and click "Start from <pattern>"
        st._overrides.update({"1_focus": flow["id"]}); st._clicks.add(f"Start from {pid}")
        self.assertTrue(run(3))
        self.assertIn("1_prefill", st.session_state)
        # 2. next run: the draft fills the builder; the learner adds rationale/evidence and submits
        st._clicks.clear(); st._clicks.add("Add threat")
        st._overrides.update({"1_tb0_rat": "The brief shows no integrity protection on this hop, so tampering is plausible here.",
                              "1_tb0_evi": "Architecture description in the lab brief", "1_tb0_conf": "Medium"})
        st._new_run()
        self.assertTrue(run(3))
        self.assertEqual(len(w["threats"]), 1)
        t = w["threats"][0]
        self.assertEqual(t["library_ref"]["pattern_id"], pid)
        self.assertEqual(t["origin"], "learner")
        self.assertEqual(t["targets"], [flow["id"]])
        self.assertEqual(w["competence"]["threats"]["streak"], 1)
        # 3. open the threat, take the suggested template
        tpl = L.suggest_trees(w, t)[0]["tree_id"]
        st._clicks.clear(); st._overrides.clear()
        st._overrides.update({"1_thr_sel": t["id"]}); st._clicks.add(f"Use template {tpl} (then edit it)")
        st._new_run()
        self.assertTrue(run(3))
        tr = m.get_tree(w, t["id"])
        self.assertEqual(tr["template_id"], tpl)
        # 4. Step 6: validate every leaf through the form
        leaves = [n for n in tr["nodes"] if n["type"] == "leaf"]
        st._clicks.clear(); st._overrides.clear(); st._clicks.add("Save step validations")
        for n in leaves:
            st._overrides[f"1_vs_{n['id']}_unassessed"] = "plausible"
            st._overrides[f"1_vd_{n['id']}_unassessed"] = 3
            st._overrides[f"1_vr_{n['id']}_unassessed"] = "Reachable given the exposure described in the lab brief."
        st._new_run()
        self.assertTrue(run(6))
        an = m.tree_analysis(w, t["id"])
        self.assertEqual(an["unassessed"], [])
        self.assertTrue(an["viable"])
        # 5. the banner now sends the learner on to rating, not back to validation
        st._clicks.clear(); st._overrides.clear(); st._messages.clear(); st._new_run()
        run(6)
        banner = " ".join(msg for k, msg in st._messages if "Next:" in msg)
        self.assertNotIn("Validate the attack steps", banner)


class Interactions(unittest.TestCase):
    def test_add_element_through_the_form_and_no_duplicate_on_rerun(self):
        w = fresh("1", overrides={"1_el_n_0": "Customer", "1_el_t_0": "external_entity", "1_el_desc_0": "end user"}, clicks={"Add element"})
        self.assertTrue(run(2))                       # success triggers st.rerun
        self.assertEqual([e["name"] for e in m.elements(w)], ["Customer"])
        # script reruns with the same click still "pressed" (as when a form is resubmitted): the nonce moved on
        run(2)
        self.assertEqual(len(m.elements(w)), 1)
        self.assertEqual(w["counters"]["EE"], 1)

    def test_validation_errors_are_visible_not_swallowed(self):
        w = fresh("1", clicks={"Add element"})
        run(2)
        self.assertEqual(m.elements(w), [])
        self.assertTrue([k for k, msg in st._messages if k == "error"])

    def test_threat_builder_adds_valid_threat_only(self):
        w = fresh("1")
        ee = m.add_element(w, "external_entity", "Customer", "end user")
        pr = m.add_element(w, "process", "API", "backend")
        fid = m.add_flow(w, ee, pr, "requests", "HTTPS", classification="Confidential")
        m.add_scope_item(w, "assets", {"name": "Orders", "sensitivity": "High"})
        base = "1_tb0_"
        ov = {base + "stride": "T", base + "targets": [fid], base + "srcpick": m.THREAT_SOURCES[3], base + "pre": "traffic crosses an untrusted network segment",
              base + "act": "modify the request body in transit between client and API", base + "assets": ["Orders"], base + "imp": "orders are altered",
              base + "rat": "no integrity protection is described", base + "evi": "design review", base + "conf": "Medium"}
        st._overrides.update(ov)
        st._clicks.add("Add threat")
        self.assertTrue(run(3))
        self.assertEqual(len(w["threats"]), 1)
        self.assertEqual(w["threats"][0]["targets"], [fid])
        run(3)
        self.assertEqual(len(w["threats"]), 1)

    def test_incomplete_threat_is_rejected_with_messages(self):
        w = fresh("1")
        ee = m.add_element(w, "external_entity", "Customer", "end user")
        pr = m.add_element(w, "process", "API", "backend")
        fid = m.add_flow(w, ee, pr, "requests", "HTTPS", classification="Confidential")
        st._overrides.update({"1_tb0_targets": [fid]})
        st._clicks.add("Add threat")
        run(3)
        self.assertEqual(w["threats"], [])
        self.assertTrue(len([1 for k, _ in st._messages if k == "error"]) >= 3)

    def test_editing_a_flow_in_the_ui_flags_downstream(self):
        w = fresh("1", complete=True)
        fid = w["threats"][0]["targets"][0]
        fid = fid if m.find(m.flows(w), fid) else m.flows(w)[0]["id"]
        f = m.find(m.flows(w), fid)
        st._overrides.update({kv: None for kv in ()})
        m.update_flow(w, fid, protocol="HTTP")
        self.assertTrue(m.stale_items(w))
        run(9)
        self.assertTrue([msg for k, msg in st._messages if "need revalidation" in msg])


class LabIsolationAndPersistence(unittest.TestCase):
    def test_switching_labs_keeps_each_workspace(self):
        w1 = fresh("1")
        m.add_element(w1, "process", "Only lab 1")
        ui_common.select_lab("2")
        self.assertEqual(st.session_state["tm"]["selected_lab"], "2")
        self.assertEqual(m.elements(ui_common.ws()), [])
        ui_common.select_lab("1")
        self.assertEqual([e["name"] for e in m.elements(ui_common.ws())], ["Only lab 1"])

    def test_save_and_restore_through_the_app_helpers(self):
        w = fresh("1", complete=True)
        ui_common.save()
        path = ui_common.progress_path(5)
        try:
            self.assertTrue(os.path.exists(path))
            snap = m.canonical_hash(st.session_state["tm"]["workspaces"]["1"])
            keep_sid = st.session_state["_sid"]
            st.session_state.clear(); st.session_state["_sid"] = keep_sid
            ui_common.init_state()
            self.assertEqual(m.canonical_hash(st.session_state["tm"]["workspaces"]["1"]), snap)
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_corrupt_save_is_reported_and_ignored(self):
        fresh("1")
        path = ui_common.progress_path(5)
        try:
            with open(path, "w") as f:
                f.write("{broken")
            keep = st.session_state["_sid"]
            st.session_state.clear(); st.session_state["_sid"] = keep
            ui_common.init_state()
            self.assertIn("could not be read", st.session_state["_load_warning"])
            self.assertEqual(st.session_state["tm"]["workspaces"], {})
        finally:
            os.remove(path)


class DiscoverFirstInTheUI(unittest.TestCase):
    LEAKS = {"2": ["Transaction DB", "User DB", "HTTP/2 + mTLS"], "3": ["Redshift JDBC", "Kafka Consumer", "Kafka protocol"],
             "4": ["Legacy EHR", "Device Data Svc", "Patient DB", "MLLP/HL7v2", "Alert Service"]}

    def test_no_reference_component_names_leak_on_any_page(self):
        for lab, words in self.LEAKS.items():
            fresh(lab)
            for step in range(0, 10):
                run(step)
            blob = "\n".join(msg for _, msg in st._messages) + "\n".join(st._frames)
            for w in words:
                self.assertNotIn(w, blob, f"lab {lab} leaked '{w}'")

    def test_reference_tab_shows_lock_message_and_never_calls_reveal(self):
        w = fresh("2")
        st._clicks.add("Show reference material")
        run(2)
        self.assertTrue([msg for k, msg in st._messages if k == "info" and "Discover-first" in msg])
        self.assertEqual(w["reveals"], [])

    def test_lab1_guided_starter_loads_without_duplicates(self):
        w = fresh("1")
        st._clicks.add("Show reference material")
        run(2)
        self.assertTrue(w["reveals"])
        st._clicks.add("Load into my DFD (existing items are never duplicated)")
        self.assertTrue(run(2))
        n = len(m.elements(w))
        self.assertGreaterEqual(n, 6)
        run(2)
        self.assertEqual(len(m.elements(w)), n)
        m.load_reference_dfd(w, __import__("tm_labs").reference_model("1"))
        self.assertEqual(len(m.elements(w)), n)


class EntryPoint(unittest.TestCase):
    def test_home_page_and_workspace_page_run(self):
        st.session_state.clear(); st._overrides.clear(); st._clicks.clear(); st._messages.clear()
        st.session_state.update({"_sid": "entry1", "_loaded": True, "tm": m.new_state()})
        path = os.path.join(sp.ROOT, "workshop23.py")
        st._new_run()
        with self.assertRaises(stub.Stop):                # home page ends with st.stop()
            runpy.run_path(path, run_name="__main__")
        st._new_run()
        st.session_state["tm"] = m.new_state()
        m.ensure_workspace(st.session_state["tm"], "1")
        st.session_state["tm"]["selected_lab"] = "1"
        runpy.run_path(path, run_name="__main__")
        blob = "\n".join(msg for _, msg in st._messages)
        self.assertIn("Define scope and goals", blob)
        self.assertNotIn("10 stages", blob)


if __name__ == "__main__":
    unittest.main()
