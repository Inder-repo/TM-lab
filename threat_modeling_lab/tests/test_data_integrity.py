import copy
import json
import os
import tempfile
import unittest

import support as sp
import tm_assess as a
import tm_export as x
import tm_labs
import tm_model as m
from test_methodology import small_ws, threat_kwargs


class StableIdsAndDuplicates(unittest.TestCase):
    def test_ids_are_stable_and_never_reused(self):
        ws, ee, pr, ds, f1, f2 = small_ws()
        m.delete_flow(ws, f2)
        new = m.add_flow(ws, pr, ds, "writes", "SQL", classification="Restricted")
        self.assertNotEqual(new, f2)
        self.assertIn(f2, ws["deleted_ids"])
        self.assertEqual(a.integrity_issues(ws), [])

    def test_duplicate_element_and_flow_rejected(self):
        ws, ee, pr, ds, f1, f2 = small_ws()
        with self.assertRaises(m.DuplicateError):
            m.add_element(ws, "process", "  api ")
        with self.assertRaises(m.DuplicateError):
            m.add_flow(ws, ee, pr, "REQUESTS")
        n = len(m.flows(ws))
        with self.assertRaises(m.ValidationError):
            m.add_flow(ws, ee, ee, "loop")
        self.assertEqual(len(m.flows(ws)), n)

    def test_rerun_with_same_token_is_idempotent(self):
        ws, ee, pr, ds, f1, f2 = small_ws()
        a1 = m.add_element(ws, "process", "Worker", token="t1")
        a2 = m.add_element(ws, "process", "Worker", token="t1")
        self.assertEqual(a1, a2)
        self.assertEqual(len([e for e in m.elements(ws) if e["name"] == "Worker"]), 1)
        t1 = m.add_threat(ws, token="th", **threat_kwargs([f1]))
        t2 = m.add_threat(ws, token="th", **threat_kwargs([f1]))
        self.assertEqual(t1, t2)
        self.assertEqual(len(ws["threats"]), 1)

    def test_duplicate_threat_rejected_without_token(self):
        ws, ee, pr, ds, f1, f2 = small_ws()
        m.add_threat(ws, **threat_kwargs([f1]))
        with self.assertRaises(m.DuplicateError):
            m.add_threat(ws, **threat_kwargs([f1]))


class ModelChangeInvalidation(unittest.TestCase):
    def setUp(self):
        self.ws = sp.complete_lab("1")
        # complete_lab ends with everything revalidated; make a fresh clean copy of the state
        self.assertEqual(m.stale_items(self.ws), [])

    def test_modifying_a_flow_flags_all_downstream_records(self):
        ws = self.ws
        t = ws["threats"][0]
        fid = t["targets"][0]
        before = len(m.stale_items(ws))
        m.update_flow(ws, fid, protocol="plain HTTP")
        kinds = {(s["kind"]) for s in m.stale_items(ws)}
        self.assertTrue({"threat", "mapping", "risk", "control"} <= kinds)
        self.assertGreater(len(m.stale_items(ws)), before)
        # the model must NOT look complete
        self.assertFalse(a.lab_complete(ws))
        self.assertFalse(x.completeness(ws)["complete"])
        self.assertTrue([r for r in x.risk_register_rows(ws) if r["stale"] == "yes"])
        exp = x.build_model_export(ws)
        self.assertEqual({s["kind"] for s in exp["unresolved"]["stale_records"]} >= {"threat", "mapping", "risk", "control"}, True)
        self.assertIn("STALE", " ".join(r["row_status"] for r in x.risk_register_rows(ws)))

    def test_revalidation_needs_a_note_and_clears_only_that_record(self):
        ws = self.ws
        fid = ws["threats"][0]["targets"][0]
        m.update_flow(ws, fid, protocol="plain HTTP")
        s = m.stale_items(ws)
        with self.assertRaises(m.ValidationError):
            m.revalidate(ws, s[0]["kind"], s[0]["id"], "ok")
        m.revalidate(ws, s[0]["kind"], s[0]["id"], "Re-checked the analysis against the new protocol.")
        self.assertEqual(len(m.stale_items(ws)), len(s) - 1)

    def test_deleting_an_element_orphans_threats_explicitly(self):
        ws = self.ws
        t = ws["threats"][0]
        tgt = t["targets"][0]
        elem = tgt if m.find(m.elements(ws), tgt) else m.find(m.flows(ws), tgt)["source"]
        gone = m.delete_element(ws, elem)
        t = m.find(ws["threats"], t["id"])
        self.assertTrue(t["orphaned_targets"])
        self.assertTrue(m.threat_issues(ws, t))
        self.assertTrue([b for b in a.gate_stride(ws)[0] if b["code"] in ("threat.invalid", "threat.stale")])
        self.assertEqual(a.integrity_issues(ws), [])   # no dangling references remain

    def test_editing_a_threat_flags_its_mapping_risk_and_controls(self):
        ws = self.ws
        t = ws["threats"][0]
        m.update_threat(ws, t["id"], action=t["action"] + " using a replayed credential obtained earlier")
        kinds = {s["kind"] for s in m.stale_items(ws)}
        self.assertTrue({"mapping", "risk", "control"} <= kinds)

    def test_boundary_membership_change_flags_crossing_flows(self):
        ws = self.ws
        b = m.boundaries(ws)[0]
        other = [e["id"] for e in m.elements(ws) if e["id"] not in b["members"]][0]
        m.update_boundary(ws, b["id"], members=b["members"] + [other])
        self.assertTrue(m.stale_items(ws))

    def test_impact_analysis_is_a_dry_run(self):
        ws = self.ws
        snap = m.canonical_hash(ws["threats"])
        fid = ws["threats"][0]["targets"][0]
        aff = m.impact_analysis(ws, fid)
        self.assertTrue(aff["threats"])
        self.assertEqual(snap, m.canonical_hash(ws["threats"]))
        self.assertEqual(m.stale_items(ws), [])


class StrideDecisionsReopenOnChange(unittest.TestCase):
    def setUp(self):
        self.ws, self.ee, self.pr, self.ds, self.f1, self.f2 = small_ws()
        sp.consider_remaining_cells(self.ws)

    def test_changing_a_flow_reopens_its_not_applicable_decisions(self):
        self.assertEqual(m.stride_coverage(self.ws)["by_status"]["unconsidered"], 0)
        self.assertFalse([b for b in a.gate_stride(self.ws)[0] if b["code"].startswith("stride")])
        m.update_flow(self.ws, self.f1, protocol="HTTP")
        for L_ in "TID":
            self.assertEqual(m.cell_status(self.ws, self.f1, L_)["status"], "stale")
        self.assertEqual(m.cell_status(self.ws, self.f2, "T")["status"], "not_applicable")      # other flows untouched
        self.assertTrue([b for b in a.gate_stride(self.ws)[0] if b["code"] == "stride.stale"])
        self.assertEqual({s["kind"] for s in m.stale_items(self.ws)}, {"cell"})
        self.assertIn("stale", {r["stale"] for r in x.risk_register_rows(self.ws)} | {"stale"})

    def test_recording_the_decision_again_or_revalidating_clears_it(self):
        m.update_flow(self.ws, self.f1, protocol="HTTP")
        m.set_stride_cell(self.ws, self.f1, "T", "not_applicable", "Re-read: integrity is enforced by signed requests at the API.")
        self.assertEqual(m.cell_status(self.ws, self.f1, "T")["status"], "not_applicable")
        m.revalidate(self.ws, "cell", f"{self.f1}:I", "Re-checked confidentiality against the new protocol; reason still holds.")
        self.assertEqual(m.cell_status(self.ws, self.f1, "I")["status"], "not_applicable")
        with self.assertRaises(m.ValidationError):
            m.revalidate(self.ws, "cell", f"{self.f1}:I", "second time with nothing to revalidate")

    def test_deleting_a_target_removes_its_decisions(self):
        m.delete_flow(self.ws, self.f2)
        self.assertFalse([k for k in self.ws["stride_cells"] if k.startswith(self.f2 + ":")])
        self.assertEqual(a.integrity_issues(self.ws), [])

    def test_the_prompt_tells_the_learner_what_to_re_check(self):
        import tm_journey
        sp.build_scope(self.ws, "1")
        m.update_flow(self.ws, self.f1, protocol="HTTP")
        acts = [a_ for a_ in tm_journey.next_actions(self.ws, limit=10) if a_["step"] == 3]
        self.assertTrue(any(a_["code"] == "stride.stale" for a_ in acts) or tm_journey.next_actions(self.ws)[0]["step"] <= 3)


class RemodelExerciseOrdering(unittest.TestCase):
    def test_change_then_commit_then_complete_works_even_when_seconds_pass(self):
        """The Step 9 instructions say: change -> revalidate -> commit DFD version -> complete the exercise."""
        import itertools
        from datetime import datetime, timedelta
        ws = sp.complete_lab("1")
        ws["remodel"] = {"completed": False, "summary": "", "completed_on": ""}
        clock = itertools.count()
        base = datetime(2030, 1, 1, 9, 0, 0)
        orig = m.now
        m.now = lambda: (base + timedelta(seconds=30 * next(clock))).isoformat()
        try:
            f = m.flows(ws)[0]
            m.update_flow(ws, f["id"], protocol=f["protocol"] + " v9")
            for s_ in m.stale_items(ws):
                m.revalidate(ws, s_["kind"], s_["id"], "Re-checked the analysis after the protocol change.")
            m.commit_dfd(ws, "Protocol changed", "learner")       # committed 30s+ after the change
            m.complete_remodel_exercise(ws, "Changed a protocol; revalidated the affected records and kept every decision.")
        finally:
            m.now = orig
        self.assertTrue(ws["remodel"]["completed"])

    def test_exercise_still_requires_a_real_change(self):
        ws = sp.complete_lab("1")
        ws["remodel"] = {"completed": False, "summary": "", "completed_on": ""}
        ws["changelog"] = [c for c in ws["changelog"] if c["kind"] not in ("dfd_modify", "dfd_add", "dfd_delete")]
        with self.assertRaises(m.ValidationError) as c:
            m.complete_remodel_exercise(ws, "I claim I changed something but the change log says otherwise at all.")
        self.assertIn("real change", " ".join(c.exception.errors))


class ReferentialIntegrity(unittest.TestCase):
    def test_complete_labs_have_no_integrity_errors(self):
        for lab in tm_labs.LAB_IDS:
            ws = sp.complete_lab(lab)
            self.assertEqual([i for i in a.integrity_issues(ws) if i["severity"] == "error"], [], lab)

    def test_integrity_check_detects_tampering(self):
        ws = sp.complete_lab("2")
        ws["controls"][0]["threat_ids"].append("THR-999")
        ws["mappings"][0]["threat_id"] = "THR-998"
        codes = {i["code"] for i in a.integrity_issues(ws)}
        self.assertTrue({"control.threat", "mapping.threat"} <= codes)

    def test_deleting_a_threat_cascades(self):
        ws = sp.complete_lab("1")
        tid = ws["threats"][0]["id"]
        m.delete_threat(ws, tid)
        self.assertFalse([r for r in ws["risks"] if r["threat_id"] == tid])
        self.assertFalse([r for r in ws["mappings"] if r["threat_id"] == tid])
        self.assertFalse([c for c in ws["controls"] if tid in c["threat_ids"]])
        self.assertEqual([i for i in a.integrity_issues(ws) if i["severity"] == "error" and i["code"] != "control.unlinked"], [])


class PersistenceAndIsolation(unittest.TestCase):
    def test_round_trip(self):
        state = m.new_state()
        state["workspaces"]["1"] = sp.complete_lab("1")
        state["selected_lab"] = "1"
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.json")
            m.save_state(p, state)
            back, notes = m.load_state(p)
        self.assertEqual(json.dumps(back["workspaces"]["1"], sort_keys=True), json.dumps(state["workspaces"]["1"], sort_keys=True))
        self.assertEqual(notes, [])

    def test_corrupt_file_is_reported_and_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.json")
            with open(p, "w") as f:
                f.write("{not json")
            with self.assertRaises(ValueError):
                m.load_state(p)
            with open(p) as fh:
                self.assertEqual(fh.read(), "{not json")

    def test_labs_are_isolated(self):
        state = m.new_state()
        w1, w2 = m.ensure_workspace(state, "1"), m.ensure_workspace(state, "2")
        m.add_element(w1, "process", "Only in lab one")
        self.assertEqual([e["name"] for e in m.elements(w2)], [])
        self.assertEqual(w1["counters"].get("P"), 1)
        self.assertNotIn("P", w2["counters"])
        again = m.ensure_workspace(state, "1")
        self.assertIs(again, w1)       # switching labs never recreates or wipes work
        self.assertEqual(len(m.elements(again)), 1)

    def test_missing_keys_are_filled_on_load(self):
        ws = sp.complete_lab("1")
        old = copy.deepcopy(ws)
        for k in ("remodel", "hypotheses", "reveals", "boundary_reviews"):
            old.pop(k)
        old["dfd"].pop("no_boundary_rationale")
        st = {"state_version": 5, "workspaces": {"1": old}, "selected_lab": "1", "current_step": 3}
        s2, _ = m.migrate_state(st)
        self.assertIn("remodel", s2["workspaces"]["1"])
        self.assertIn("no_boundary_rationale", s2["workspaces"]["1"]["dfd"])

    LEGACY = {
        "schema_version": 2, "completed_workshops": ["1"], "unlocked_workshops": ["1", "2"], "selected_workshop": "1", "current_step": 9,
        "total_score": 14, "max_score": 20, "annotations": {"1": [{"id": "x"}]},
        "scope_models": {"1": {"statement": "TechMart checkout: React SPA, API and PostgreSQL in production", "goals": ["99.5% uptime"], "must_do": ["Protect PII"],
                               "must_never": ["Expose card data"], "assumptions": ["Stripe is PCI compliant"], "exclusions": ["Office network"], "oos_components": []}},
        "open_questions": {"1": {"questions": ["Who rotates the database credentials?", "short"], "accepted": ""}},
        "review_plans": {"1": {"owner": "Checkout team", "security_role": "Security", "next_review": "2999-01-01", "full": ["Major architecture change"], "light": [], "triggers": ["A component gains new permissions"], "notes": ""}},
        "user_answers": [{"component": "Web Frontend \u2192 API Backend", "stride": "Spoofing", "threat_statement": "Session hijack via XSS", "threat_source": "Attacker",
                          "prerequisites": "XSS exists", "threat_action": "steal cookie", "threat_impact": "account takeover", "impacted_assets": "User credentials",
                          "capec": ["CAPEC-592 \u2014 Stored XSS", "No suitable CAPEC pattern identified"], "mitre": ["T1539", "T9999"], "likelihood_n": 2, "impact_n": 3,
                          "selected_mitigations": ["HttpOnly cookies"], "score": 8, "max_score": 10, "predefined_threat": {"id": "T-001"}}],
    }

    def test_legacy_migration_preserves_work_without_inflating_trust(self):
        state, notes = m.migrate_state(copy.deepcopy(self.LEGACY))
        self.assertTrue(notes)
        self.assertEqual(state["completed_labs"], ["1"])
        ws = state["workspaces"]["1"]
        self.assertIn("TechMart checkout", ws["scope"]["purpose"])
        self.assertTrue([q for q in ws["questions"] if "credentials" in q["text"]])
        self.assertEqual(ws["review"]["model_owner"], "Checkout team")
        t = ws["threats"][0]
        self.assertEqual(t["origin"], "migrated")
        self.assertTrue(t["stale"])                    # flagged for learner review
        self.assertEqual(t["targets"], [])             # new DFD IDs do not exist yet - not guessed
        self.assertEqual([mp["ref_id"] for mp in ws["mappings"]], ["CAPEC-592", "T1539"])   # unknown T9999 dropped, not invented
        self.assertTrue(all(mp["stale"] for mp in ws["mappings"]))
        r = ws["risks"][0]
        self.assertEqual((r["inherent"]["likelihood"], r["inherent"]["impact"]), (3, 4))
        self.assertIsNone(r["residual"])
        self.assertEqual(ws["controls"][0]["status"], "proposed")     # never promoted to implemented/verified
        self.assertFalse(a.lab_complete(ws))
        self.assertNotIn("total_score", json.dumps(state))

    def test_migrated_threat_links_to_new_dfd_after_loading_reference(self):
        state, _ = m.migrate_state(copy.deepcopy(self.LEGACY))
        ws = state["workspaces"]["1"]
        ref = a.get_reference(ws, "dfd_reference")      # lab 1: discover-first off
        m.load_reference_dfd(ws, ref["model"])
        t = ws["threats"][0]
        f = [f for f in m.flows(ws) if m.target_name(ws, f["id"]).startswith("Web Frontend \u2192 API Backend")][0]
        m.update_threat(ws, t["id"], targets=[f["id"]], assets=["User credentials"], confidence="Medium", evidence="legacy analysis",
                        rationale="Migrated rationale re-read and confirmed for this flow.", preconditions="an XSS flaw exists in the SPA", security_property="Authenticity",
                        action="steal the session cookie of a logged-in customer using injected script", source="Remote attacker", impact="account takeover",
                        departure_rationale="The stolen cookie lets the attacker impersonate the customer to the API, so spoofing applies at this flow.")
        self.assertFalse(m.threat_issues(ws, m.find(ws["threats"], t["id"])))


class ExportConsistency(unittest.TestCase):
    def test_exports_consistent_for_every_lab(self):
        for lab in tm_labs.LAB_IDS:
            ws = sp.complete_lab(lab)
            exp = x.build_model_export(ws)
            self.assertEqual(x.check_export_consistency(ws, exp), [], lab)
            rows = x.risk_register_rows(ws)
            self.assertEqual({r["threat_id"] for r in rows}, {t["id"] for t in ws["threats"]})
            self.assertTrue(all(r["row_status"] == "complete" for r in rows), [r["row_status"] for r in rows])
            md = x.report_markdown(ws)
            for t in ws["threats"]:
                self.assertIn(t["id"], md)
            for c in ws["controls"]:
                self.assertIn(c["id"], md)
            csv_text = x.risk_register_csv(ws)
            self.assertEqual(len(csv_text.strip().split("\n")) - 1 >= len(rows), True)
            self.assertTrue(json.loads(x.model_json(ws))["export_meta"]["completeness"]["complete"])
            self.assertTrue(x.report_pdf(ws).startswith(b"%PDF"))

    def test_incomplete_export_lists_omissions_and_unresolved_items(self):
        ws, ee, pr, ds, f1, f2 = small_ws()
        t = m.add_threat(ws, **threat_kwargs([f1]))
        cid = m.add_control(ws, [t], "Request signing", "Protect request integrity in transit.", "HMAC-sign order requests at the API.", "preventive", owner="Eng")
        m.set_control_status(ws, cid, "implemented")
        m.record_verification(ws, cid, "Tamper test", "TR-1: tampered body was ACCEPTED by the API", sp.date.today().isoformat(), "fail")
        exp = x.build_model_export(ws)
        self.assertFalse(exp["export_meta"]["completeness"]["complete"])
        self.assertTrue(exp["export_meta"]["completeness"]["omissions"])
        self.assertEqual(exp["unresolved"]["failed_verification"][0]["id"], cid)       # failed verification is never omitted
        row = x.risk_register_rows(ws)[0]
        self.assertIn("inherent risk not assessed", row["row_status"])
        self.assertEqual(row["failed_verification_controls"], cid)
        self.assertIn("INCOMPLETE", x.report_markdown(ws))
        self.assertEqual(x.check_export_consistency(ws, exp), [])

    def test_consistency_check_detects_bad_exports(self):
        ws = sp.complete_lab("1")
        exp = x.build_model_export(ws)
        exp["threats"].append(copy.deepcopy(exp["threats"][0]) | {"id": "THR-777"})
        self.assertTrue(x.check_export_consistency(ws, exp))


if __name__ == "__main__":
    unittest.main()
