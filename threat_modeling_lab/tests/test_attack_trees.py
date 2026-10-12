import unittest
from datetime import date

import support as sp
import tm_assess as a
import tm_export as x
import tm_journey
import tm_labs
import tm_library as L
import tm_model as m
from test_methodology import small_ws, threat_kwargs


def threat_ws():
    ws, ee, pr, ds, f1, f2 = small_ws()
    t = m.add_threat(ws, **threat_kwargs([f1]))
    return ws, t, f1


def hand_tree(ws, t):
    """goal(OR): A | B(AND: C, D). Leaves A, C, D."""
    m.create_attack_tree(ws, t, goal="Read orders without being entitled to")
    root = m.get_tree(ws, t)["nodes"][0]["id"]
    A = m.add_step(ws, t, root, "Guess a valid session token directly")
    B = m.add_step(ws, t, root, "Abuse missing object-level authorisation", "and")
    C = m.add_step(ws, t, B, "Obtain any low-privilege login")
    D = m.add_step(ws, t, B, "Substitute another member's identifier")
    return A, B, C, D


def assess(ws, sid, status="plausible", diff=2, why="Judged using facts about this system and its design."):
    m.assess_step(ws, sid, status, diff if status == "plausible" else None, why)


class TreeStructure(unittest.TestCase):
    def test_template_and_scratch_creation_and_duplicates(self):
        ws, t, f1 = threat_ws()
        ids = m.create_attack_tree(ws, t, "AT-03")
        self.assertTrue(all(i.startswith("ST-") for i in ids))
        tr = m.get_tree(ws, t)
        self.assertEqual(len([n for n in tr["nodes"] if n["parent"] is None]), 1)
        self.assertEqual(tr["nodes"][0]["logic"], "and")
        with self.assertRaises(m.DuplicateError):
            m.create_attack_tree(ws, t, "AT-01")
        self.assertEqual(len(m.get_tree(ws, t)["nodes"]), len(ids))
        with self.assertRaises(m.ValidationError):
            m.create_attack_tree(ws, "THR-999", "AT-01")
        self.assertEqual(a.integrity_issues(ws), [])

    def test_step_rules(self):
        ws, t, f1 = threat_ws()
        A, B, C, D = hand_tree(ws, t)
        with self.assertRaises(m.ValidationError):
            m.add_step(ws, t, A, "Sub-step under a leaf step")
        with self.assertRaises(m.DuplicateError):
            m.add_step(ws, t, B, "obtain any LOW-privilege login")
        with self.assertRaises(m.ValidationError):
            m.delete_step(ws, m.get_tree(ws, t)["nodes"][0]["id"])
        with self.assertRaises(m.ValidationError):
            assess(ws, B)
        with self.assertRaises(m.ValidationError):
            m.assess_step(ws, A, "plausible", None, "A reason that is long enough here")
        with self.assertRaises(m.ValidationError):
            m.assess_step(ws, A, "plausible", 3, "short")

    def test_deleting_a_step_unlinks_controls_and_mappings(self):
        ws, t, f1 = threat_ws()
        A, B, C, D = hand_tree(ws, t)
        cid = m.add_control(ws, [t], "Object-level checks", "Enforce authorisation per object.", "Check ownership of the record in the service.", "preventive", owner="Eng", step_ids=[D])
        mid = m.add_mapping(ws, t, "CAPEC", "CAPEC-1", "Substituting identifiers to reach functionality the ACL should block", m.RELATIONSHIPS[0],
                            "The profile endpoint accepts any identifier once the caller is logged in, so another member's record is reachable.", "Medium", step_id=D)
        gone = m.delete_step(ws, B)
        self.assertEqual(sorted(gone), sorted([B, C, D]))
        self.assertEqual(m.find(ws["controls"], cid)["step_ids"], [])
        self.assertEqual(m.find(ws["mappings"], mid)["step_id"], "")
        self.assertTrue(m.find(ws["mappings"], mid)["stale"])
        self.assertTrue(m.find(ws["controls"], cid)["status"] == "proposed")
        self.assertEqual(a.integrity_issues(ws), [])
        self.assertTrue(set(gone) <= set(ws["deleted_ids"]))

    def test_foreign_or_nonleaf_step_links_rejected(self):
        ws, t, f1 = threat_ws()
        A, B, C, D = hand_tree(ws, t)
        with self.assertRaises(m.ValidationError):
            m.add_control(ws, [t], "Control", "Enforce authorisation per object.", "Check ownership of the record in the service.", "preventive", step_ids=[B])
        with self.assertRaises(m.ValidationError):
            m.add_control(ws, [t], "Control", "Enforce authorisation per object.", "Check ownership of the record in the service.", "preventive", step_ids=["ST-999"])
        with self.assertRaises(m.ValidationError):
            m.add_mapping(ws, t, "CAPEC", "CAPEC-1", "Substituting identifiers to reach functionality", m.RELATIONSHIPS[0], "r" * 60, "Low", step_id="ST-999")


class PathAnalysis(unittest.TestCase):
    def setUp(self):
        self.ws, self.t, self.f1 = threat_ws()
        self.A, self.B, self.C, self.D = hand_tree(self.ws, self.t)

    def test_and_or_logic_and_easiest_path(self):
        assess(self.ws, self.A, "plausible", 4)
        assess(self.ws, self.C, "plausible", 1)
        assess(self.ws, self.D, "plausible", 2)
        an = m.tree_analysis(self.ws, self.t)
        self.assertEqual(an["paths_total"], 2)
        self.assertEqual(an["unassessed"], [])
        self.assertEqual(an["easiest"]["steps"], sorted([self.C, self.D]))     # AND path: effort = hardest step = 2
        self.assertEqual(an["easiest"]["cost"], 2)
        self.assertEqual(len(an["viable"]), 2)
        self.assertEqual(len(an["validated"]), 2)

    def test_implausible_leaf_removes_every_path_through_it(self):
        assess(self.ws, self.A, "implausible")
        assess(self.ws, self.C, "plausible", 2)
        assess(self.ws, self.D, "implausible")
        an = m.tree_analysis(self.ws, self.t)
        self.assertEqual(an["viable"], [])
        self.assertIsNone(an["easiest"])

    def test_rating_requires_validated_steps(self):
        with self.assertRaises(m.ValidationError) as c:
            m.set_inherent_risk(self.ws, self.t, 3, "Reachable with moderate effort.", 3, "Moderate regulated data impact.", "ctx", "evidence", "")
        self.assertIn("Validate every attack step", str(c.exception))
        for s in (self.A, self.C, self.D):
            assess(self.ws, s)
        m.set_inherent_risk(self.ws, self.t, 3, "Reachable with moderate effort.", 3, "Moderate regulated data impact.", "ctx", "evidence", "")
        basis = m.get_risk(self.ws, self.t)["inherent"]["attack_path_basis"]
        self.assertEqual(basis["viable_paths"], 2)
        self.assertEqual(basis["easiest_cost"], 2)
        self.assertEqual(m.get_risk(self.ws, self.t)["inherent"]["likelihood"], 3)   # the tree informs; the learner decides

    def test_empty_group_blocks_rating_and_gate(self):
        root = m.get_tree(self.ws, self.t)["nodes"][0]["id"]
        m.add_step(self.ws, self.t, root, "An unfinished group of alternatives", "or")
        with self.assertRaises(m.ValidationError):
            m.set_inherent_risk(self.ws, self.t, 3, "Reachable with moderate effort.", 3, "Moderate regulated data impact.", "ctx", "evidence", "")
        self.assertTrue([b for b in a.gate_stride(self.ws)[0] if b["code"] == "tree.structure"])

    def _rated(self, diffs):
        for s, d in zip((self.A, self.C, self.D), diffs):
            assess(self.ws, s, "plausible", d)
        m.set_inherent_risk(self.ws, self.t, 4, "Known technique on an exposed path.", 4, "Regulated records are affected.", "Regulated", "Design review", "")

    def _control(self, steps, verify=True):
        cid = m.add_control(self.ws, [self.t], "Authorisation checks", "Enforce object-level authorisation.", "Check record ownership in the service.", "preventive", owner="Eng", step_ids=steps)
        if verify:
            m.set_control_status(self.ws, cid, "implemented")
            m.record_verification(self.ws, cid, "Negative test of identifier substitution", "TR-4: substituting another id returned 403 in all cases", date.today().isoformat(), "pass")
        return cid

    def test_path_states_open_planned_cut(self):
        self._rated((4, 1, 2))
        self.assertEqual({tuple(p["steps"]): p["state"] for p in m.tree_analysis(self.ws, self.t)["viable"]}[tuple(sorted([self.C, self.D]))], "open")
        cid = self._control([self.D], verify=False)
        self.assertEqual(m.tree_analysis(self.ws, self.t)["easiest"]["state"], "planned")
        m.set_control_status(self.ws, cid, "implemented")
        self.assertEqual(m.tree_analysis(self.ws, self.t)["easiest"]["state"], "planned")      # implemented is not verified
        m.record_verification(self.ws, cid, "Negative test of identifier substitution", "TR-4: substituting another id returned 403 in all cases", date.today().isoformat(), "pass")
        an = m.tree_analysis(self.ws, self.t)
        self.assertEqual(an["easiest"]["state"], "cut")
        self.assertEqual(len(an["remaining"]), 1)          # path A is still open

    def test_likelihood_cannot_fall_until_the_easiest_path_is_cut(self):
        self._rated((4, 1, 2))
        other = self._control([self.A])                     # verified control, but on the HARDER path
        args = (self.ws, self.t, 2, "A verified control blocks one route.", 4, "Impact is unchanged by any control.", [other],
                "Authenticated insider misuse remains", "Covers token guessing only", "Token guessing blocked by verified control TR-4")
        with self.assertRaises(m.ValidationError) as c:
            m.set_residual_risk(*args)
        self.assertIn("easiest viable attack path", str(c.exception))
        cut = self._control([self.D])
        m.set_residual_risk(self.ws, self.t, 2, "Both viable routes are now cut by verified controls.", 4, "Impact is unchanged by any control.", [other, cut],
                            "Authenticated insider misuse remains", "Covers the tested interfaces only", "Both viable routes cut by verified controls TR-4")
        res = m.get_risk(self.ws, self.t)["residual"]
        self.assertEqual(res["score"], 8)
        self.assertEqual(res["path_basis"]["remaining_paths"], [])
        self.assertEqual(len(res["path_basis"]["cut_paths"]), 2)

    def test_impact_reduction_is_not_tied_to_paths(self):
        self._rated((4, 1, 2))
        cid = self._control([self.A])
        with self.assertRaises(m.ValidationError):          # impact reduction still needs a verified control, and gets one
            m.set_residual_risk(self.ws, self.t, 4, "No verified control on the easiest path.", 3, "Backups limit what can be corrupted.", [], "Easiest path remains open",
                                "None verified", "Backups verified")
        m.set_residual_risk(self.ws, self.t, 4, "The easiest path is still open.", 3, "A verified control limits the data exposed.", [cid], "Easiest path remains open",
                            "Only token guessing is covered", "Verified control limits exposure of records on the guessable route")

    def test_gate_requires_a_control_on_the_easiest_path(self):
        self._rated((4, 1, 2))
        self._control([self.A])
        self.assertTrue([b for b in a.gate_controls(self.ws)[0] if b["code"] == "ctl.path"])
        self._control([self.C])
        self.assertFalse([b for b in a.gate_controls(self.ws)[0] if b["code"] == "ctl.path"])


class StalenessAndLinks(unittest.TestCase):
    def test_changes_flag_the_tree_and_its_dependents(self):
        ws = sp.complete_lab("3")
        tid = ws["threats"][0]["id"]
        flow = [t for t in ws["threats"][0]["targets"]][0]
        f = m.find(m.flows(ws), flow) or m.flows(ws)[0]
        m.update_flow(ws, f["id"], protocol=f["protocol"] + " v3")
        kinds = {s["kind"] for s in m.stale_items(ws)}
        self.assertIn("tree", kinds)
        for s in [s for s in m.stale_items(ws) if s["kind"] == "tree"]:
            m.revalidate(ws, "tree", s["id"], "Re-read the attack steps after the flow change.")
        self.assertEqual([s for s in m.stale_items(ws) if s["kind"] == "tree"], [])

    def test_editing_a_step_flags_ratings_and_linked_controls(self):
        ws = sp.complete_lab("1")
        t = ws["threats"][0]["id"]
        step = [n for n in m.get_tree(ws, t)["nodes"] if n["type"] == "leaf"][0]
        ctl = [c for c in ws["controls"] if step["id"] in c["step_ids"]]
        m.update_step(ws, step["id"], label=step["label"] + " using a different technique")
        self.assertTrue(m.get_risk(ws, t)["stale"])
        for c in ctl:
            self.assertTrue(m.find(ws["controls"], c["id"])["stale"])

    def test_reassessing_a_step_after_rating_flags_the_risk(self):
        ws = sp.complete_lab("1")
        t = ws["threats"][0]["id"]
        leaf = [n for n in m.get_tree(ws, t)["nodes"] if n["type"] == "leaf" and n["status"] == "plausible"][0]
        m.assess_step(ws, leaf["id"], "implausible", None, "New evidence shows this step is blocked by the platform.")
        self.assertTrue(m.get_risk(ws, t)["stale"])
        self.assertFalse(a.lab_complete(ws))

    def test_deleting_a_threat_removes_its_tree(self):
        ws = sp.complete_lab("2")
        t = ws["threats"][0]["id"]
        steps = [n["id"] for n in m.get_tree(ws, t)["nodes"]]
        m.delete_threat(ws, t)
        self.assertIsNone(m.get_tree(ws, t))
        self.assertTrue(set(steps) <= set(ws["deleted_ids"]))
        self.assertEqual([i for i in a.integrity_issues(ws) if i["severity"] == "error" and i["code"] != "control.unlinked"], [])

    def test_integrity_check_finds_dangling_step_links(self):
        ws = sp.complete_lab("1")
        ws["controls"][0]["step_ids"].append("ST-999")
        ws["mappings"][0]["step_id"] = "ST-998"
        codes = {i["code"] for i in a.integrity_issues(ws)}
        self.assertTrue({"control.step", "mapping.step"} <= codes)


class ExportsCarryTheTrees(unittest.TestCase):
    def test_json_register_and_report(self):
        ws = sp.complete_lab("3")
        exp = x.build_model_export(ws)
        self.assertEqual(set(exp["attack_trees"]), {t["id"] for t in ws["threats"]})
        tid = ws["threats"][0]["id"]
        self.assertIn("analysis", exp["attack_trees"][tid])
        self.assertTrue(exp["attack_trees"][tid]["analysis"]["viable"])
        rows = x.risk_register_rows(ws)
        self.assertTrue(all("steps validated" in r["attack_tree"] for r in rows))
        self.assertTrue(all(r["open_attack_paths"] != "" for r in rows))
        md = x.report_markdown(ws)
        self.assertIn(f"Attack tree {tid}", md)
        self.assertIn("attack paths after verified controls", md)
        for c in ws["controls"]:
            for sid in c["step_ids"]:
                self.assertIn(sid, md)
        self.assertEqual(x.check_export_consistency(ws, exp), [])
        exp["controls"][0]["step_ids"] = ["ST-999"]
        self.assertTrue(x.check_export_consistency(ws, exp))
        self.assertIn("digraph", x.tree_dot(ws, tid))

    def test_open_paths_are_reported_not_hidden(self):
        ws = sp.complete_lab("1")
        exp = x.build_model_export(ws)
        open_paths = {u["threat"] for u in exp["unresolved"]["open_attack_paths"]}
        self.assertEqual(open_paths, {t["id"] for t in ws["threats"] if m.tree_analysis(ws, t["id"])["remaining"]})


class AssistanceModes(unittest.TestCase):
    def test_labs_start_in_the_intended_mode(self):
        self.assertEqual([m.new_workspace(l)["settings"]["assist_mode"] for l in "1234"], ["guided", "fading", "fading", "independent"])

    def test_fading_levels_follow_clean_streaks_and_errors_reset(self):
        ws = m.new_workspace("2")
        self.assertEqual(a.assist_level(ws, "threats"), "full")
        for _ in range(2):
            a.note_attempt(ws, "add_threat", True)
        self.assertEqual(a.assist_level(ws, "threats"), "reduced")
        for _ in range(2):
            a.note_attempt(ws, "add_threat", True)
        self.assertEqual(a.assist_level(ws, "threats"), "none")
        a.note_attempt(ws, "add_threat", False)
        self.assertEqual(a.assist_level(ws, "threats"), "full")           # help returns after a rejected submission
        self.assertEqual(a.assist_level(ws, "trees"), "full")             # skills fade independently
        a.note_attempt(ws, "some_other_op", True)                         # unknown ops are ignored
        self.assertEqual(ws["competence"]["threats"]["errors"], 1)

    def test_modes_and_locks(self):
        ws = m.new_workspace("4")
        with self.assertRaises(m.ValidationError):
            a.set_assist_mode(ws, "guided")
        ws1 = m.new_workspace("1")
        a.set_assist_mode(ws1, "independent")
        self.assertTrue(ws1["settings"]["discover_first"])
        a.set_assist_mode(ws1, "guided")
        self.assertFalse(ws1["settings"]["discover_first"])
        with self.assertRaises(m.ValidationError):
            a.set_assist_mode(ws1, "turbo")

    def test_drafts_and_worked_examples_only_at_full_assistance(self):
        ws, ee, pr, ds, f1, f2 = small_ws("2")
        a.set_assist_mode(ws, "guided")
        full = a.get_reference(ws, "library_suggestions", f1)
        self.assertEqual(full["level"], "full")
        self.assertTrue(all("draft" in i and "worked_example" in i for i in full["items"]))
        for _ in range(2):
            a.note_attempt(ws, "add_threat", True)
        a.set_assist_mode(ws, "fading")
        red = a.get_reference(ws, "library_suggestions", f1)
        self.assertEqual(red["level"], "reduced")
        self.assertTrue(all("draft" not in i and "worked_example" not in i and i["reasons"] for i in red["items"]))

    def test_independent_mode_locks_library_until_own_unassisted_work(self):
        ws, ee, pr, ds, f1, f2 = small_ws("2")
        a.set_assist_mode(ws, "independent")
        for kind, ref in (("library_suggestions", f1), ("library_browse", None)):
            with self.assertRaises(m.RevealLocked, msg=kind):
                a.get_reference(ws, kind, ref)
        a.set_hypothesis(ws, "3", "I expect request tampering on the public hop and weak authorisation behind the gateway.")
        with self.assertRaises(m.RevealLocked):
            a.get_reference(ws, "library_suggestions", f1)               # still no threat of their own
        m.add_threat(ws, library_ref={"pattern_id": "TP-04", "assist_level": "full"}, **threat_kwargs([f1]))
        with self.assertRaises(m.RevealLocked):
            a.get_reference(ws, "library_suggestions", f1)               # a threat started from an example is not independent work
        m.add_threat(ws, **threat_kwargs([f2], "I", security_property="Confidentiality", action="read order rows from the database connection without authentication"))
        self.assertTrue(a.get_reference(ws, "library_suggestions", f1)["items"])
        self.assertTrue(a.get_reference(ws, "library_browse")["patterns"])

    def test_tree_templates_need_a_per_threat_sketch_in_independent_mode(self):
        ws, ee, pr, ds, f1, f2 = small_ws("2")
        t = m.add_threat(ws, **threat_kwargs([f1]))
        a.set_assist_mode(ws, "independent")
        with self.assertRaises(m.RevealLocked):
            a.get_reference(ws, "tree_templates", t)
        a.set_hypothesis(ws, f"3:{t}", "Get on the network path, then rewrite the request body before it reaches the API.")
        items = a.get_reference(ws, "tree_templates", t)["items"]
        self.assertTrue(items and all("worked_example" not in i for i in items))

    def test_reveals_are_logged_for_the_report(self):
        ws, ee, pr, ds, f1, f2 = small_ws("2")
        a.get_reference(ws, "library_suggestions", f1)
        self.assertTrue([r for r in ws["reveals"] if r["kind"] == "library_suggestions"])
        exp = x.build_model_export(ws)
        self.assertIn("mode", exp["assistance"])


if __name__ == "__main__":
    unittest.main()
