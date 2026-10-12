import ast
import os
import re
import unittest

import support as sp
import tm_assess as a
import tm_labs
import tm_model as m
from test_methodology import small_ws, threat_kwargs

ROOT = sp.ROOT
EXPECTED = ["Define scope and goals", "Create and validate the DFD", "Apply STRIDE and build threat statements", "Validate trust boundaries",
            "Map MITRE ATT&CK and CAPEC", "Assess inherent risk", "Select and verify controls", "Record residual risk and open questions",
            "Review schedule and deliverables"]


def src(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as f:
        return f.read()


class NineSteps(unittest.TestCase):
    def test_order_and_numbering(self):
        self.assertEqual([n for n, _, _ in a.STEPS], list(range(1, 10)))
        self.assertEqual([t for _, t, _ in a.STEPS], EXPECTED)
        self.assertEqual(sorted(a.GATES), list(range(1, 10)))

    def test_ui_has_exactly_nine_pages_in_order(self):
        tree = ast.parse(src("ui_pages.py"))
        pages = [n for n in ast.walk(tree) if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "PAGES"][0]
        # page 0 is the journey overview (the baseline); pages 1-9 are the nine canonical steps in order
        self.assertEqual([k.value for k in pages.value.keys], list(range(0, 10)))
        self.assertEqual([v.id for v in pages.value.values], ["journey"] + [f"step{i}" for i in range(1, 10)])

    def test_each_page_answers_the_five_questions(self):
        s = src("ui_pages.py")
        self.assertEqual(len(re.findall(r"\bframe\(\d,", s)), 9)
        c = src("ui_common.py")
        for q in ("What am I learning?", "What do I need to do?", "Why does this matter in a real architecture review?", "What artefact must I produce?", "How will I know my reasoning is defensible?"):
            self.assertIn(q.replace("What artefact", "What artefact"), c)

    def test_legacy_duplicate_pages_are_gone(self):
        text = src("workshop23.py") + src("ui_pages.py") + src("ui_common.py")
        for gone in ("Zones of trust", "STRIDE rules", "OWASP mapping", "Identify threats", "Threat actors", "STRIDE mapping",
                     "Assessment & report", "STRIDE_ZONE_RULES", "CRITICALITY_ZONES", "render_architecture_svg", "suggested_residual", "calculate_threat_score"):
            self.assertNotIn(gone, text, "legacy page present: " + gone)
        self.assertEqual(len(re.findall(r"def step\d\(", src("ui_pages.py"))), 9)

    def test_boundary_crossings_are_entered_once(self):
        # flows are only defined in step 2; step 4 stores justifications keyed by (boundary, flow) and cannot add flows
        s4 = src("ui_pages.py").split("def step4")[1].split("def step5")[0] if "def step5" in src("ui_pages.py") else ""
        self.assertNotIn("add_flow", s4)
        self.assertNotIn("add_boundary", s4)


class DiscoverFirstEnforcement(unittest.TestCase):
    def test_locked_labs_refuse_reference_content_until_own_work(self):
        for lab in ("2", "3", "4"):
            ws = m.new_workspace(lab)
            self.assertTrue(ws["settings"]["discover_first"])
            for kind in ("dfd_reference", "stride_suggestions", "attack_tree", "reference_comparison", "gap_feedback"):
                with self.assertRaises(m.RevealLocked, msg=(lab, kind)):
                    a.get_reference(ws, kind)
            with self.assertRaises(m.RevealLocked):
                a.get_reference(ws, "mapping_suggestions", "THR-001")

    def test_dfd_reference_requires_own_elements_and_hypothesis(self):
        ws = m.new_workspace("2")
        m.add_element(ws, "external_entity", "A user")
        m.add_element(ws, "process", "My service")
        with self.assertRaises(m.RevealLocked):
            a.get_reference(ws, "dfd_reference")
        c = m.add_element(ws, "datastore", "My store")
        m.add_flow(ws, m.elements(ws)[1]["id"], c, "data", "TLS")
        with self.assertRaises(m.RevealLocked):                      # still no hypothesis
            a.get_reference(ws, "dfd_reference")
        with self.assertRaises(m.ValidationError):
            a.set_hypothesis(ws, "2", "too short")
        a.set_hypothesis(ws, "2", "I expect a gateway, two services, and two stores with trust changing at the edge.")
        ref = a.get_reference(ws, "dfd_reference")
        self.assertEqual(ref["mode"], "inventory")
        self.assertEqual(ref["model"]["flows"], [])                  # lab 2 gets inventory only
        self.assertTrue(ws["reveals"])                               # reveal is auditable

    def test_seeded_content_does_not_count_as_own_work(self):
        ws = m.new_workspace("1")
        a.set_discover_first(ws, True)
        ref = a.get_reference(ws, "dfd_reference") if False else None
        from tm_labs import reference_model
        m.load_reference_dfd(ws, reference_model("1"))
        a.set_hypothesis(ws, "2", "Hypothesis that is long enough to pass the minimum length check.")
        with self.assertRaises(m.RevealLocked):
            a.get_reference(ws, "dfd_reference")

    def test_threat_suggestions_unlock_after_own_threat(self):
        ws, ee, pr, ds, f1, f2 = small_ws("2")
        a.set_discover_first(ws, True)
        a.set_hypothesis(ws, "3", "The weakest point is the unauthenticated hop between services, followed by logging gaps.")
        with self.assertRaises(m.RevealLocked):
            a.get_reference(ws, "stride_suggestions")
        m.add_threat(ws, **threat_kwargs([f1]))
        self.assertTrue(a.get_reference(ws, "stride_suggestions"))

    def test_controls_and_mappings_and_risk_gated_per_threat(self):
        ws, ee, pr, ds, f1, f2 = small_ws("2")
        t = m.add_threat(ws, **threat_kwargs([f1]))
        for kind in ("mapping_suggestions", "risk_reference", "control_reference"):
            with self.assertRaises(m.RevealLocked, msg=kind):
                a.get_reference(ws, kind, t)
        a.set_hypothesis(ws, f"5:{t}", "The attacker positions on the network path, then rewrites the request body.")
        self.assertIn("attack", a.get_reference(ws, "mapping_suggestions", t))
        m.set_inherent_risk(ws, t, 3, "Realistic with moderate effort on exposed path.", 3, "Moderate regulated-data impact on integrity.", "ctx", "evidence", "")
        a.get_reference(ws, "risk_reference", t)
        m.add_control(ws, [t], "Request signing", "Protect request integrity in transit.", "HMAC-sign the order request at the API.", "preventive")
        self.assertIn("note", a.get_reference(ws, "control_reference", t))

    def test_lab4_discover_first_cannot_be_turned_off(self):
        ws = m.new_workspace("4")
        with self.assertRaises(m.ValidationError):
            a.set_discover_first(ws, False)
        ws1 = m.new_workspace("1")
        self.assertFalse(ws1["settings"]["discover_first"])
        a.set_discover_first(ws1, True)
        self.assertTrue(ws1["settings"]["discover_first"])

    def test_application_code_cannot_bypass_the_gate(self):
        for name in ("workshop23.py", "ui_pages.py", "ui_common.py"):
            tree = ast.parse(src(name))
            for n in ast.walk(tree):
                if isinstance(n, (ast.Import, ast.ImportFrom)):
                    mods = [n.module] if isinstance(n, ast.ImportFrom) else [al.name for al in n.names]
                    for mod in mods:
                        if mod == "lab_data":
                            self.assertEqual({al.name for al in n.names}, {"WORKSHOPS"}, f"{name} imports reference data from lab_data")
            text = src(name)
            for forbidden in ("PREDEFINED_THREATS", "ATTACK_TREES", "OWASP_STRIDE_MAP", "reference_threats(", "reference_model(", "known_gaps("):
                if name == "ui_pages.py" and forbidden == "reference_model(":
                    continue
                self.assertNotIn(forbidden, text, f"{name}:{forbidden}")


class GatesJudgeQuality(unittest.TestCase):
    def test_empty_workspace_reports_accurately(self):
        ws = m.new_workspace("3")
        prog = {p["step"]: p for p in a.progress(ws)}
        self.assertEqual(prog[1]["state"], "not_started")
        self.assertEqual(prog[3]["state"], "blocked")
        self.assertTrue(any("purpose" in b["message"].lower() for b in prog[1]["blockers"]))
        self.assertFalse(a.lab_complete(ws))

    def test_scope_with_weak_content_is_not_complete(self):
        ws = m.new_workspace("3")
        m.set_scope_text(ws, "purpose", "Threat model.")
        self.assertTrue([b for b in a.gate_scope(ws)[0] if b["code"] == "scope.purpose"])

    def test_dfd_gate_reports_incomplete_and_disconnected(self):
        ws = m.new_workspace("3")
        ee = m.add_element(ws, "external_entity", "Partner")
        p = m.add_element(ws, "process", "Svc")
        m.add_element(ws, "datastore", "Orphan store")
        m.add_flow(ws, ee, p, "calls")
        codes = {b["code"] for b in a.gate_dfd(ws)[0]}
        self.assertTrue({"flow.incomplete", "element.disconnected", "dfd.no_boundary", "dfd.version"} <= codes)
        warn = {w["code"] for w in a.gate_dfd(ws)[1]}
        self.assertIn("external.unexplained", warn)

    def test_stride_gate_counts_reasoning_not_threats(self):
        ws, *_ = small_ws()
        self.assertTrue([b for b in a.gate_stride(ws)[0] if b["code"] == "stride.unconsidered"])
        sp.consider_remaining_cells(ws)
        self.assertFalse(a.gate_stride(ws)[0])

    def test_rubric_flags_generic_threats_instead_of_rewarding_quantity(self):
        ws, ee, pr, ds, f1, f2 = small_ws()
        m.add_threat(ws, **threat_kwargs([f1], action="steal data somehow now", preconditions="attacker is present here"))
        d = {x["key"]: x for x in a.rubric(ws)}
        crit = {c["text"]: c["met"] for c in d["statements"]["criteria"]}
        self.assertFalse(crit["Actions are concrete and refer to this system"])
        self.assertTrue(d["statements"]["needs_review"])             # plausibility is flagged for a human
        self.assertLess(d["statements"]["met"], d["statements"]["total"])

    def test_rubric_does_not_require_every_stride_category_or_a_mapping_per_threat(self):
        ws = sp.complete_lab("1")
        self.assertEqual({t["stride"] for t in ws["threats"]} != set(m.STRIDE), True)
        rb = {x["key"]: x for x in a.rubric(ws)}
        self.assertEqual(rb["mappings"]["level"], "Strong")          # all decisions were 'no defensible mapping'
        self.assertTrue(all(x["mappings"] != "mapped" for x in [{"mappings": d} for t in ws["threats"] for d in m.mapping_decisions(ws, t["id"]).values()]))


class AllLabsSameMethodology(unittest.TestCase):
    def test_every_lab_completes_through_the_same_api(self):
        for lab in tm_labs.LAB_IDS:
            ws = sp.complete_lab(lab)
            self.assertTrue(a.lab_complete(ws), (lab, [(p["step"], [b["message"] for b in p["blockers"]]) for p in a.progress(ws) if p["blockers"]]))
            self.assertEqual({x["level"] for x in a.rubric(ws)} - {"Strong", "Proficient"}, set(), lab)

    def test_labs_differ_in_scaffolding_not_in_data_model(self):
        profs = [tm_labs.profile(l) for l in tm_labs.LAB_IDS]
        self.assertEqual([p["scaffold"] for p in profs], ["guided", "reduced", "minimal", "independent"])
        self.assertEqual([p["discover_first_default"] for p in profs], [False, True, True, True])
        self.assertEqual([p["reference_dfd"] for p in profs], ["load", "inventory", "compare", "compare"])
        self.assertEqual([bool(p["worked_example"]) for p in profs], [True, False, False, False])
        self.assertEqual(len({p["role"] for p in profs}), 4)
        keys = {tuple(sorted(m.new_workspace(l).keys())) for l in tm_labs.LAB_IDS}
        self.assertEqual(len(keys), 1)
        self.assertEqual(len({tm_labs.brief(l) for l in tm_labs.LAB_IDS}), 4)
        self.assertEqual(len({tuple(p["expectations"].values()) for p in profs}), 4)

    def test_lab4_brief_is_incomplete_and_gap_feedback_is_not_a_grade(self):
        ws = sp.complete_lab("4")
        fb = a.get_reference(ws, "gap_feedback")
        raised = [g for g in fb if g["status"].startswith("possibly")]
        self.assertTrue(raised)
        self.assertTrue(all("reviewer" in g["status"] for g in raised))
        self.assertTrue(len(tm_labs.known_gaps("4")) >= 6)

    def test_reference_data_issues_are_surfaced_not_hidden(self):
        bad = [(l, r["ref_id"], r["unresolved_targets"]) for l in tm_labs.LAB_IDS for r in tm_labs.reference_threats(l) if r["unresolved_targets"]]
        self.assertTrue(bad)       # S3 Storage, Data Lake, HL7 Interface are not DFD elements in the legacy data
        ws = sp.complete_lab("1")
        a.set_discover_first(ws, False)
        cmp_ = a.get_reference(ws, "reference_comparison")
        self.assertIn("reference_target_not_in_dfd", {r["status"] for r in cmp_["rows"]})


if __name__ == "__main__":
    unittest.main()
