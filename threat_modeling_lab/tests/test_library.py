import re
import unittest

import support as sp
import tm_catalog as c
import tm_labs
import tm_library as L
import tm_model as m
from test_methodology import small_ws


class LibraryContent(unittest.TestCase):
    def test_sizes_meet_the_brief(self):
        self.assertTrue(10 <= len(L.PATTERNS) <= 15, len(L.PATTERNS))
        self.assertTrue(4 <= len(L.TREES) <= 6, len(L.TREES))

    def test_every_entry_has_conditions_and_a_worked_example(self):
        for p in L.PATTERNS:
            self.assertTrue(len(p["applies_when"]) > 30 and len(p["not_applicable_when"]) > 30, p["id"])
            ex = p["worked_example"]
            self.assertTrue(ex["statement"].startswith("Given ") and "could" in ex["statement"] and "resulting in" in ex["statement"], p["id"])
            self.assertTrue(ex["why_it_is_strong"], p["id"])
            self.assertIn("BookSwap", ex["system"])
            self.assertTrue(p["control_themes"] and p["references"], p["id"])
            self.assertIn(p["stride"], m.STRIDE)
            self.assertTrue(set(p["when"].get("any", []) + p["when"].get("all", []) + p["when"].get("none", [])) <= L.TAGS, p["id"])
        for t in L.TREES:
            self.assertTrue(t["applies_when"] and t["not_applicable_when"], t["id"])
            self.assertTrue(t["worked_example"]["assessments"] and t["worked_example"]["outcome"], t["id"])
            self.assertTrue(set(t["when"].get("any", [])) <= L.TAGS, t["id"])

    def test_worked_examples_are_not_lab_answers(self):
        import lab_data
        # multi-word component names ("Payment Service") would hand a learner their answer; single generic words ("Database") are fine
        lab_words = {c_["name"].lower() for lab in "1234" for c_ in lab_data.WORKSHOPS[lab]["scenario"]["components"] if " " in c_["name"].strip()}
        for p in L.PATTERNS:
            for w in lab_words:
                self.assertNotIn(w, p["worked_example"]["statement"].lower(), (p["id"], w))

    def test_stride_coverage_and_cross_references(self):
        self.assertEqual({p["stride"] for p in L.PATTERNS}, set("STRIDE"))
        ids = {p["id"] for p in L.PATTERNS}
        self.assertEqual(len(ids), len(L.PATTERNS))
        for p in L.PATTERNS:
            self.assertTrue(set(p["tree_ids"]) <= set(L.TREE_BY_ID), p["id"])
        for t in L.TREES:
            self.assertTrue(set(t["pattern_ids"]) <= ids and t["pattern_ids"], t["id"])
        self.assertTrue({tid for p in L.PATTERNS for tid in p["tree_ids"]} == set(L.TREE_BY_ID))

    def test_catalogue_ids_exist_in_the_local_dataset(self):
        for p in L.PATTERNS:
            for i in p["attack_ids"]:
                self.assertIsNotNone(c.lookup("ATT&CK", i), (p["id"], i))
            for i in p["capec_ids"]:
                self.assertIsNotNone(c.lookup("CAPEC", i), (p["id"], i))
        for t in L.TREES:
            for n, _ in L.walk(t["root"]):
                for i in n.get("attack_ids", []):
                    self.assertIsNotNone(c.lookup("ATT&CK", i), (n["id"], i))
                for i in n.get("capec_ids", []):
                    self.assertIsNotNone(c.lookup("CAPEC", i), (n["id"], i))

    def test_tree_structure(self):
        for t in L.TREES:
            nodes = [n for n, _ in L.walk(t["root"])]
            ids = [n["id"] for n in nodes]
            self.assertEqual(len(ids), len(set(ids)), t["id"])
            self.assertEqual(t["root"]["type"], "goal")
            leaves = L.tree_leaves(t)
            self.assertTrue(len(leaves) >= 4, t["id"])
            for n in nodes:
                if n["type"] != "leaf":
                    self.assertTrue(n["children"], (t["id"], n["id"]))
            self.assertTrue(sum(1 for n in leaves if n["attack_ids"]) >= len(leaves) * 0.6, t["id"])
            for sid in t["worked_example"]["assessments"]:
                self.assertIn(sid, ids)

    def test_templates_instantiate_with_logic(self):
        flat = L.instantiate_nodes("AT-03")
        self.assertEqual(flat[0]["logic"], "and")          # position AND weakness
        self.assertTrue(all(n["logic"] == "leaf" for n in flat if n["type"] == "leaf"))
        self.assertIsNone(flat[0]["parent_template"])


class ContextualSuggestions(unittest.TestCase):
    def ws(self):
        ws = m.new_workspace("2")
        ee = m.add_element(ws, "external_entity", "Mobile App", "customers' phone app, untrusted device")
        gw = m.add_element(ws, "process", "API Gateway", "REST API entry point with login and token validation")
        db = m.add_element(ws, "datastore", "Accounts DB", "SQL database with customer account data")
        f_http = m.add_flow(ws, ee, gw, "login credentials", "HTTP", classification="Restricted")
        f_tls = m.add_flow(ws, gw, db, "account queries", "mTLS + JDBC", classification="Confidential", authenticated="mutual TLS")
        m.add_boundary(ws, "Internet", "", [ee])
        return ws, ee, gw, db, f_http, f_tls

    def test_suggestions_are_driven_by_the_dfd_and_explain_why(self):
        ws, ee, gw, db, f_http, f_tls = self.ws()
        s = {x["pattern_id"]: x for x in L.suggest_patterns(ws, f_http)}
        self.assertIn("TP-04", s); self.assertIn("TP-08", s); self.assertIn("TP-02", s)
        self.assertTrue(any("does not state encryption" in r for r in s["TP-04"]["reasons"]))
        self.assertTrue(any("crosses a trust boundary" in r for r in s["TP-04"]["reasons"]))
        s2 = {x["pattern_id"] for x in L.suggest_patterns(ws, f_tls)}
        self.assertNotIn("TP-04", s2)                       # states encryption and crosses no boundary
        for x in L.suggest_patterns(ws, f_http):
            self.assertTrue(x["reasons"])

    def test_element_type_filters_patterns(self):
        ws, ee, gw, db, f_http, f_tls = self.ws()
        self.assertTrue(all(L.PATTERN_BY_ID[x["pattern_id"]]["when"]["kinds"].count("datastore") for x in L.suggest_patterns(ws, db)))
        self.assertNotIn("TP-05", {x["pattern_id"] for x in L.suggest_patterns(ws, ee)})
        self.assertIn("TP-05", {x["pattern_id"] for x in L.suggest_patterns(ws, db)})
        self.assertIn("TP-10", {x["pattern_id"] for x in L.suggest_patterns(ws, db)})

    def test_scenario_text_drives_multi_tenant_and_device_patterns(self):
        w1, w3, w4 = sp.complete_lab("1"), sp.complete_lab("3"), sp.complete_lab("4")
        def all_ids(ws):
            return {x["pattern_id"] for t in m.elements(ws) for x in L.suggest_patterns(ws, t["id"], limit=20)}
        self.assertNotIn("TP-14", all_ids(w1))
        self.assertIn("TP-14", all_ids(w3))
        self.assertIn("TP-15", all_ids(w4))

    def test_drafts_fill_every_placeholder_for_every_lab_target(self):
        for lab in tm_labs.LAB_IDS:
            ws = sp.complete_lab(lab)
            for tid in [e["id"] for e in m.elements(ws)] + [f["id"] for f in m.flows(ws)]:
                for it in L.suggest_patterns(ws, tid, limit=20):
                    d = it["draft"]
                    self.assertFalse(re.search(r"\{[a-z]+\}", d["action"] + d["preconditions"] + d["impact"]), (lab, tid, it["pattern_id"]))
                    self.assertEqual(d["targets"], [tid])

    def test_generic_fallback_is_marked_not_specific(self):
        ws = m.new_workspace("1")
        e = m.add_element(ws, "process", "Worker")
        s = L.suggest_patterns(ws, e)
        self.assertTrue(s)
        self.assertTrue(all(x["specific"] or "applies to this element type" in x["reasons"] for x in s))

    def test_tree_suggestions_follow_the_threat_and_context(self):
        ws, ee, gw, db, f_http, f_tls = self.ws()
        ws["scope"]["assets"].append({"id": "AS-001", "name": "Accounts", "sensitivity": "", "note": ""})
        t = m.add_threat(ws, stride="T", source="Adversary with network access", preconditions="traffic crosses an untrusted network segment",
                         action="modify the login request in transit between the app and the gateway", targets=[f_http], security_property="Integrity",
                         impact="altered requests", assets=["Accounts"], evidence="design review", rationale="no integrity protection is described", confidence="Medium")
        names = [x["tree_id"] for x in L.suggest_trees(ws, m.find(ws["threats"], t))]
        self.assertIn("AT-03", names)
        self.assertTrue(all(x["reasons"] for x in L.suggest_trees(ws, m.find(ws["threats"], t))))


if __name__ == "__main__":
    unittest.main()
