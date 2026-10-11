import unittest
from datetime import date

import support as sp
import tm_assess as a
import tm_catalog
import tm_model as m


def small_ws(lab="1"):
    ws = m.new_workspace(lab)
    sp.build_scope(ws, lab) if False else None
    ee = m.add_element(ws, "external_entity", "Customer", "end user")
    pr = m.add_element(ws, "process", "API", "backend")
    ds = m.add_element(ws, "datastore", "DB", "orders")
    f1 = m.add_flow(ws, ee, pr, "requests", "HTTPS", classification="Confidential")
    f2 = m.add_flow(ws, pr, ds, "queries", "SQL", classification="Restricted")
    m.add_scope_item(ws, "assets", {"name": "Orders", "sensitivity": "High"})
    return ws, ee, pr, ds, f1, f2


def threat_kwargs(targets, stride="T", **over):
    kw = dict(stride=stride, source="Adversary with network access", preconditions="traffic crosses an untrusted network segment",
              action="modify the request body in transit between the client and the API", targets=targets, security_property="Integrity",
              impact="orders are altered", assets=["Orders"], evidence="design review", rationale="no integrity protection is described", confidence="Medium")
    kw.update(over)
    return kw


class StrideApplicability(unittest.TestCase):
    def test_applicability_prompts_per_element_type(self):
        self.assertEqual(m.APPLICABILITY, {"external_entity": "SR", "process": "STRIDE", "datastore": "TRID", "flow": "TID"})

    def test_cells_generated_per_type(self):
        ws, ee, pr, ds, f1, f2 = small_ws()
        cells = m.applicable_cells(ws)
        by = {}
        for t, L in cells:
            by.setdefault(t, "")
            by[t] += L
        self.assertEqual(sorted(by[ee]), sorted("SR"))
        self.assertEqual(sorted(by[pr]), sorted("STRIDE"))
        self.assertEqual(sorted(by[ds]), sorted("TRID"))
        self.assertEqual(sorted(by[f1]), sorted("TID"))

    def test_departure_requires_explanation(self):
        ws, ee, pr, ds, f1, f2 = small_ws()
        with self.assertRaises(m.ValidationError) as c:   # Elevation of privilege on a flow is not a standard prompt
            m.add_threat(ws, **threat_kwargs([f1], "E", security_property="Authorisation"))
        self.assertIn("departure", " ".join(c.exception.errors).lower())
        tid = m.add_threat(ws, **threat_kwargs([f1], "E", security_property="Authorisation",
                                               departure_rationale="A forged role claim in the token body is processed by the receiving service."))
        self.assertTrue(m.departs_from_standard(ws, m.find(ws["threats"], tid)))

    def test_cell_na_needs_a_reason(self):
        ws, ee, *_ = small_ws()
        with self.assertRaises(m.ValidationError):
            m.set_stride_cell(ws, ee, "S", "not_applicable", "N/A")
        m.set_stride_cell(ws, ee, "S", "not_applicable", "Customer identity is established by the IdP outside this scope.")
        self.assertEqual(m.cell_status(ws, ee, "S")["status"], "not_applicable")

    def test_no_fixed_number_of_threats_required(self):
        ws, *_ = small_ws()
        sp.consider_remaining_cells(ws)
        cov = m.stride_coverage(ws)
        self.assertEqual(cov["by_status"]["unconsidered"], 0)
        self.assertEqual(len(ws["threats"]), 0)
        self.assertFalse([b for b in a.gate_stride(ws)[0] if "threat" in b["code"] and b["code"] != "threat.invalid"])


class ThreatStatements(unittest.TestCase):
    def test_must_reference_valid_ids(self):
        ws, ee, pr, ds, f1, f2 = small_ws()
        with self.assertRaises(m.ValidationError):
            m.add_threat(ws, **threat_kwargs(["DF-999"]))
        with self.assertRaises(m.ValidationError):
            m.add_threat(ws, **threat_kwargs([]))

    def test_structured_fields_survive_wording_edit(self):
        ws, ee, pr, ds, f1, f2 = small_ws()
        tid = m.add_threat(ws, **threat_kwargs([f1]))
        t = m.find(ws["threats"], tid)
        gen = m.statement_text(ws, t)
        self.assertTrue(gen.startswith("Given ") and "could" in gen and "resulting in" in gen)
        m.update_threat(ws, tid, statement_override="Edited wording by learner.")
        t = m.find(ws["threats"], tid)
        self.assertEqual(m.statement_text(ws, t), "Edited wording by learner.")
        self.assertEqual(t["source"], "Adversary with network access")
        self.assertIn("Adversary", m.build_statement(ws, t))
        m.reset_statement(ws, tid)
        self.assertEqual(m.statement_text(ws, m.find(ws["threats"], tid)), gen)

    def test_asset_must_come_from_scope(self):
        ws, ee, pr, ds, f1, f2 = small_ws()
        with self.assertRaises(m.ValidationError):
            m.add_threat(ws, **threat_kwargs([f1], assets=["Unlisted asset"]))


class MappingRules(unittest.TestCase):
    def setUp(self):
        self.ws, self.ee, self.pr, self.ds, self.f1, self.f2 = small_ws()
        self.t = m.add_threat(self.ws, **threat_kwargs([self.f1]))

    def test_adding_a_threat_creates_no_mapping(self):
        self.assertEqual(self.ws["mappings"], [])
        self.assertEqual(m.mapping_decisions(self.ws, self.t), {"ATT&CK": "undecided", "CAPEC": "undecided"})

    def test_mapping_needs_scenario_rationale_and_valid_id(self):
        with self.assertRaises(m.ValidationError):
            m.add_mapping(self.ws, self.t, "ATT&CK", "T1557", "AitM on the link", m.RELATIONSHIPS[0], "short", "Medium")
        with self.assertRaises(m.ValidationError):
            m.add_mapping(self.ws, self.t, "ATT&CK", "banana", "behaviour long enough here", m.RELATIONSHIPS[0], "x" * 60, "Medium")
        mid = m.add_mapping(self.ws, self.t, "ATT&CK", "t1557", "Attacker intercepts and alters the Customer to API request on the shared network",
                            m.RELATIONSHIPS[0], "The Customer to API flow crosses a network the attacker controls, so an adversary-in-the-middle position is realistic.", "Medium")
        mp = m.find(self.ws["mappings"], mid)
        self.assertEqual(mp["ref_id"], "T1557")
        self.assertEqual(mp["name"], tm_catalog.ATTACK_BY_ID["T1557"]["name"])
        self.assertTrue(mp["url"].startswith("https://attack.mitre.org/techniques/T1557"))
        self.assertEqual(mp["catalogue_status"], "curated-unverified")   # never presented as verified

    def test_unlisted_id_is_flagged_not_invented(self):
        with self.assertRaises(m.ValidationError):
            m.add_mapping(self.ws, self.t, "CAPEC", "CAPEC-9999", "Some behaviour that is long enough", m.RELATIONSHIPS[0], "r" * 60, "Low")
        mid = m.add_mapping(self.ws, self.t, "CAPEC", "CAPEC-9999", "Some behaviour that is long enough", m.RELATIONSHIPS[0], "r" * 60, "Low",
                            learner_supplied_name="Official Name Copied From Source")
        self.assertEqual(m.find(self.ws["mappings"], mid)["catalogue_status"], "unlisted-pending-verification")
        self.assertTrue([w for w in a.gate_mappings(self.ws)[1] if w["code"] == "map.unlisted"])

    def test_no_defensible_mapping_is_valid_with_reason_only(self):
        with self.assertRaises(m.ValidationError):
            m.add_no_mapping(self.ws, self.t, "CAPEC", "none")
        m.add_no_mapping(self.ws, self.t, "CAPEC", "No catalogued pattern matches this design-level weakness without forcing it.")
        self.assertEqual(m.mapping_decisions(self.ws, self.t)["CAPEC"], "no_defensible_mapping")
        with self.assertRaises(m.DuplicateError):
            m.add_no_mapping(self.ws, self.t, "CAPEC", "A second decision for the same framework is refused.")

    def test_catalogue_statuses_are_honest(self):
        meta = tm_catalog.catalogue_meta()
        self.assertEqual(meta["ATT&CK"]["status"], "curated-unverified")
        self.assertEqual(meta["CAPEC"]["status"], "curated-unverified")


class RiskSeparation(unittest.TestCase):
    def setUp(self):
        self.ws, self.ee, self.pr, self.ds, self.f1, self.f2 = small_ws()
        self.t = m.add_threat(self.ws, **threat_kwargs([self.f1]))
        m.set_inherent_risk(self.ws, self.t, 4, "Known technique on an exposed path.", 4, "Order integrity affects revenue and regulated data.",
                            "Online retailer", "Design review", "")

    def test_scoring_is_transparent_and_validated(self):
        self.assertEqual(m.risk_score(4, 4), 16)
        self.assertEqual(m.risk_band(16), "High")
        self.assertEqual(m.risk_band(17), "Critical")
        with self.assertRaises(m.ValidationError):
            m.risk_score(0, 3)
        with self.assertRaises(m.ValidationError):
            m.risk_score(3, 6)
        with self.assertRaises(m.ValidationError):
            m.set_inherent_risk(self.ws, self.t, 3, "", 3, "", "ctx", "e", "")

    def test_selecting_a_control_never_changes_risk(self):
        before = m.canonical_hash(m.get_risk(self.ws, self.t))
        cid = m.add_control(self.ws, [self.t], "TLS and request signing", "Protect request integrity in transit.", "Enforce TLS 1.2+ and HMAC-sign order requests.", "preventive", owner="Eng lead")
        m.set_control_status(self.ws, cid, "implemented")
        self.assertEqual(before, m.canonical_hash(m.get_risk(self.ws, self.t)))
        self.assertIsNone(m.get_risk(self.ws, self.t)["residual"])

    def test_reduction_requires_a_verified_control(self):
        cid = m.add_control(self.ws, [self.t], "Request signing", "Protect request integrity in transit.", "HMAC-sign order requests at the API.", "preventive", owner="Eng lead")
        args = (self.ws, self.t, 2, "Signing blocks tampering.", 4, "Impact unchanged.", [cid], "Insider misuse remains", "Covers one interface", "Signing verified in test TR-9, tampered bodies rejected")
        with self.assertRaises(m.ValidationError) as c:       # proposed
            m.set_residual_risk(*args)
        self.assertIn("VERIFIED", " ".join(c.exception.errors))
        m.set_control_status(self.ws, cid, "implemented")
        with self.assertRaises(m.ValidationError):            # implemented, unverified
            m.set_residual_risk(*args)
        m.record_verification(self.ws, cid, "Tamper test against API", "TR-9: modified body rejected with 401; log line present", date.today().isoformat(), "pass")
        m.set_residual_risk(*args)
        r = m.get_risk(self.ws, self.t)
        self.assertEqual(r["inherent"]["score"], 16)           # inherent untouched
        self.assertEqual(r["residual"]["score"], 8)
        self.assertNotEqual(r["inherent"], r["residual"])

    def test_failed_verification_cannot_support_reduction(self):
        cid = m.add_control(self.ws, [self.t], "Request signing", "Protect request integrity in transit.", "HMAC-sign order requests at the API.", "preventive", owner="Eng lead")
        m.set_control_status(self.ws, cid, "implemented")
        m.record_verification(self.ws, cid, "Tamper test against API", "TR-10: modified body ACCEPTED - signing not enforced", date.today().isoformat(), "fail")
        self.assertEqual(m.find(self.ws["controls"], cid)["status"], "verification_failed")
        with self.assertRaises(m.ValidationError):
            m.set_residual_risk(self.ws, self.t, 2, "Signing blocks tampering.", 4, "Impact unchanged.", [cid], "x" * 12, "y" * 12, "Explained reduction basis that is long enough")

    def test_residual_equal_to_inherent_needs_no_control(self):
        m.set_residual_risk(self.ws, self.t, 4, "No verified control yet.", 4, "Impact is unchanged by any control.", [], "Original path remains", "No controls verified")
        self.assertEqual(m.get_risk(self.ws, self.t)["residual"]["score"], 16)

    def test_control_verification_gates(self):
        cid = m.add_control(self.ws, [self.t], "Request signing", "Protect request integrity in transit.", "HMAC-sign order requests at the API.", "preventive", owner="Eng lead")
        with self.assertRaises(m.ValidationError):
            m.set_control_status(self.ws, cid, "verified")
        with self.assertRaises(m.ValidationError):   # not implemented yet
            m.record_verification(self.ws, cid, "Tamper test", "evidence that is long enough", date.today().isoformat(), "pass")
        m.set_control_status(self.ws, cid, "implemented")
        with self.assertRaises(m.ValidationError):   # no evidence
            m.record_verification(self.ws, cid, "Tamper test", "", date.today().isoformat(), "pass")
        with self.assertRaises(m.ValidationError):   # future date
            m.record_verification(self.ws, cid, "Tamper test", "evidence that is long enough", "2999-01-01", "pass")


class TreatmentDecisions(unittest.TestCase):
    def setUp(self):
        self.ws, self.ee, self.pr, self.ds, self.f1, self.f2 = small_ws()
        self.t = m.add_threat(self.ws, **threat_kwargs([self.f1]))
        m.set_inherent_risk(self.ws, self.t, 4, "Known technique on an exposed path.", 5, "Safety-relevant records and regulated data.", "Regulated", "Design review", "")
        m.set_residual_risk(self.ws, self.t, 4, "No verified control.", 5, "Impact is unchanged by any control.", [], "Original path remains", "None verified")

    def test_acceptance_needs_owner_and_rationale(self):
        with self.assertRaises(m.ValidationError) as c:
            m.set_treatment(self.ws, self.t, "accept", "", "ok", acceptance_conditions="", review_by="")
        msg = " ".join(c.exception.errors)
        self.assertIn("owner", msg)
        self.assertIn("justification", msg.lower())

    def test_missing_owner_alone_blocks_every_decision_type(self):
        good = dict(justification="A full, explicit justification of the decision taken here.", acceptance_conditions="Revisit on next release",
                    escalation_to="CISO", review_by="2999-01-01")
        for dec in ("accept", "transfer", "avoid"):
            with self.assertRaises(m.ValidationError, msg=dec) as c:
                m.set_treatment(self.ws, self.t, dec, "", **good)
            self.assertIn("accountable risk owner", " ".join(c.exception.errors))
        with self.assertRaises(m.ValidationError):
            m.set_treatment(self.ws, self.t, "accept", "Owner", "too short", acceptance_conditions="Revisit on next release", escalation_to="CISO", review_by="2999-01-01")
        m.set_treatment(self.ws, self.t, "accept", "Owner", **good)

    def test_high_residual_acceptance_needs_escalation(self):
        kw = dict(decision="accept", owner="Head of Engineering", justification="Cost of control exceeds benefit until the next platform migration.",
                  acceptance_conditions="Revisit at migration or on incident", review_by="2999-01-01")
        with self.assertRaises(m.ValidationError) as c:
            m.set_treatment(self.ws, self.t, **kw)
        self.assertIn("escalated", " ".join(c.exception.errors))
        m.set_treatment(self.ws, self.t, escalation_to="CISO", **kw)
        tr = m.get_risk(self.ws, self.t)["treatment"]
        self.assertTrue(tr["escalation_required"])
        self.assertEqual(tr["owner"], "Head of Engineering")

    def test_mitigate_needs_a_control_plan(self):
        with self.assertRaises(m.ValidationError):
            m.set_treatment(self.ws, self.t, "mitigate", "Eng lead", "We will fix this by adding request signing next sprint.")

    def test_treatment_requires_residual_first(self):
        t2 = m.add_threat(self.ws, **threat_kwargs([self.f2], "I", security_property="Confidentiality", action="read order rows from the database connection without authentication"))
        with self.assertRaises(m.ValidationError):
            m.set_treatment(self.ws, t2, "avoid", "Owner", "Remove the feature entirely to remove the exposure.")


class BoundaryRules(unittest.TestCase):
    def test_crossings_computed_once_and_no_threat_created(self):
        ws, ee, pr, ds, f1, f2 = small_ws()
        tb = m.add_boundary(ws, "Internet", "", [ee])
        tb2 = m.add_boundary(ws, "Data tier", "", [ds])
        cs = m.crossings(ws)
        self.assertEqual(sorted((c["boundary_id"], c["flow_id"]) for c in cs), sorted([(tb, f1), (tb2, f2)]))
        self.assertEqual(len(cs), len({(c["boundary_id"], c["flow_id"]) for c in cs}))
        m.set_boundary_review(ws, tb, "Separates the public Internet from our network.", "Callers are no longer trusted to be authentic or well-formed.", ["Identity"], "Authenticate and validate input at the edge.", "Pen-test report and WAF config.")
        m.set_crossing_review(ws, tb, f1, "Caller identity is unproven.", "Session authentication and validation.", "Negative tests.")
        self.assertEqual(ws["threats"], [])      # a boundary is not a threat
        with self.assertRaises(m.ValidationError):
            m.set_crossing_review(ws, tb, f2, "not crossing", "not crossing", "not crossing")

    def test_zone_scores_do_not_drive_stride(self):
        import inspect
        src = inspect.getsource(m)
        self.assertNotIn("STRIDE_ZONE_RULES", src)
        self.assertNotIn("zone_score", src)


if __name__ == "__main__":
    unittest.main()
