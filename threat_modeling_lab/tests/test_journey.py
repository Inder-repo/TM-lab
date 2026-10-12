import unittest

import learner_bot as lb
import support as sp
import tm_assess as a
import tm_export as x
import tm_journey as j
import tm_labs
import tm_model as m


def semantic_duplicates(ws):
    d = []
    names = [m.norm(e["name"]) for e in m.elements(ws)]
    d += ["element:" + n for n in set(names) if names.count(n) > 1]
    fk = [(f["source"], f["destination"], m.norm(f["data"])) for f in m.flows(ws)]
    d += ["flow:%s" % (k,) for k in set(fk) if fk.count(k) > 1]
    tk = [(t["stride"], tuple(sorted(t["targets"])), m.norm(t["action"])) for t in ws["threats"]]
    d += ["threat:%s" % (k,) for k in set(tk) if tk.count(k) > 1]
    mk = [(mp["threat_id"], mp["framework"], mp["ref_id"], mp.get("step_id", "")) for mp in ws["mappings"]]
    d += ["mapping:%s" % (k,) for k in set(mk) if mk.count(k) > 1]
    ids = [r["id"] for c in ("threats", "mappings", "risks", "controls", "questions") for r in ws[c]] + [e["id"] for e in m.elements(ws)] + [f["id"] for f in m.flows(ws)]
    d += ["id:" + i for i in set(ids) if ids.count(i) > 1]
    rk = [r["threat_id"] for r in ws["risks"]]
    d += ["risk:" + i for i in set(rk) if rk.count(i) > 1]
    tr = [(tid, n["parent"], m.norm(n["label"])) for tid, t in ws["attack_trees"].items() for n in t["nodes"]]
    d += ["step:%s" % (k,) for k in set(tr) if tr.count(k) > 1]
    return d


class BaselinePrompts(unittest.TestCase):
    def test_a_new_learner_is_told_exactly_what_to_do_first(self):
        for lab in tm_labs.LAB_IDS:
            ws = m.new_workspace(lab)
            acts = j.next_actions(ws)
            self.assertEqual(acts[0]["step"], 1, lab)
            self.assertTrue(acts[0]["headline"] and acts[0]["detail"] and acts[0]["why"])
            self.assertNotEqual(acts[0]["headline"], "Resolve this item")
            jy = j.journey(ws)
            self.assertEqual([s["step"] for p in jy["phases"] for s in p["steps"]], list(range(1, 10)))
            self.assertEqual([p["name"] for p in jy["phases"]], ["Understand", "Analyse", "Decide", "Sustain"])
            self.assertFalse(jy["complete"])

    def test_prompt_always_points_at_the_earliest_incomplete_step(self):
        ws = sp.complete_lab("2")
        self.assertEqual(j.next_actions(ws)[0]["code"], "done")
        f = m.flows(ws)[0]
        m.update_flow(ws, f["id"], protocol=f["protocol"] + " changed")
        nxt = j.next_actions(ws)[0]
        prog = {p["step"]: p["state"] for p in a.progress(ws)}
        first_incomplete = min(s for s, st in prog.items() if st != "complete")
        self.assertEqual(nxt["step"], first_incomplete)

    def test_hints_fade_with_assistance(self):
        ws = m.new_workspace("2")
        a.set_assist_mode(ws, "guided")
        h_guided = j._hint(ws, "tree.missing")
        a.set_assist_mode(ws, "independent")
        h_indep = j._hint(ws, "tree.missing")
        self.assertTrue(h_guided and not h_indep)

    def test_register_grows_with_the_journey(self):
        ws = m.new_workspace("1")
        self.assertEqual(j.register_rows(ws), [])
        full = sp.complete_lab("1")
        rows = j.register_rows(full)
        self.assertEqual(len(rows), len(full["threats"]))
        for r in rows:
            self.assertIn("steps validated", r["Attack tree"])
            self.assertNotEqual(r["Inherent"], "-")
            self.assertIn("verified", r["Controls"])
            self.assertNotEqual(r["Residual"], "-")
            self.assertTrue(r["Decision"].startswith("mitigate"))


class FullJourneys(unittest.TestCase):
    """Run each of the four scenarios from scope to final report by following only the prompts."""

    def run_lab(self, lab):
        bot = lb.LearnerBot(lab).run()
        ws = bot.ws
        self.assertTrue(a.lab_complete(ws), (lab, bot.trace[-3:]))
        return bot, ws

    def check_end_state(self, bot, ws):
        lab = bot.lab
        steps_seen = {t["step"] for t in bot.trace}
        self.assertEqual(steps_seen & set(range(1, 10)), set(range(1, 10)), "prompts never visited every step: %s" % sorted(steps_seen))
        self.assertEqual(bot.trace[0]["step"], 1)
        self.assertEqual(bot.trace[-1]["code"], "done")
        generic = [t for t in bot.trace if t["code"] != "done" and t["headline"] == "Resolve this item"]
        self.assertEqual(generic, [], "prompts without a specific headline: %s" % {t["code"] for t in generic})
        self.assertTrue([e for e in bot.events if isinstance(e, tuple) and e[0] == "edited threat"])
        self.assertTrue([e for e in bot.events if isinstance(e, tuple) and e[0] == "changed flow"])
        self.assertGreater(len([e for e in bot.events if e == "restored"]), 8)
        self.assertEqual(semantic_duplicates(ws), [])
        self.assertEqual([i for i in a.integrity_issues(ws) if i["severity"] == "error"], [])
        self.assertEqual(m.stale_items(ws), [])
        exp = x.build_model_export(ws)
        self.assertTrue(exp["export_meta"]["completeness"]["complete"])
        self.assertEqual(x.check_export_consistency(ws, exp), [])
        rows = x.risk_register_rows(ws)
        self.assertTrue(rows and all(r["row_status"] == "complete" for r in rows))
        md = x.report_markdown(ws)
        for t in ws["threats"]:
            self.assertIn(t["id"], md)
            self.assertIn("Attack tree " + t["id"], md)
        self.assertTrue(x.report_pdf(ws).startswith(b"%PDF"))
        # every threat is traceable DFD -> threat -> tree -> mapping decision -> rating -> control -> verification -> residual -> decision
        for t in ws["threats"]:
            self.assertTrue(all(m.get_target(ws, i) for i in t["targets"]))
            self.assertTrue(m.get_tree(ws, t["id"]))
            self.assertTrue(all(d != "undecided" for d in m.mapping_decisions(ws, t["id"]).values()))
            r = m.get_risk(ws, t["id"])
            self.assertTrue(r["inherent"]["attack_path_basis"] is not None and r["residual"] and r["treatment"]["owner"])
            ctl = m.controls_for(ws, t["id"])
            self.assertTrue(ctl and all(c["verification"]["evidence"] for c in ctl if c["status"] == "verified"))

    def test_lab1_guided_fundamentals(self):
        bot, ws = self.run_lab("1")
        self.check_end_state(bot, ws)

    def test_lab2_service_architecture(self):
        bot, ws = self.run_lab("2")
        self.check_end_state(bot, ws)

    def test_lab3_multi_tenant(self):
        bot, ws = self.run_lab("3")
        self.check_end_state(bot, ws)
        self.assertTrue(tm_labs.profile("3")["require_attack_trees"])

    def test_lab4_independent(self):
        bot, ws = self.run_lab("4")
        self.check_end_state(bot, ws)
        self.assertEqual(ws["settings"]["assist_mode"], "independent")
        self.assertTrue(ws["settings"]["discover_first"])
        self.assertTrue(any(e["assumed"] for e in m.elements(ws)))

    def test_journey_is_the_same_without_saving_in_between(self):
        a_ = lb.LearnerBot("1", save_every_action=False, interventions=False).run()
        b_ = lb.LearnerBot("1", save_every_action=True, interventions=False).run()
        self.assertEqual(m.canonical_hash({k: v for k, v in a_.ws.items() if k in ("threats", "mappings", "risks", "controls", "attack_trees")}).__len__(), 64)
        self.assertEqual(len(a_.ws["threats"]), len(b_.ws["threats"]))
        self.assertEqual([c["id"] for c in a_.ws["controls"]], [c["id"] for c in b_.ws["controls"]])
        self.assertEqual([t["code"] for t in a_.trace], [t["code"] for t in b_.trace])


class NoDuplicatesOnResubmission(unittest.TestCase):
    def test_replaying_every_kind_of_submission_creates_nothing_new(self):
        ws = sp.complete_lab("3")
        snap = {k: len(ws[k]) for k in ("threats", "mappings", "risks", "controls", "questions")}
        snap.update(el=len(m.elements(ws)), fl=len(m.flows(ws)), tb=len(m.boundaries(ws)), steps=sum(len(t["nodes"]) for t in ws["attack_trees"].values()))
        e, f, t = m.elements(ws)[0], m.flows(ws)[0], ws["threats"][0]
        mp = [x_ for x_ in ws["mappings"]][0]
        with self.assertRaises(m.DuplicateError): m.add_element(ws, e["type"], e["name"])
        with self.assertRaises(m.DuplicateError): m.add_flow(ws, f["source"], f["destination"], f["data"])
        with self.assertRaises(m.DuplicateError): m.add_boundary(ws, m.boundaries(ws)[0]["name"])
        with self.assertRaises(m.DuplicateError): m.add_threat(ws, **{k: t[k] for k in ("stride", "source", "preconditions", "action", "targets", "security_property", "impact", "assets", "evidence", "rationale", "confidence")})
        with self.assertRaises(m.DuplicateError): m.add_no_mapping(ws, mp["threat_id"], mp["framework"], "A second reason for the same decision is refused anyway.")
        with self.assertRaises(m.DuplicateError): m.create_attack_tree(ws, t["id"], "AT-01")
        with self.assertRaises(m.DuplicateError): m.add_question(ws, ws["questions"][0]["text"])
        tk = "tok-1"
        a1 = m.add_element(ws, "process", "Brand new worker", token=tk)
        a2 = m.add_element(ws, "process", "Brand new worker", token=tk)
        self.assertEqual(a1, a2)
        snap["el"] += 1
        after = {k: len(ws[k]) for k in ("threats", "mappings", "risks", "controls", "questions")}
        after.update(el=len(m.elements(ws)), fl=len(m.flows(ws)), tb=len(m.boundaries(ws)), steps=sum(len(t_["nodes"]) for t_ in ws["attack_trees"].values()))
        self.assertEqual(snap, after)
        self.assertEqual(lb.__name__, "learner_bot")

    def test_editing_a_threat_in_place_keeps_its_id_and_creates_no_copy(self):
        ws = sp.complete_lab("2")
        n, t = len(ws["threats"]), ws["threats"][0]
        for i in range(3):
            m.update_threat(ws, t["id"], rationale=t["rationale"] + f" Reviewed again ({i}).")
        self.assertEqual(len(ws["threats"]), n)
        self.assertEqual(ws["threats"][0]["id"], t["id"])
        self.assertEqual(semantic_duplicates(ws), [])


class SaveRestoreMidJourney(unittest.TestCase):
    def test_restoring_at_every_step_boundary_loses_nothing(self):
        bot = lb.LearnerBot("3", save_every_action=True, interventions=False).run()
        self.assertGreater(len([e for e in bot.events if e == "restored"]), 8)
        self.assertTrue(a.lab_complete(bot.ws))

    def test_other_labs_are_untouched_by_work_in_one_lab(self):
        state = m.new_state()
        w1 = m.ensure_workspace(state, "1")
        sp.build_scope(w1, "1")
        h1 = m.canonical_hash(w1)
        w2 = m.ensure_workspace(state, "2")
        sp.build_scope(w2, "2"); sp.build_dfd(w2, "2")
        self.assertEqual(h1, m.canonical_hash(state["workspaces"]["1"]))
        self.assertEqual(m.elements(w1), [])


if __name__ == "__main__":
    unittest.main()
