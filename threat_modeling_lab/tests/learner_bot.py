"""A simulated learner that completes a lab by FOLLOWING ONLY THE NEXT-ACTION PROMPT.

It reads tm_journey.next_actions(ws)[0] (exactly what the banner/sidebar show), does the work for the step the
prompt points at, saves and restores the workspace after every action (as a browser refresh would), and records a
trace. It also performs two mid-journey interventions a real learner would make:
  * edits a threat after Step 3 was finished,
  * changes a DFD flow after the controls were verified,
and checks that the prompts send it back to revalidate. The bot 'reads the brief' by using the lab's reference
model as its knowledge of the system; the point of the test is the journey, not the DFD content.
"""
import os
import tempfile
from datetime import date

import support as sp
import tm_assess as a
import tm_journey
import tm_labs
import tm_model as m

STALE_CODES = {"stride.stale", "threat.stale", "tree.stale", "map.stale", "risk.stale", "ctl.stale", "res.stale", "tb.stale", "tb.crossing_stale", "rev.stale"}


class JourneyFailure(AssertionError):
    pass


class LearnerBot:
    def __init__(self, lab, save_every_action=True, interventions=True, on_state=None):
        self.on_state = on_state
        self.lab = lab
        self.state = m.new_state()
        self.state["selected_lab"] = lab
        m.ensure_workspace(self.state, lab)
        self.trace, self.events = [], []
        self.save_every_action = save_every_action
        self.interventions = interventions
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "progress.json")
        self._did = set()

    @property
    def ws(self):
        return self.state["workspaces"][self.lab]

    # ── persistence round trip (what a browser refresh does) ────────────────────────────
    def restore(self):
        before = m.canonical_hash(self.state["workspaces"][self.lab])
        m.save_state(self.path, self.state)
        self.state, _ = m.load_state(self.path)
        after = m.canonical_hash(self.state["workspaces"][self.lab])
        if before != after:
            raise JourneyFailure("save/restore changed the workspace")
        self.events.append("restored")

    # ── work for each step, idempotent and guarded ───────────────────────────────────────
    def do_stale(self):
        for s in m.stale_items(self.ws):
            m.revalidate(self.ws, s["kind"], s["id"], "Re-checked this record against the change and the conclusion still holds.")

    def step1(self):
        if not self.ws["scope"]["version"]:
            sp.build_scope(self.ws, self.lab)
        elif m.scope_changed_since_commit(self.ws):
            m.commit_scope(self.ws, "Updated scope", "bot")

    def step2(self):
        ws = self.ws
        if not m.elements(ws):
            sp.build_dfd(ws, self.lab)
        if any(i["severity"] == "error" for i in m.dfd_issues(ws)) and ws["dfd"]["version"]:
            raise JourneyFailure("DFD errors remain after build: " + str([i["message"] for i in m.dfd_issues(ws) if i["severity"] == "error"]))
        m.commit_dfd(ws, "Initial DFD" if not ws["dfd"]["version"] else "DFD updated", "bot")

    def step3(self):
        ws = self.ws
        if not ws["threats"]:
            sp.build_threats(ws, self.lab)
        sp.build_trees(ws)
        sp.consider_remaining_cells(ws)

    def step4(self):
        sp.review_boundaries(self.ws)

    def step5(self):
        ws = self.ws
        for t in ws["threats"]:
            for fw, reason in (("ATT&CK", "The attack path in this scenario is design-level misuse; no specific adversary technique is evidenced."),
                               ("CAPEC", "No catalogued pattern fits the scenario closely enough to map confidently without forcing it.")):
                if m.mapping_decisions(ws, t["id"])[fw] == "undecided":
                    m.add_no_mapping(ws, t["id"], fw, reason)

    def step6(self):
        sp.validate_trees(self.ws)
        sp.rate_risks(self.ws)

    def step7(self):
        ws = self.ws
        sp.propose_and_verify_controls(ws)
        for t in ws["threats"]:                      # link a control to the easiest path if the prompt says so
            an = m.tree_analysis(ws, t["id"])
            if an["exists"] and any(p["state"] == "open" for p in an["easiest_tier"]):
                cs = m.controls_for(ws, t["id"])
                if cs:
                    m.set_control_steps(ws, cs[0]["id"], sorted(set(cs[0].get("step_ids", [])) | {p["steps"][0] for p in an["easiest_tier"]}))

    def step8(self):
        ws = self.ws
        for t in ws["threats"]:
            r = m.get_risk(ws, t["id"])
            ctl = [c for c in m.controls_for(ws, t["id"]) if c["status"] == "verified"]
            inh = r["inherent"]
            if not r.get("residual"):
                if ctl and m.tree_analysis(ws, t["id"])["easiest_tier"] and all(p["state"] == "cut" for p in m.tree_analysis(ws, t["id"])["easiest_tier"]):
                    m.set_residual_risk(ws, t["id"], max(1, inh["likelihood"] - 1), "Verified control cuts the easiest path.", inh["impact"],
                                        "Impact is unchanged: the control does not limit what is exposed.", [c["id"] for c in ctl],
                                        m.describe_paths(ws, t["id"], m.tree_analysis(ws, t["id"])["remaining"]) or "No viable path remains.",
                                        "Covers the tested interface only.", "Verified negative test shows the easiest path is closed.")
                else:
                    m.set_residual_risk(ws, t["id"], inh["likelihood"], "No verified control on the easiest path.", inh["impact"], "Impact unchanged by controls.", [],
                                        "Original attack path remains.", "Controls are not verified.")
            if not r.get("treatment"):
                m.set_treatment(ws, t["id"], "mitigate", "Engineering lead", "Controls are planned and verified where possible; residual tracked in the register.")
        if len([q for q in ws["questions"] if q["origin"] == "learner"]) < 3:
            for text, rel in (("Who confirms that the provider patches managed components within the agreed window?", []),
                              ("Is traffic between internal components encrypted in every environment?", [ws["threats"][0]["id"]]),
                              ("What firmware or client update path exists and who signs releases?", [])):
                try:
                    m.add_question(ws, text, owner="Platform lead", due=sp.FUTURE, related=rel)
                except m.DuplicateError:
                    pass

    def step9(self):
        ws = self.ws
        sp.review_plan(ws)
        if not ws["remodel"]["completed"]:
            f = m.flows(ws)[0]
            if not any(c["kind"] in ("dfd_modify",) and c["at"] >= min(v["at"] for v in ws["versions"] if v["kind"] == "dfd") for c in ws["changelog"]):
                m.update_flow(ws, f["id"], protocol=f["protocol"] + " v2")
            self.do_stale()
            m.commit_dfd(ws, "Protocol changed during re-modelling exercise", "bot")
            m.complete_remodel_exercise(ws, "Changed a flow protocol; affected threat, tree, mapping, risk and control were revalidated and no decision changed.")

    # ── the loop ──────────────────────────────────────────────────────────────────────────
    def run(self, max_iter=80):
        last_sig, repeats = None, 0
        for i in range(max_iter):
            if self.on_state:
                self.on_state(self)
            acts = tm_journey.next_actions(self.ws)
            act = acts[0]
            self.trace.append({"i": i, "step": act["step"], "code": act["code"], "headline": act["headline"], "detail": act["detail"]})
            if act["code"] == "done":
                return self
            sig = (act["step"], act["code"], act["detail"], m.canonical_hash(self.ws))
            repeats = repeats + 1 if sig == last_sig else 0
            last_sig = sig
            if repeats >= 1:
                raise JourneyFailure(f"The prompt did not lead to progress: {act['headline']} - {act['detail']} (step {act['step']})")
            self._interventions(act)
            if self.on_state:
                self.on_state(self)          # also see the state right after the learner's edit (stale records present)
            act = tm_journey.next_actions(self.ws)[0]
            if act["code"] == "done":
                continue
            if act["code"] in STALE_CODES:
                self.do_stale()
            else:
                getattr(self, f"step{act['step']}")()
            if self.save_every_action:
                self.restore()
        raise JourneyFailure("did not finish within the iteration budget; last prompts: " + str([(t["step"], t["code"]) for t in self.trace[-4:]]))

    def _interventions(self, act):
        if not self.interventions:
            return
        ws = self.ws
        if act["step"] >= 4 and "edit_threat" not in self._did and ws["threats"]:
            self._did.add("edit_threat")
            t = ws["threats"][0]
            m.update_threat(ws, t["id"], action=t["action"] + " (refined after reviewing the brief again)")
            nxt = tm_journey.next_actions(ws)[0]
            if not (nxt["step"] <= 3 or nxt["step"] <= act["step"]):
                raise JourneyFailure("editing a threat did not send the learner back")
            self.events.append(("edited threat", nxt["step"], nxt["code"]))
        elif act["step"] >= 8 and "change_flow" not in self._did and m.flows(ws):
            self._did.add("change_flow")
            f = next((f_ for f_ in m.flows(ws) if m.impact_analysis(ws, f_["id"])["threats"]), m.flows(ws)[0])   # a flow a threat depends on
            m.update_flow(ws, f["id"], protocol=f["protocol"] + " revised")
            nxt = tm_journey.next_actions(ws)[0]
            if nxt["step"] >= 8 or nxt["code"] == "done":
                raise JourneyFailure("a DFD change after verification was not flagged by the next action: " + str(nxt))
            self.events.append(("changed flow", nxt["step"], nxt["code"]))
