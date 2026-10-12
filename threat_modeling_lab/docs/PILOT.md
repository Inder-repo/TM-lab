# Instructor walkthrough checklist and learner-pilot plan
*(Plans only - none of this has been performed.)*

## A. Instructor walkthrough (about 90 min, before the first cohort)
Environment
- [ ] `pip install -r requirements.txt`; `./run_tests.sh` passes; `python -m unittest tests.test_apptest` runs (not skipped).
- [ ] `python tools/verify_catalogues.py ...` run with official ATT&CK/CAPEC files; Step 5 banner shows *verified* (or you accept and brief the "unverified" label).
- [ ] `streamlit run workshop23.py` opens; reload keeps progress (URL has `sid`).
Journey and baseline
- [ ] New lab opens on the Journey overview; the Next action matches the first blocker of Step 1; 'Take me there' goes to Step 1.
- [ ] After finishing a step the banner moves on without you hunting for it; after editing a threat or flow it sends you back to what is stale.
- [ ] The register and DFD expander at the top of steps 3-9 show the same threats you edited (no second copy).
Library and attack trees
- [ ] Step 3: pick a flow with protocol HTTP -> suggestions explain *why* (encryption not stated / crosses a boundary). Guided: 'Start from TP-..' fills the builder.
- [ ] Open a threat -> Attack tree tab -> template suggested; edit/add/delete steps; Step 6 will not let you rate until every leaf is judged.
- [ ] Step 7: link a control to a step; Step 8: try lowering likelihood when the easiest path is not cut -> refused.
- [ ] Switch assistance to fading in Lab 2 and write 2 threats cleanly: drafts disappear; submit a bad one: help returns. Lab 4: mode is locked.
- [ ] Browser: expanders do not error, no 'duplicate widget' errors, nothing resets when you tick checkboxes inside lists.
Lab 1 (guided)
- [ ] Step 1: commit scope v1; changing a field shows "changes not committed".
- [ ] Step 2: load starter DFD; edit a flow; validation view lists a flow with no classification; add a duplicate flow -> refused.
- [ ] Step 3: worked example visible; try Elevation of Privilege on a flow -> departure rationale demanded; mark a prompt N/A with "N/A" -> refused.
- [ ] Steps 4-8: boundary justification, mapping with *no defensible mapping*, rate, propose control, mark implemented, try lowering residual -> refused until verified with evidence.
- [ ] Step 8: accept a High residual with no escalation -> refused.
- [ ] Step 9: complete plan; change a flow protocol -> stale items listed; revalidate; complete exercise; download JSON/CSV/MD/PDF.
Labs 2-4
- [ ] Discover-first: reference tab says locked; stays locked with seeded content only; unlocks after own work + hypothesis.
- [ ] Lab 4: cannot disable discover-first; brief is incomplete; gap feedback unlocks after 3 questions + a threat.
- [ ] Switch labs: each lab's work is intact; "Reset this lab" affects only that lab.
Exports
- [ ] Open the CSV and JSON of an incomplete model: omissions, stale items and failed verification are listed.
Record any deviation in an issue list with screenshots.

## B. Learner pilot (suggested: 6-8 learners, mixed experience, Lab 1 then Lab 3 or 4)
Measure
| Measure | How | Target (acceptance) |
|---|---|---|
| Task completion | Steps reaching "complete" unaided | >= 80% of learners complete Lab 1 |
| Time per step | Facilitator timer / session log | Lab 1 within planned duration +/- 25% |
| Confusion points | Think-aloud + "where did you stop?" markers | No step where >= 3 learners need help with the *same* UI element |
| Repeated work | Observer notes: any information entered twice | Zero mandatory re-entry |
| Gate fairness | Learner/observer disagreement with a blocker | < 10% of blockers judged unfair |
| Explainability | After the lab, learner explains: top 3 risks, why a control is "verified", what an accepted risk needs | >= 80% explain all three correctly (instructor rubric) |
| Discover-first | Did learners form a hypothesis before reveal? Did locks frustrate? | Hypotheses recorded in >= 90% of reveals; frustration reported as "fair" by majority |
| Journey clarity | Learner states, without looking, what the next action is at 3 random points | >= 90% correct |
| Library usefulness | Share of suggestions judged relevant by the learner; threats started from examples later edited substantially | >= 70% relevant; edits present in >= 80% |
| Fading | Learners in fading mode who complete later steps with reduced help without more rejected submissions | no increase in rejected submissions after help fades |
| Stale-handling | Can learner find and clear revalidation items after a DFD change | >= 80% succeed without help |
Protocol: 10-min briefing -> 5-min pre-quiz on STRIDE/ATT&CK/CAPEC differences -> lab (observer silent, notes only) -> export review -> 15-min debrief and post-quiz.
Acceptance for rollout: all targets met, or each miss has a logged fix and a re-test.
