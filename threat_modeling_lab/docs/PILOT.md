# Instructor walkthrough checklist and learner-pilot plan
*(Plans only - none of this has been performed.)*

## A. Instructor walkthrough (about 90 min, before the first cohort)
Environment
- [ ] `pip install -r requirements.txt`; `./run_tests.sh` passes; `python -m unittest tests.test_apptest` runs (not skipped).
- [ ] `python tools/verify_catalogues.py ...` run with official ATT&CK/CAPEC files; Step 5 banner shows *verified* (or you accept and brief the "unverified" label).
- [ ] `streamlit run workshop23.py` opens; reload keeps progress (URL has `sid`).
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
| Stale-handling | Can learner find and clear revalidation items after a DFD change | >= 80% succeed without help |
Protocol: 10-min briefing -> 5-min pre-quiz on STRIDE/ATT&CK/CAPEC differences -> lab (observer silent, notes only) -> export review -> 15-min debrief and post-quiz.
Acceptance for rollout: all targets met, or each miss has a logged fix and a re-test.
