# Testing report (actual results)

Environment: Python 3.12, Linux sandbox, **no network, no Streamlit, no pytest, no browser**. Dependencies available: pandas, reportlab.

## Baseline (before any change)
* `python -m py_compile` on the original: **passes**.
* `import` of the original: **fails only because Streamlit is not installed** (not a code defect).
* The original shipped **no tests and no dependency file**; there were no pre-existing test results to record.

## Executed (revision 2)
| Command | Result |
|---|---|
| `python -m py_compile` on all modules | OK |
| `python -m unittest discover -s tests -v` | **152 tests: 151 passed, 0 failed, 1 skipped** (`test_apptest.py`, needs Streamlit). About 47 s |
| Mutation check, revision 1 rules (8 regressions) | 8/8 detected |
| Mutation check, revision 2 rules (13 regressions: rating without validated steps, likelihood falling without cutting the easiest path, stale STRIDE decisions not flagged, example-started threats counted as independent, library never gated, control-step links unvalidated, AND/OR swapped, dangling links after step deletion, no gate on uncovered easiest path, remodel baseline regression, assistance never fading, next action skipping a step, library ignoring element kind) | **13/13 detected** (one was missed on the first pass - no direct test for stale STRIDE decisions - a test was added) |
| **Learner journeys**: each of the 4 labs from scope to final report by a bot that follows *only* the next-action prompt, saving and restoring after every action, editing a threat after Step 3 and changing a DFD flow after controls were verified | All four complete; prompts visited all nine steps; every prompt had a specific headline; edits sent the learner back to revalidate; no duplicate records (elements, flows, threats, mappings, risks, tree steps, IDs); no integrity errors; exports consistent and complete; PDF valid |
| Replay of every kind of submission (element, flow, boundary, threat, mapping decision, tree, question) | Nothing new created; token replay idempotent |
| Scripted UI journey (Lab 1 guided) through the real widget keys: start from a library draft -> add threat -> use suggested tree template -> validate every step | Pass |
| Page sweep: all 10 pages at every state the bot passes through (48 states over 4 labs, including stale and partly validated states) plus controls in every status | No exceptions |

**What the stub now enforces** (rules real Streamlit enforces and the first version of the stub did not): no nested expanders, no duplicate widget keys within a run, no `st.button` inside `st.form`, `st.form_submit_button` only inside a form. This found two crash-level defects from revision 1 (see ARCHITECTURE.md section 10). The stub still cannot find layout, widget-state or rerun-semantics problems.

Test groups: methodology 26, data integrity 28, workflow 22, library 13, attack trees/assistance 26, journey 13, catalogue 6, UI-path (stub) 17, real-runtime 1 (skipped).

## NOT tested (be explicit)
* **The app has never been launched under real Streamlit** (this is the single largest remaining risk; revision 2 found two crash-level defects that the earlier stub could not see, so assume more may exist). The UI tests use `tests/stub_streamlit.py`, which proves code paths execute and drive the model, but cannot detect layout problems, widget-state/`rerun` subtleties, `st.graphviz_chart` rendering, `st.date_input` behaviour, or version-specific API differences. Run `tests/test_apptest.py` and the instructor checklist (docs/PILOT.md) before teaching.
* No browser/keyboard-navigation/accessibility testing. Streamlit's native widgets are used and every action is a button, but this is unverified.
* No instructor walkthrough and no learner pilot has taken place. The checklist and protocol are plans, not results.
* Python versions other than 3.12 were not executed (an AST scan confirmed no f-string syntax newer than 3.8 is used).
* ATT&CK/CAPEC datasets were **not** verified against official sources (no network). The verifier is tested only with synthetic fixtures.
* Concurrent sessions sharing one session id (file overwrite) are not tested.
* Migration was tested with a constructed legacy payload built from the legacy record shapes, not a real saved file.

## Known limitations and defects
1. ATT&CK dataset (60 techniques) and CAPEC subset (11 patterns) are carried from the legacy app; the legacy "v19" label is displayed as *declared, unverified*. Some legacy IDs may not exist in the official catalogue - the verifier will list them.
2. Rubric heuristics for specificity are keyword-based (a system name/protocol/asset must appear in the text). They can pass vague text that happens to name a component and fail good text that does not. Such items are flagged "needs reviewer" but the criteria result stands.
3. Lab reference data defects retained verbatim (see ARCHITECTURE.md section 1); the app reports them as "reference target not in DFD".
4. The legacy SVG architecture renderer, diagram annotations, score pages and legacy PDFs were removed rather than ported; Graphviz DOT is used instead.
5. Lab 1's own reference threat T-001 labels Spoofing on a data flow, which is outside the standard prompts; learners need a departure rationale (this is intended and demonstrates the rule).
6. Review-date gates depend on today's date; a plan dated in the past blocks Step 9.
7. Gap-feedback matching in Lab 4 is keyword based and meant as an instructor prompt.
8. The tag heuristics behind contextual suggestions are keyword-based (e.g. an element named "Gateway" is treated as API-like). They explain themselves ("suggested because...") so a wrong suggestion is visible, but they will miss unusual naming.
9. Library worked examples and the template step hints are authored content; they have been checked for structure, ID validity and leakage, not reviewed by a second security practitioner. Control and reference entries are topic-level (no section numbers).
10. Effort scale (1-5) and "easiest path = hardest step on it" are a documented simplification, not a calibrated model.
11. A tree is optional in Labs 1-2 (warned) and required in Labs 3-4; if you want it required everywhere, set `require_attack_trees` in `tm_labs.PROFILES`.
12. Legacy IDs in the ATT&CK dataset that look doubtful (e.g. T1685, T1689, T1692-T1695 and tactic labels "Stealth"/"Defense Impairment") are not used by the library; the verifier will report them.
