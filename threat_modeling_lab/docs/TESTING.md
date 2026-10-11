# Testing report (actual results)

Environment: Python 3.12, Linux sandbox, **no network, no Streamlit, no pytest, no browser**. Dependencies available: pandas, reportlab.

## Baseline (before any change)
* `python -m py_compile` on the original: **passes**.
* `import` of the original: **fails only because Streamlit is not installed** (not a code defect).
* The original shipped **no tests and no dependency file**; there were no pre-existing test results to record.

## Executed after the refactor
| Command | Result |
|---|---|
| `python -m py_compile` on all modules | OK |
| `python -m unittest discover -s tests -v` | **91 tests: 90 passed, 0 failed, 1 skipped** (`test_apptest.py`, needs Streamlit) |
| Mutation check (8 deliberate regressions: discover-first gate off, acceptance checks off, owner not required, risk reduction without verified control, no stale propagation, duplicate flows allowed, "verified" without evidence, export hiding stale records) | **8/8 detected** by the suite. Two were missed on the first pass (weak owner assertion, stale records not asserted in export); the tests were strengthened and re-run |
| Representative end-to-end run of all four labs through the public API (scope -> remodel -> exports) | All nine gates pass for labs 1-4; exports pass `check_export_consistency` for each; PDF generation returns a valid `%PDF` for each |
| Page smoke run, all 9 pages x 4 labs x {fresh, completed} with the in-memory Streamlit stub | No exceptions |
| Scripted UI interactions with the stub (add element/threat via forms, rerun idempotence, visible errors, lab switch, save/restore, corrupt save, entry-point run) | Pass |

Test groups: methodology 26, data integrity 22, workflow 22, UI-path (stub) 14, catalogue 6, real-runtime 1 (skipped).

## NOT tested (be explicit)
* **The app has never been launched under real Streamlit.** The UI tests use `tests/stub_streamlit.py`, which proves code paths execute and drive the model, but cannot detect layout problems, widget-state/`rerun` subtleties, `st.graphviz_chart` rendering, `st.date_input` behaviour, or version-specific API differences. Run `tests/test_apptest.py` and the instructor checklist (docs/PILOT.md) before teaching.
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
