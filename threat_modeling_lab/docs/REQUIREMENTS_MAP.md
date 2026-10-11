# Requirement -> implementation -> test

Paths: `tm_model.py` (M), `tm_assess.py` (A), `tm_export.py` (X), `tm_catalog.py` (C), `tm_labs.py` (L), `ui_pages.py` (UI), `ui_common.py` (UC).
Tests: `MT` test_methodology, `DI` test_data_integrity, `WF` test_workflow, `UIT` test_ui_smoke, `CT` test_catalog.

| # | Requirement | Implemented in | Verified by |
|---|---|---|---|
| 3 | Seven learner outcomes (scope, DFD, STRIDE, mappings, risk/controls, residual+owners, review plan) | whole 9-step flow | WF `AllLabsSameMethodology.test_every_lab_completes...` |
| 4.1 | Step 1 scope: purpose, boundaries, objectives, assets, stakeholders, facts vs assumptions, exclusions, dependencies, sensitivity, success criteria; versioned | M `add_scope_item`, `commit_scope`; UI `step1`; A `gate_scope` | WF `test_empty_workspace...`, `test_scope_with_weak_content...`; UIT |
| 4.2 | Step 2 editable DFD, validation view, stable IDs, no silent duplicates, versioned | M `add_element/add_flow/add_boundary/update_*/delete_*/dfd_issues/commit_dfd`; UI `step2`; X `dfd_dot` | DI `StableIdsAndDuplicates`; WF `test_dfd_gate_reports...`; UIT `test_add_element...` |
| 4.3 | Step 3 STRIDE-per-element prompts, departures explained, threat fields, structured statement builder, editable wording | M `APPLICABILITY`, `set_stride_cell`, `add_threat`, `build_statement`, `statement_override`; UI `step3` | MT `StrideApplicability`, `ThreatStatements`; UIT `test_threat_builder...` |
| 4.4 | Step 4 boundary validation only (no re-mapping, no boundary=threat, no zone scores) | M `crossings`, `set_boundary_review`, `set_crossing_review`; UI `step4` | MT `BoundaryRules`; WF `test_boundary_crossings_are_entered_once` |
| 4.5 | Step 5 distinct frameworks, mapping fields, validation, non-mapping, unverified catalogue not "current" | M `add_mapping`, `add_no_mapping`; C; UI `step5` | MT `MappingRules`; CT |
| 4.6 | Step 6 documented risk model, validation, inherent separate | M `RISK_MODEL`, `risk_score`, `risk_matrix`, `set_inherent_risk`; UI `step6` | MT `RiskSeparation.test_scoring_is_transparent...` |
| 4.7 | Step 7 propose-before-reveal, control fields, evidence for verified, no auto reduction | M `add_control`, `set_control_status`, `record_verification`; A `control_reference`; UI `step7` | MT `test_selecting_a_control_never_changes_risk`, `test_control_verification_gates`; WF `test_controls_and_mappings_and_risk_gated_per_threat` |
| 4.8 | Step 8 residual, treatment, owner, date, justification, questions, acceptance conditions, escalation | M `set_residual_risk`, `set_treatment`, `add_question`; UI `step8` | MT `TreatmentDecisions`, `test_reduction_requires_a_verified_control` |
| 4.9 | Step 9 review plan, re-modelling exercise, report + exports | M `set_review_plan`, `impact_analysis`, `complete_remodel_exercise`; X; UI `step9` | DI `ExportConsistency`; UIT `test_completed_lab_exposes_all_downloads` |
| 5 | Remove repetition; single canonical records; 9-step tracker; five questions per page | UI/UC `frame()`; `workshop23.tracker`; legacy pages deleted (see ARCHITECTURE.md) | WF `NineSteps` (5 tests) |
| 6 | Four progressive labs | L `PROFILES`, `BRIEFS`, `INSTRUCTOR_ONLY`; M `new_workspace` | WF `test_labs_differ_in_scaffolding...`, `test_lab4_brief...` |
| 7 | Rubric, alternatives, reviewer flags, quantity not rewarded, discover-first enforced | A `rubric`, `reveal_status`, `get_reference`, `reference_comparison` | WF `GatesJudgeQuality`, `DiscoverFirstEnforcement`; UIT `DiscoverFirstInTheUI` |
| 8 | IDs, relationships, isolation, save/restore/migrate, no duplicates, deleted/modified handling, stale flags, change record | M `ensure_workspace`, `save_state`, `migrate_state`, `_mark_stale`, `changelog` | DI (all classes) |
| 9 | Complete report + JSON + separate risk-register CSV, consistent IDs, omissions never hidden | X `build_model_export`, `risk_register_rows`, `check_export_consistency`, `report_*` | DI `ExportConsistency`; UIT |
| 10 | Modular, existing entry point, rerun-safe, visible errors, no hard-coded test claims | `workshop23.py` unchanged entry; UC `attempt`, tokens/nonces | UIT `test_add_element...no_duplicate_on_rerun`, `test_validation_errors_are_visible...`; WF `test_application_code_cannot_bypass_the_gate` |
| 11 | Methodology / integrity / workflow tests | `tests/` | 91 tests, see TESTING.md |
| 11 | Runtime acceptance (start app, browser, four-lab run) | **Not performed** (no Streamlit/network/browser in the build sandbox). `tests/test_apptest.py` is provided but skipped there | See TESTING.md "Not tested" |
| 13.8-13.9 | Instructor checklist, pilot plan | `docs/PILOT.md` | n/a (documents) |
