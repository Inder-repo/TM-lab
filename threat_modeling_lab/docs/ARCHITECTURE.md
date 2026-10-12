# Architecture, data model and before/after

## 1. Findings from inspecting the original (6,774-line single file)
| Finding | Evidence in original | Consequence |
|---|---|---|
| 18 pages in 10 "stages" with overlapping work | architecture + DFD + trust-boundary + zones; actors + attack trees + threat identification; STRIDE rules + STRIDE mapping; OWASP + controls; assessment + report | Same crossings/threats entered 2-3 times |
| Scoring = matching a predefined answer key | `PREDEFINED_THREATS` compared by component + STRIDE; "target_threats" counts | Rewards guessing the author's list; cannot accept valid alternatives |
| Zone/criticality scores drove STRIDE rules | `STRIDE_ZONE_RULES`, `CRITICALITY_ZONES` | Deterministic "if zone 3 then Spoofing" - not methodology |
| Residual risk auto-reduced by keyword/count of controls | `suggested_residual`, containment keywords | Controls reduced risk because they were *selected* |
| "Named owner" claimed but no owner field | residual-acceptance form | Acceptance without accountability |
| `threats`, `user_answers`, scores were single global lists | `start_workshop()` reset them | Switching labs wiped work; saves held only the current lab |
| Reference threats pointed at elements absent from the DFD | Lab 1 T-010 `API Backend -> S3 Storage`, Lab 3 T-204 `Data Lake -> Data Warehouse`, Lab 4 T-305 `HL7 Interface -> Legacy EHR` are flows not in those DFDs; Lab 2's description mentions message queues but no queue is in its DFD | Unanswerable "disconnected data structures" (kept verbatim in `lab_data.py`, now surfaced by the app) |
| ATT&CK catalogue declared "v19" with no provenance | inline `ATTACK_TECHNIQUES`, `CAPEC_CANDIDATES` | Presented as current without verification |
| No tests, no dependency file | - | Baseline: file compiles (`py_compile`) but cannot be imported without Streamlit; no pre-existing tests to run |

## 2. New structure
```
workshop23.py -> ui_pages.py (9 pages) -> ui_common.py
                      |                        |
                      +---- tm_assess.py ------+---- tm_export.py
                                 |
                              tm_model.py  <-- tm_catalog.py, tm_labs.py <-- lab_data.py
```
Business rules live only in `tm_*`; pages never contain scoring or validation logic.

## 3. Canonical data model (workspace schema v3, one per lab per learner session)
```
scope(version, facts[F-], assumptions[A-], assets[AS-], stakeholders[SH-], exclusions[EX-], ...)
dfd(version, elements[EE-|P-|DS-], flows[DF-], boundaries[TB-])         rev counters per record
stride_cells{"<target>:<letter>": disposition+rationale}
threats[THR-]  -> targets: element/flow IDs, stride, source, preconditions, action, impact, assets, evidence, rationale, confidence, departure_rationale, statement_override
mappings[MAP-] -> threat_id, framework, outcome(mapped|no_defensible_mapping), ref_id, name, url, catalogue_status, version, rationale ...
risks[RSK-]    -> threat_id, inherent{L,I,score,band,priority,...}, residual{L,I,basis_control_ids,...}, treatment{decision,owner,...}
controls[CTL-] -> threat_ids, targets, function, owner, status(proposed|planned|implemented|verified|verification_failed|rejected), verification{method,evidence,date,result}
questions[Q-], boundary_reviews{TB-}, crossing_reviews{"TB|DF"}, review, remodel, versions[], changelog[CH-], hypotheses, reveals
```
* IDs come from per-prefix counters and are never reused (`deleted_ids` is checked by the integrity test).
* Crossings are **computed** from boundary membership; Step 4 stores only justifications keyed by `(boundary, flow)`.
* Inherent and residual live in separate sub-records of one risk record. Residual is always entered; it can only fall below inherent when a **verified (pass + evidence)** control linked to that threat is cited.

## 4. Change management
`update_*`/`delete_*` on DFD records bump `rev`, append stale flags to dependent threats, mappings, risks, controls, boundary reviews and crossing reviews, and write a `changelog` entry listing affected IDs. Deleting an element removes its flows, drops the ID from threats (`orphaned_targets`) and flags them. `revalidate()` needs a note and clears one record. Gates, the risk-register export (`row_status`), and `completeness()` all treat stale records as open work, so the model cannot look complete while stale.

## 5. Discover-first
`tm_assess.reveal_status()` is the single decision point and `get_reference()` the only way to obtain instructor material (a test asserts the UI modules do not import reference data). Gates: DFD reference needs 3 own elements + 1 own flow + a saved hypothesis (seeded/loaded items do not count); threat suggestions/attack trees need a hypothesis + a learner-authored threat; mapping suggestions need a per-threat attack-path hypothesis; risk reference needs your rating; control reference needs your control; gap feedback (Lab 4) needs 3 own questions + a threat. Lab 4 cannot disable the mode. Every reveal is logged and exported.

## 6. Lab progression (same methodology, different scaffolding)
| | Lab 1 Guided | Lab 2 Applied services | Lab 3 Multi-tenant | Lab 4 Independent |
|---|---|---|---|---|
| Discover-first default | off | on | on | on, locked |
| DFD help | loadable starter DFD | component inventory only | read-only comparison after own DFD | read-only comparison after own DFD |
| Worked STRIDE example | yes | no | no | no |
| Brief | complete | complete, with decisions left open (identity propagation, queues) | explicitly lists unknowns | deliberately incomplete; you list what's missing |
| Scope pre-seeding | assets + objectives | assets + objectives | facts only | facts only |
| Extra expectation | basics | identity/authz per flow | cross-tenant attack paths | inferred elements, information gaps, safety impact |

## 7. Migration of existing saved work
`migrate_state()` accepts legacy (schema <= 2) files and v5 files. Legacy import keeps scope text/goals/assumptions/exclusions, open questions, review plan, the selected lab's threats (origin `migrated`, flagged stale, **targets left empty rather than guessed**), CAPEC/ATT&CK picks found in the dataset (unknown IDs dropped, flagged stale), ratings (1-3 scale mapped to 2/3/4 on the 5-point scale, flagged), and selected mitigations as `proposed` controls. **Not carried over:** answer-key scores, zone scores/STRIDE-rule answers, diagram annotations, other labs' threats (the legacy file only ever held the selected lab's). Nothing migrated is promoted to implemented/verified. The legacy file is never modified.

## 8. Before / after
| | Before | After |
|---|---|---|
| Navigation | 18 pages, 10 stages | 9 steps, one persistent tracker |
| Threat record | answer-key match + scored free-text | one canonical record with IDs, targets, structured statement + editable wording |
| Per-lab state | one global set, wiped on switch | isolated workspace per lab |
| DFD | fixed scenario diagram | editable elements/flows/boundaries with validation, versioning, Graphviz view |
| Zones | drive STRIDE | optional "security domain" label only |
| Mapping | pick from list, hidden catalogue status | rationale required, provenance shown, non-mapping valid |
| Risk | 1-3 scale, auto residual | documented 5x5 model, residual evidence-gated |
| Controls | selected = effective | proposed -> planned -> implemented -> verified (evidence) |
| Assessment | percentage | criteria rubric with reasons + "needs reviewer" flags |
| Exports | PDFs from legacy records | JSON, risk-register CSV, Markdown, PDF from one model; omissions listed |
| Tests | none | 91 automated tests (see TESTING.md) |


## 9. Revision 2 - one streamlined journey
**Baseline and prompting.** Page 0 (Journey overview) shows the lab's purpose, the artefact each step produces, per-step state and a count summary, assistance levels, the shared DFD and the threat register. `tm_journey.next_actions()` returns the first blockers of the first incomplete step *using the same gates the steps use*, so the prompt can never disagree with what will be accepted. It appears as a banner on every page, as a primary button in the sidebar and on the overview. Steps are grouped into four phases (Understand, Analyse, Decide, Sustain); the nine canonical steps and their gates are unchanged.

**One register, one model.** `tm_journey.register_rows()` renders the single threat register (statement, tree progress, ATT&CK/CAPEC decision, inherent, controls and verified count, residual, decision, flags). Every analysis step shows it, together with the shared DFD, in one expander. There is no second copy of any record.

**Consolidated screens.** Step 3 is one "threat register workspace": pick a DFD element/flow -> contextual library suggestions -> structured builder -> your threats, each with statement and attack-tree tabs. STRIDE coverage and reference/library are the other two tabs. Threat actors are a field of the threat, not a page.

**Attack trees as canonical data.** `ws["attack_trees"][threat_id]` holds nodes with stable `ST-nnn` IDs, AND/OR logic, per-leaf validation (plausible/implausible, effort 1-5, reason) and provenance (template or own). `tree_analysis()` computes viable paths, validated paths, the easiest path (effort = hardest step on the path) and each path's control state: open / planned (control linked, not verified) / cut (verified control). Links: mapping.step_id and control.step_ids (validated against the threat's own tree).

**Connected exercise (what flows where).** Step 3 builds the tree -> Step 5 maps steps -> Step 6 requires every leaf validated before rating and stores the path evidence with the rating (it informs, never sets, the number) -> Step 7 links controls to steps and the gate needs a control on the easiest path -> Step 8 lets likelihood fall only if the easiest path tier is cut by a verified control, and records cut/remaining paths -> exports and the report carry the tree, its analysis, links and open paths.

**Assistance modes.** `guided` (examples, drafts, worked examples), `fading` (help decreases per skill as submissions are accepted first time: full -> reduced after 2 clean in a row -> none after 4; a rejected submission restores it), `independent` (library only after your own hypothesis and an unassisted threat). Defaults: Lab 1 guided, Labs 2-3 fading, Lab 4 independent and locked. A threat started from an example is recorded (`library_ref`), does not count as independent work for unlocking references, is reported in the export and is not penalised.

**Stale STRIDE decisions.** A DFD change now also reopens the "not applicable / mitigated by design" decisions for that element or flow (previously only threats, mappings, risks and controls were flagged).

## 10. Defects found by the stricter tests in this revision (fixed)
| Defect | Introduced | Effect under real Streamlit | Found by |
|---|---|---|---|
| Control "Update" expander nested inside the per-threat expander (Step 7) | revision 1 | `StreamlitAPIException` - Step 7 would crash | stub now enforces the nesting rule |
| Step 3 reference tab created two widgets with the same key | revision 1 | `DuplicateWidgetID` under discover-first | stub now enforces unique keys |
| Re-modelling exercise required a DFD change *after the latest* DFD commit, contradicting the on-screen order (change -> commit -> complete) | revision 1 | exercise fails whenever the commit is a second after the change | page sweep at in-between states |
| STRIDE "not applicable" decisions were not reopened by DFD changes | revision 1 | a learner could change a protocol and keep a stale N/A | learner bot |
| Library worked example reused the Lab 2 component name "Payment Service" | revision 2 draft | would hand Lab 2 learners an answer | library leakage test |
| Elements with no distinguishing signals got no suggestions | revision 2 draft | beginners got nothing | library test |
