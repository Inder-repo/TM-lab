# Threat Modeling Lab (nine-step refactor)

## Install, test, run
```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
./run_tests.sh                                          # or: python -m unittest discover -s tests -v
streamlit run workshop23.py
```
`tests/test_apptest.py` uses Streamlit's own AppTest harness and only runs where Streamlit is installed
(it is skipped in the sandbox this refactor was built in - see docs/TESTING.md).

## Verify the ATT&CK / CAPEC datasets (recommended before teaching)
```bash
python tools/verify_catalogues.py --attack enterprise-attack.json --attack-version "ATT&CK vX.Y" \
                                  --capec stix-capec.json --capec-version "CAPEC X.Y"
```
Until this has been run the app labels both datasets `curated-unverified` everywhere, including exports.

## Layout
| File | Role |
|---|---|
| `workshop23.py` | Streamlit entry point (config, CSS, unlock codes, sidebar, 9-step tracker, routing) |
| `ui_pages.py` / `ui_common.py` | The nine step pages / shared widgets, state and persistence wiring |
| `tm_model.py` | Canonical data model + every business rule (no Streamlit) |
| `tm_assess.py` | Completion gates, discover-first reveal gate, rubric, integrity checks |
| `tm_export.py` | JSON, risk-register CSV, Markdown and PDF generated from the same model |
| `tm_catalog.py`, `tools/verify_catalogues.py` | ATT&CK/CAPEC data with provenance, and the verifier |
| `tm_labs.py`, `lab_data.py` | Per-lab pedagogy; scenarios and instructor reference material |
| `legacy/workshop23_original.py` | The unmodified original, kept for rollback/diffing |
| `docs/` | Architecture, requirement map, testing report, instructor checklist, pilot plan |
