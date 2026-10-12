#!/usr/bin/env bash
# Runs the complete automated suite (unittest; also collectable by pytest).
set -e
cd "$(dirname "$0")"
python -m py_compile workshop23.py ui_common.py ui_pages.py tm_model.py tm_assess.py tm_export.py tm_catalog.py tm_labs.py lab_data.py tools/verify_catalogues.py
python -m unittest discover -s tests -v
