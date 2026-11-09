#!/usr/bin/env bash
# Run every test for the scripts and the admin UI backends (no Rust build needed).
set -euo pipefail
cd "$(dirname "$0")/../.."
scripts/tests/changelog_test.sh
python3 -B scripts/tests/deselect_test.py
python3 -B scripts/tests/admin_ui_test.py
bash -n scripts/start.sh scripts/footprint.sh scripts/e2e-clients.sh scripts/s3-tests/run.sh
