#!/bin/sh
# Run from a development environment installed with pip install -e '.[dev,redis]'.
set -eu
cd "$(dirname "$0")/.."
python -m pip check
python -m ruff check --no-cache .
python compatibility/check.py
python -m pytest -q --cov "$@"
