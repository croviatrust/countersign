#!/usr/bin/env bash
# Countersign dev install (Linux/macOS)
set -euo pipefail
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
echo
echo "Installed. Try:"
echo "  countersign init --log ./witness-log"
echo "  python3 examples/demo.py"
echo "  pytest -q"
