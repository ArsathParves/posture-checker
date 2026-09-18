#!/bin/bash
# CLI launcher. Always runs from the repo root so `-m posture.cli` resolves.
set -e
cd "$(dirname "$0")"
if [ -f .venv/bin/activate ]; then
    source .venv/bin/activate
fi
if [ $# -eq 0 ]; then
    echo "Usage: ./run_cli.sh <domain> [--json] [--no-info]"
    echo "Example: ./run_cli.sh example.com"
    exit 1
fi
exec python3 -m posture.cli "$@"
