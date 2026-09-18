#!/bin/bash
# Web tool launcher. Always runs from the repo root so `web.server:app` resolves.
set -e
cd "$(dirname "$0")"

# Refuse to run without .venv rather than falling back to system Python.
# Silent fallback either fails cryptically ("uvicorn: not found") or, worse,
# runs against a globally installed uvicorn that resolves web.server via the
# wrong sys.path — the user gets no actionable signal either way.
if [ ! -f .venv/bin/activate ]; then
    echo "error: .venv/bin/activate not found." >&2
    echo "Create a virtualenv and install dependencies before running:" >&2
    echo "  python -m venv .venv" >&2
    echo "  source .venv/bin/activate" >&2
    echo "  pip install -e .[web]     # PEP 621 install (preferred)" >&2
    echo "  # OR" >&2
    echo "  pip install -r requirements.txt" >&2
    exit 1
fi
source .venv/bin/activate

echo "Web tool starting on http://127.0.0.1:8000/"
echo "Health check: curl http://127.0.0.1:8000/healthz"
echo "Stop with Ctrl+C"
echo
exec uvicorn web.server:app --host 127.0.0.1 --port 8000 --reload
