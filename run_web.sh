#!/bin/bash
# Web tool launcher. Always runs from the repo root so `web.server:app` resolves.
set -e
cd "$(dirname "$0")"
if [ -f .venv/bin/activate ]; then
    source .venv/bin/activate
fi
echo "Web tool starting on http://127.0.0.1:8000/"
echo "Health check: curl http://127.0.0.1:8000/healthz"
echo "Stop with Ctrl+C"
echo
exec uvicorn web.server:app --host 127.0.0.1 --port 8000 --reload
