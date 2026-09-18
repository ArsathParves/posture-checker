"""Shared test fixtures. Ensures the repo root is on sys.path so `posture`
and `web` packages import when pytest is invoked from any directory."""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
