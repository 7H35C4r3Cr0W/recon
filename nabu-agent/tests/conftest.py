"""Shared test fixtures. Kept light: the policy-invariant AST tests need nothing; behavioural tests
monkeypatch the engine chokepoint. (Async test-DB + Redis fixtures land in Phase 2 integration.)"""
from __future__ import annotations

import pathlib
import sys

# Ensure the package is importable when pytest is invoked from the repo root.
_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
