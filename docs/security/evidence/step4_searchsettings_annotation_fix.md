]633;E;echo "# Step 4 SearchSettings Annotation Fix";bf4feba7-51ca-4d8c-aae1-1dd0a2f229c2]633;C# Step 4 SearchSettings Annotation Fix

Date: Mon May 25 11:34:13 UTC 2026
Branch: security-layer-mvp
Commit before fix: b885f52

## Root cause

SearchSettings was imported only under TYPE_CHECKING but used in runtime annotations in backend/onyx/context/search/models.py.

## Fix

Added: from __future__ import annotations

## Validation command

python -m pytest backend/tests/security_layer -q

## Result

Record the pytest result here.
