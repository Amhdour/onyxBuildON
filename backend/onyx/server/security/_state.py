"""Deprecated module.

Production security APIs are DB-backed and must not use in-memory state.
This file is retained only for backwards import compatibility.
"""

from pathlib import Path

REPORT_DIR = Path("security_reports")
