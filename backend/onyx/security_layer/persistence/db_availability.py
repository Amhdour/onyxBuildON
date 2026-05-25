from __future__ import annotations

from onyx.db.engine.sql_engine import get_sqlalchemy_engine


def is_security_layer_db_available() -> bool:
    try:
        get_sqlalchemy_engine()
        return True
    except RuntimeError as exc:
        if "Engine not initialized" in str(exc):
            return False
        raise
