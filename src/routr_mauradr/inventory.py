# Authorized networks / own systems ONLY. Defensive skeleton; no operational implementation.
# All stubs fail closed (NotImplementedError). Never imports optional research material.
"""Offline local asset inventory (SQLite, planned)."""

from pathlib import Path

from .types import JSONObject


def import_assets(db_path: Path, assets_json: Path) -> int:
    """Import operator-supplied assets; returns count."""
    raise NotImplementedError("Defensive skeleton; not implemented")


def list_assets(db_path: Path) -> list[JSONObject]:
    """Return stored assets."""
    raise NotImplementedError("Defensive skeleton; not implemented")
