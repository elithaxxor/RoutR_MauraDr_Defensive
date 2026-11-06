# Authorized networks / own systems ONLY. Defensive skeleton; no operational implementation.
# All stubs fail closed (NotImplementedError). Never imports optional research material.
"""Firmware versions from operator-supplied metadata only; unknown otherwise."""

from pathlib import Path


def import_firmware(db_path: Path, firmware_json: Path) -> int:
    """Import firmware metadata; returns count."""
    raise NotImplementedError("Defensive skeleton; not implemented")


def firmware_for(db_path: Path, asset_id: str) -> str | None:
    """Return version, or None meaning unknown."""
    raise NotImplementedError("Defensive skeleton; not implemented")
