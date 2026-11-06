# Authorized networks / own systems ONLY. Defensive skeleton; no operational implementation.
# All stubs fail closed (NotImplementedError). Never imports optional research material.
"""Baseline alerts from local config snapshots; never stores raw config or changes devices."""

from pathlib import Path

from .types import Finding


def check(rules_path: Path, snapshot: Path) -> list[Finding]:
    """Evaluate rules against a snapshot."""
    raise NotImplementedError("Defensive skeleton; not implemented")
