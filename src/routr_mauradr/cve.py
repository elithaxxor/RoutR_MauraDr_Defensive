# Authorized networks / own systems ONLY. Defensive skeleton; no operational implementation.
# All stubs fail closed (NotImplementedError). Never imports optional research material.
"""Offline informational CVE matching via explicit CPE mappings; not conclusive."""

from pathlib import Path

from .types import Finding


def import_dataset(db_path: Path, dataset: Path, *, sha256: str) -> int:
    """Import a checksum-verified local dataset."""
    raise NotImplementedError("Defensive skeleton; not implemented")


def match(db_path: Path) -> list[Finding]:
    """Return possible matches with provenance; unsupported versions yield unknown."""
    raise NotImplementedError("Defensive skeleton; not implemented")
