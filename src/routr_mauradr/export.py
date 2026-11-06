# Authorized networks / own systems ONLY. Defensive skeleton; no operational implementation.
# All stubs fail closed (NotImplementedError). Never imports optional research material.
"""JSON and escaped static HTML export."""

from pathlib import Path
from typing import Literal


def export_results(db_path: Path, out: Path, *, fmt: Literal["json", "html"]) -> None:
    """Write results; HTML fully escaped, no secrets."""
    raise NotImplementedError("Defensive skeleton; not implemented")
