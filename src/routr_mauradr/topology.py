# Authorized networks / own systems ONLY. Defensive skeleton; no operational implementation.
# All stubs fail closed (NotImplementedError). Never imports optional research material.
"""Topology from operator mapping and observed facts only; no inferred links."""

from pathlib import Path
from typing import Literal


def render(mapping_path: Path, *, fmt: Literal["mermaid", "dot"]) -> str:
    """Render Mermaid or DOT text."""
    raise NotImplementedError("Defensive skeleton; not implemented")
