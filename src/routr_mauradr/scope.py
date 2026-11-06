# Authorized networks / own systems ONLY. Defensive skeleton; no operational implementation.
# All stubs fail closed (NotImplementedError). Never imports optional research material.
"""Scope guard. Every network helper must pass here before any connect.

Contract: --authorized AND --scope FILE mandatory; IP literals only (no DNS);
hard caps on hosts, concurrency, timeout and rate from the scope file.
"""

from pathlib import Path

from .types import Scope


def load_scope(path: Path) -> Scope:
    """Parse and validate a TOML scope file."""
    raise NotImplementedError("Defensive skeleton; not implemented")


def authorize_scope(*, authorized: bool, scope_path: Path) -> Scope:
    """Refuse unless authorized is True and the scope file is valid."""
    raise NotImplementedError("Defensive skeleton; not implemented")


def resolve_scoped_target(ip: str, port: int, *, authorized: bool, scope: Scope) -> tuple[str, int]:
    """Accept an IP literal and port only if inside scope."""
    raise NotImplementedError("Defensive skeleton; not implemented")


def expand_scoped_cidr(cidr: str, *, authorized: bool, scope: Scope) -> tuple[str, ...]:
    """Expand a CIDR inside scope, bounded by max_hosts."""
    raise NotImplementedError("Defensive skeleton; not implemented")
