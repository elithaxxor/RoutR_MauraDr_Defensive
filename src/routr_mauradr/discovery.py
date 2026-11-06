# Authorized networks / own systems ONLY. Defensive skeleton; no operational implementation.
# All stubs fail closed (NotImplementedError). Never imports optional research material.
"""TCP reachability on allowlisted ports for in-scope IP literals."""

from .types import Finding, Scope


def discover(cidr: str, *, authorized: bool, scope: Scope) -> list[Finding]:
    """Bounded reachability check across an in-scope CIDR."""
    raise NotImplementedError("Defensive skeleton; not implemented")
