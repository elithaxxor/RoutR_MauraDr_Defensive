# Authorized networks / own systems ONLY. Defensive skeleton; no operational implementation.
# All stubs fail closed (NotImplementedError). Never imports optional research material.
"""Certificate health: SAN, expiry, chain. Verification always enabled."""

from .types import Finding, Scope


def check_certificate(
    ip: str, port: int, *, server_name: str | None, authorized: bool, scope: Scope
) -> Finding:
    """Minimal handshake against an in-scope IP; server_name is for SNI/identity only."""
    raise NotImplementedError("Defensive skeleton; not implemented")
