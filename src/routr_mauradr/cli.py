# Authorized networks / own systems ONLY. Defensive skeleton; no operational implementation.
# All stubs fail closed (NotImplementedError). Never imports optional research material.
"""Command-line entry point (skeleton). Not functional; --help is not implemented.

Planned: every network command (discover, tls check) requires --authorized and --scope.
No research commands exist or will be added here.
"""

from argparse import ArgumentParser
from collections.abc import Sequence


def build_parser() -> ArgumentParser:
    """Build the planned parser."""
    raise NotImplementedError("Defensive skeleton; not implemented")


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for routr-audit. Fails closed until implemented."""
    raise NotImplementedError("Defensive skeleton; not implemented")
