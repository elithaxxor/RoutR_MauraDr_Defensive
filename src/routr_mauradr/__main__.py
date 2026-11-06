# Authorized networks / own systems ONLY. Defensive skeleton; no operational implementation.
# All stubs fail closed (NotImplementedError). Never imports optional research material.
"""Adapter for `python -m routr_mauradr`; fails closed via cli.main."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
