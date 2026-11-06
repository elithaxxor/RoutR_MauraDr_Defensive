# Authorized networks / own systems ONLY. Skeleton checks; no network.
import ast
import pathlib

import pytest

PKG = pathlib.Path(__file__).resolve().parents[1] / "src" / "routr_mauradr"


def test_no_research_imports():
    for f in PKG.glob("*.py"):
        for node in ast.walk(ast.parse(f.read_text())):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            assert not any(n.split(".")[0] in {"impacket", "pgrok"} for n in names), f


def test_cli_fails_closed(monkeypatch):
    monkeypatch.syspath_prepend(str(PKG.parent))
    from routr_mauradr import cli

    with pytest.raises(NotImplementedError):
        cli.main([])
