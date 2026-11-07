# Authorized networks / own systems ONLY. These tests never open a socket.
import ast
import pathlib
import socket

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PKG = ROOT / "src" / "routr_mauradr"
SCOPE = """
allow_cidrs = ["192.168.56.0/28"]
allow_ports = [443]
max_hosts = 16
max_concurrency = 4
timeout_seconds = 3
max_rate_per_second = 5
"""


@pytest.fixture(autouse=True)
def _import_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(PKG.parent))


@pytest.fixture
def scope_file(tmp_path: pathlib.Path) -> pathlib.Path:
    path = tmp_path / "scope.toml"
    path.write_text(SCOPE, encoding="utf-8")
    return path


def test_no_research_imports() -> None:
    for source in PKG.glob("*.py"):
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            assert not any(name.split(".")[0] in {"impacket", "pgrok"} for name in names), source


def test_help_makes_no_connection(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _forbid_sockets(monkeypatch)
    from routr_mauradr import cli

    assert cli.main(["--help"]) == 0
    assert "authorized" in capsys.readouterr().out.lower()


def test_discover_requires_authorized(
    monkeypatch: pytest.MonkeyPatch, scope_file: pathlib.Path
) -> None:
    _forbid_sockets(monkeypatch)
    from routr_mauradr import cli

    status = cli.main(["--scope", str(scope_file), "discover", "192.168.56.0/28"])
    assert status == 2


def test_discover_requires_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    _forbid_sockets(monkeypatch)
    from routr_mauradr import cli

    status = cli.main(["--authorized", "discover", "192.168.56.0/28"])
    assert status == 2


def test_discover_rejects_out_of_scope(
    monkeypatch: pytest.MonkeyPatch, scope_file: pathlib.Path
) -> None:
    _forbid_sockets(monkeypatch)
    from routr_mauradr import cli

    status = cli.main(
        ["--authorized", "--scope", str(scope_file), "discover", "10.0.0.0/30"]
    )
    assert status == 2


def test_discover_rejects_hostname(
    monkeypatch: pytest.MonkeyPatch, scope_file: pathlib.Path
) -> None:
    _forbid_sockets(monkeypatch)
    from routr_mauradr import cli

    status = cli.main(
        ["--authorized", "--scope", str(scope_file), "discover", "router.local/32"]
    )
    assert status == 2


def test_in_scope_discover_does_not_connect(
    monkeypatch: pytest.MonkeyPatch,
    scope_file: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _forbid_sockets(monkeypatch)
    from routr_mauradr import cli

    status = cli.main(
        ["--authorized", "--scope", str(scope_file), "discover", "192.168.56.0/28"]
    )
    assert status == 2
    assert "not implemented" in capsys.readouterr().err


def test_tls_requires_authorization(
    monkeypatch: pytest.MonkeyPatch, scope_file: pathlib.Path
) -> None:
    _forbid_sockets(monkeypatch)
    from routr_mauradr import cli

    status = cli.main(["--scope", str(scope_file), "tls", "check", "192.168.56.10:443"])
    assert status == 2


def test_tls_rejects_disallowed_port(
    monkeypatch: pytest.MonkeyPatch, scope_file: pathlib.Path
) -> None:
    _forbid_sockets(monkeypatch)
    from routr_mauradr import cli

    status = cli.main(
        ["--authorized", "--scope", str(scope_file), "tls", "check", "192.168.56.10:22"]
    )
    assert status == 2


def test_offline_command_does_not_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    _forbid_sockets(monkeypatch)
    from routr_mauradr import cli

    assert cli.main(["inventory"]) == 2


def test_scope_rejects_excessive_host_budget(tmp_path: pathlib.Path) -> None:
    from routr_mauradr.scope import ScopeError, load_scope

    path = tmp_path / "wide.toml"
    path.write_text(
        'allow_cidrs = ["192.168.0.0/24"]\nallow_ports = [443]\nmax_hosts = 100000\n',
        encoding="utf-8",
    )
    with pytest.raises(ScopeError):
        load_scope(path)


def test_expand_stops_above_max_hosts(tmp_path: pathlib.Path) -> None:
    from routr_mauradr.scope import ScopeError, expand_scoped_cidr, load_scope

    path = tmp_path / "small.toml"
    path.write_text(
        'allow_cidrs = ["192.168.56.0/24"]\nallow_ports = [443]\nmax_hosts = 4\n',
        encoding="utf-8",
    )
    scope = load_scope(path)
    with pytest.raises(ScopeError):
        expand_scoped_cidr("192.168.56.0/28", authorized=True, scope=scope)


def _forbid_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("network command opened a socket")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
