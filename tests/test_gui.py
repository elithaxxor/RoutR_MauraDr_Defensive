# Authorized networks / own systems ONLY. Action tests never open a device socket.
import json
import pathlib
import threading
import urllib.error
import urllib.parse
import urllib.request

import pytest

from routr_mauradr import cli
from routr_mauradr.gui import (
    GuiError,
    import_inventory,
    list_inventory,
    make_server,
    require_loopback,
    validate_discover,
    validate_tls,
)


def test_listen_address_must_be_loopback() -> None:
    with pytest.raises(GuiError):
        require_loopback("0.0.0.0")
    assert cli.main(["gui", "--listen", "0.0.0.0", "--port", "9"]) == 2


def test_import_list_and_escape(tmp_path: pathlib.Path) -> None:
    assets = tmp_path / "assets.json"
    assets.write_text(
        json.dumps(
            [
                {
                    "asset_id": "sw1",
                    "address": "192.168.56.10",
                    "name": "<script>alert(1)</script>",
                }
            ]
        ),
        encoding="utf-8",
    )
    database = tmp_path / "audit.db"
    ok, message = import_inventory(str(database), str(assets))
    assert ok, message
    ok, _message, rows = list_inventory(str(database))
    assert ok and rows[0]["name"] == "<script>alert(1)</script>"
    page = _post("/inventory", f"action=list&db={urllib.parse.quote(str(database))}")
    escaped = "&" + "lt;script&" + "gt;"
    assert escaped in page
    assert "<script>alert" not in page


def test_scope_validation_does_not_connect(tmp_path: pathlib.Path) -> None:
    scope = tmp_path / "scope.toml"
    scope.write_text(
        'allow_cidrs = ["192.168.56.0/28"]\nallow_ports = [443]\nmax_hosts = 16\n',
        encoding="utf-8",
    )
    ok, message = validate_discover(False, str(scope), "192.168.56.0/28")
    assert not ok and "authorized" in message
    ok, message = validate_discover(True, str(scope), "10.1.1.0/30")
    assert not ok and "outside" in message
    ok, message = validate_discover(True, str(scope), "192.168.56.0/30")
    assert ok and "No device connection" in message
    ok, message = validate_tls(True, str(scope), "192.168.56.10:22")
    assert not ok and "port 22" in message


def test_gui_refuses_research_tree(tmp_path: pathlib.Path) -> None:
    root = tmp_path / "optional" / "research"
    root.mkdir(parents=True)
    assets = root / "assets.json"
    assets.write_text("[]", encoding="utf-8")
    ok, message = import_inventory(str(tmp_path / "audit.db"), str(assets))
    assert not ok and "research" in message


def test_loopback_page_round_trip(tmp_path: pathlib.Path) -> None:
    server = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        page = _urlopen(f"http://{host}:{port}/")
        assert "does not scan devices" in page
        missing = _urlopen(
            f"http://{host}:{port}/inventory",
            data=b"action=list&db=/tmp/does-not-exist-routr.db",
        )
        assert "not found" in missing.lower()
    finally:
        server.shutdown()
        server.server_close()


def _post(path: str, body: str) -> str:
    server = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        return _urlopen(f"http://{host}:{port}{path}", data=body.encode())
    finally:
        server.shutdown()
        server.server_close()


def _urlopen(url: str, data: bytes | None = None) -> str:
    request = urllib.request.Request(url, data=data)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.read().decode()
