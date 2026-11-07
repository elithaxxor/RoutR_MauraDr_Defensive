# Authorized networks / own systems ONLY. These tests never open a socket.
import json
import pathlib
import socket
import stat

import pytest

from routr_mauradr import cli
from routr_mauradr.inventory import (
    InventoryError,
    import_assets,
    list_assets,
    record_findings,
    start_run,
)


@pytest.fixture(autouse=True)
def _no_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("inventory opened a socket")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)


def test_import_and_list_round_trip(tmp_path: pathlib.Path) -> None:
    assets = tmp_path / "assets.json"
    assets.write_text(
        json.dumps(
            {
                "assets": [
                    {
                        "asset_id": "sw1",
                        "address": "192.168.56.10",
                        "name": "lab-switch",
                        "vendor": "example",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    db = tmp_path / "audit.db"
    assert cli.main(["--db", str(db), "inventory", "import", str(assets)]) == 0
    mode = stat.S_IMODE(db.stat().st_mode)
    assert mode & 0o077 == 0
    listed = list_assets(db)
    assert listed[0]["asset_id"] == "sw1"
    assert listed[0]["address"] == "192.168.56.10"
    assert "password" not in listed[0]


def test_import_rejects_hostname_and_secret(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "audit.db"
    host = tmp_path / "host.json"
    host.write_text(
        json.dumps([{"asset_id": "a", "address": "router.local"}]),
        encoding="utf-8",
    )
    with pytest.raises(InventoryError):
        import_assets(db, host)
    secret = tmp_path / "secret.json"
    secret.write_text(
        json.dumps([{"asset_id": "a", "address": "192.168.56.10", "password": "nope"}]),
        encoding="utf-8",
    )
    with pytest.raises(InventoryError):
        import_assets(db, secret)
    assert not db.exists()


def test_inventory_requires_database(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assets = tmp_path / "assets.json"
    assets.write_text("[]", encoding="utf-8")
    assert cli.main(["inventory", "import", str(assets)]) == 2
    assert "--db" in capsys.readouterr().err


def test_bare_inventory_does_not_create_database(tmp_path: pathlib.Path) -> None:
    assert cli.main(["inventory"]) == 2
    assert list(tmp_path.glob("*.db")) == []


def test_observations_require_known_asset(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "audit.db"
    assets = tmp_path / "assets.json"
    assets.write_text(
        json.dumps([{"asset_id": "sw1", "address": "192.168.56.10"}]),
        encoding="utf-8",
    )
    import_assets(db, assets)
    run_id = start_run(db, source="manual")
    assert record_findings(
        db,
        run_id,
        [{"asset_id": "sw1", "source": "import", "status": "unknown", "summary": "no probe"}],
    ) == 1
    with pytest.raises(InventoryError):
        record_findings(
            db,
            run_id,
            [{"asset_id": "missing", "source": "import", "status": "alert", "summary": "no"}],
        )
