# Authorized networks / own systems ONLY.
# Local inventory only. This module never opens a socket and never imports
# optional research material.
"""Offline SQLite inventory for operator-supplied assets."""

from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from sqlite3 import Connection

from .types import JSONObject

_SCHEMA_VERSION = "1"
_MAX_BYTES = 1_048_576
_MAX_ASSETS = 1000
_ID_MAX = 64
_TEXT_MAX = 256
_NOTES_MAX = 512
_ALLOWED_FIELDS = frozenset(
    {"asset_id", "address", "name", "vendor", "product", "role", "notes"}
)
_SECRET_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "private_key",
        "credential",
        "credentials",
        "community",
        "psk",
        "authorization",
    }
)
_STATUSES = frozenset({"pass", "alert", "error", "unknown"})

_CREATE = (
    """
    CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS runs (
        run_id TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        started_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS assets (
        asset_id TEXT PRIMARY KEY,
        address TEXT NOT NULL,
        name TEXT,
        vendor TEXT,
        product TEXT,
        role TEXT,
        notes TEXT,
        updated_at TEXT NOT NULL,
        run_id TEXT NOT NULL REFERENCES runs(run_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS observations (
        observation_id INTEGER PRIMARY KEY,
        run_id TEXT NOT NULL REFERENCES runs(run_id),
        asset_id TEXT REFERENCES assets(asset_id),
        source TEXT NOT NULL,
        status TEXT NOT NULL,
        summary TEXT NOT NULL,
        observed_at TEXT NOT NULL
    )
    """,
)


class InventoryError(ValueError):
    """The inventory file or database request was rejected."""


def open_inventory(db_path: Path) -> Connection:
    """Open a local inventory database. Creates it with mode 0600 if needed."""
    path = _database_path(db_path)
    if not path.exists():
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        os.close(fd)
    elif not path.is_file():
        raise InventoryError("database path is not a regular file")
    os.chmod(path, 0o600)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    _ensure_schema(connection)
    return connection


def start_run(db_path: Path, *, source: str) -> str:
    """Record one assessment run and return its id."""
    label = _short_text(source, field="source")
    run_id = uuid.uuid4().hex
    with open_inventory(db_path) as connection:
        connection.execute(
            "INSERT INTO runs (run_id, source, started_at) VALUES (?, ?, ?)",
            (run_id, label, _now()),
        )
    return run_id


def import_assets(db_path: Path, assets_json: Path) -> int:
    """Import operator-supplied assets. Returns the number written."""
    assets = _load_assets(assets_json)
    run_id = start_run(db_path, source="import")
    now = _now()
    with open_inventory(db_path) as connection:
        for asset in assets:
            connection.execute(
                """
                INSERT INTO assets (
                    asset_id, address, name, vendor, product, role, notes, updated_at, run_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    address = excluded.address,
                    name = excluded.name,
                    vendor = excluded.vendor,
                    product = excluded.product,
                    role = excluded.role,
                    notes = excluded.notes,
                    updated_at = excluded.updated_at,
                    run_id = excluded.run_id
                """,
                (
                    asset["asset_id"],
                    asset["address"],
                    asset.get("name"),
                    asset.get("vendor"),
                    asset.get("product"),
                    asset.get("role"),
                    asset.get("notes"),
                    now,
                    run_id,
                ),
            )
    return len(assets)


def list_assets(db_path: Path) -> list[JSONObject]:
    """Return stored assets. Does not include observations or raw imports."""
    with open_inventory(db_path) as connection:
        rows = connection.execute(
            """
            SELECT asset_id, address, name, vendor, product, role, notes, updated_at, run_id
            FROM assets
            ORDER BY asset_id
            """
        ).fetchall()
    return [dict(row) for row in rows]


def record_findings(db_path: Path, run_id: str, findings: list[JSONObject]) -> int:
    """Store observations for an existing run. Raw snapshots are not retained."""
    if not isinstance(findings, list):
        raise InventoryError("findings must be a list")
    if len(findings) > _MAX_ASSETS:
        raise InventoryError(f"refusing more than {_MAX_ASSETS} observations")
    prepared: list[tuple[str, str | None, str, str, str, str]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            raise InventoryError("each observation must be an object")
        _reject_secrets(finding)
        unknown = set(finding) - {"asset_id", "source", "status", "summary"}
        if unknown:
            raise InventoryError(f"unsupported observation fields: {', '.join(sorted(unknown))}")
        status = finding.get("status")
        if status not in _STATUSES:
            raise InventoryError("observation status must be pass, alert, error, or unknown")
        prepared.append(
            (
                _id(run_id, field="run_id"),
                _optional_id(finding.get("asset_id")),
                _short_text(finding.get("source"), field="source"),
                str(status),
                _short_text(finding.get("summary"), field="summary"),
                _now(),
            )
        )
    with open_inventory(db_path) as connection:
        if connection.execute("SELECT 1 FROM runs WHERE run_id = ?", (run_id,)).fetchone() is None:
            raise InventoryError("unknown run")
        for item in prepared:
            asset_id = item[1]
            if asset_id is not None and (
                connection.execute(
                    "SELECT 1 FROM assets WHERE asset_id = ?", (asset_id,)
                ).fetchone()
                is None
            ):
                raise InventoryError(f"unknown asset: {asset_id}")
            connection.execute(
                """
                INSERT INTO observations (
                    run_id, asset_id, source, status, summary, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                item,
            )
    return len(prepared)


def _ensure_schema(connection: Connection) -> None:
    existing = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta'"
    ).fetchone()
    if existing is None:
        for statement in _CREATE:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', ?)",
            (_SCHEMA_VERSION,),
        )
        return
    version = connection.execute(
        "SELECT value FROM meta WHERE key = 'schema_version'"
    ).fetchone()
    if version is None or version["value"] != _SCHEMA_VERSION:
        found = None if version is None else version["value"]
        raise InventoryError(f"unsupported inventory schema version: {found}")


def _load_assets(path: Path) -> list[dict[str, str | None]]:
    file_path = Path(path)
    if file_path.is_symlink() or not file_path.is_file():
        raise InventoryError("assets file must be a regular file")
    size = file_path.stat().st_size
    if size > _MAX_BYTES:
        raise InventoryError("assets file is too large")
    try:
        raw = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InventoryError("assets file is not valid JSON") from exc
    if isinstance(raw, dict):
        _reject_secrets(raw)
        items = raw.get("assets")
    elif isinstance(raw, list):
        items = raw
    else:
        raise InventoryError("assets file must be a list or an object with assets")
    if not isinstance(items, list):
        raise InventoryError("assets must be a list")
    if len(items) > _MAX_ASSETS:
        raise InventoryError(f"refusing more than {_MAX_ASSETS} assets")
    prepared: list[dict[str, str | None]] = []
    seen: set[str] = set()
    for item in items:
        prepared.append(_asset(item, seen))
    return prepared


def _asset(item: object, seen: set[str]) -> dict[str, str | None]:
    if not isinstance(item, dict):
        raise InventoryError("each asset must be an object")
    _reject_secrets(item)
    unknown = set(item) - _ALLOWED_FIELDS
    if unknown:
        raise InventoryError(f"unsupported asset fields: {', '.join(sorted(unknown))}")
    asset_id = _id(item.get("asset_id"), field="asset_id")
    if asset_id in seen:
        raise InventoryError(f"duplicate asset_id: {asset_id}")
    seen.add(asset_id)
    address = item.get("address")
    if not isinstance(address, str):
        raise InventoryError("asset address must be an IP literal")
    try:
        ipaddress.ip_address(address.strip())
    except ValueError as exc:
        raise InventoryError(f"refusing hostname or invalid address: {address}") from exc
    return {
        "asset_id": asset_id,
        "address": address.strip(),
        "name": _optional_text(item.get("name"), "name", _TEXT_MAX),
        "vendor": _optional_text(item.get("vendor"), "vendor", _TEXT_MAX),
        "product": _optional_text(item.get("product"), "product", _TEXT_MAX),
        "role": _optional_text(item.get("role"), "role", _TEXT_MAX),
        "notes": _optional_text(item.get("notes"), "notes", _NOTES_MAX),
    }


def _reject_secrets(value: dict[str, object]) -> None:
    for key in value:
        if key.lower() in _SECRET_KEYS:
            raise InventoryError(f"refusing secret field: {key}")


def _database_path(db_path: Path) -> Path:
    path = Path(db_path)
    if path.is_symlink():
        raise InventoryError("refusing symlink database path")
    parent = path.parent
    if not parent.is_dir():
        raise InventoryError("database directory does not exist")
    return path


def _id(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise InventoryError(f"{field} must be a string")
    text = value.strip()
    if not text or len(text) > _ID_MAX:
        raise InventoryError(f"{field} must be 1 to {_ID_MAX} characters")
    if any(not (char.isalnum() or char in "._-") for char in text):
        raise InventoryError(f"{field} contains unsupported characters")
    return text


def _optional_id(value: object) -> str | None:
    if value is None:
        return None
    return _id(value, field="asset_id")


def _optional_text(value: object, field: str, limit: int) -> str | None:
    if value is None:
        return None
    return _bounded_text(value, field=field, limit=limit)


def _short_text(value: object, *, field: str) -> str:
    return _bounded_text(value, field=field, limit=_TEXT_MAX)


def _bounded_text(value: object, *, field: str, limit: int) -> str:
    if not isinstance(value, str):
        raise InventoryError(f"{field} must be a string")
    text = value.strip()
    if not text or len(text) > limit:
        raise InventoryError(f"{field} must be 1 to {limit} characters")
    return text


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
