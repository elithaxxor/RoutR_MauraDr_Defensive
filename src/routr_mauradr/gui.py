# Authorized networks / own systems ONLY.
# Loopback GUI. It never imports research material and never connects to devices.
"""Local browser GUI for the defensive auditor.

The server binds to a loopback address only. Inventory and scope checks are
local. Discovery and TLS validation do not open device connections.
"""

from __future__ import annotations

import html
import ipaddress
import json
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

from .inventory import (
    InventoryError,
    import_assets,
    list_assets,
    list_observations,
    record_findings,
    remove_asset,
    save_asset,
    start_run,
)
from .scope import (
    ScopeError,
    authorize_scope,
    expand_scoped_cidr,
    load_scope,
    resolve_scoped_target,
)
from .types import JSONObject

_LOOPBACK = frozenset({"127.0.0.1", "::1"})
_MAX_BODY = 16_384


class GuiError(ValueError):
    """The GUI request or bind address was rejected."""


def require_loopback(host: str) -> str:
    """Accept only a loopback IP literal. Hostnames are rejected."""
    try:
        address = ipaddress.ip_address(host.strip())
    except ValueError as exc:
        raise GuiError("refusing GUI listen address: loopback IP literal required") from exc
    if not address.is_loopback:
        raise GuiError("refusing GUI listen address: loopback only")
    return str(address)


def serve(host: str = "127.0.0.1", port: int = 8765) -> int:
    """Serve the GUI until interrupted. Does not scan any network."""
    server = make_server(host, port)
    bound_host, bound_port = server.server_address[:2]
    print(f"routr-audit gui on http://{bound_host}:{bound_port}/", flush=True)
    print("loopback only; device discovery and TLS are not connected", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


def make_server(host: str, port: int) -> ThreadingHTTPServer:
    """Create a loopback HTTP server. Binding is the only socket this GUI opens."""
    if isinstance(port, bool) or not isinstance(port, int) or port < 0 or port > 65535:
        raise GuiError("GUI port must be between 0 and 65535")
    bind_host = require_loopback(host)
    server = ThreadingHTTPServer((bind_host, port), GuiHandler)
    server.daemon_threads = True
    return server


def import_inventory(db_path: str, assets_path: str) -> tuple[bool, str]:
    """Import a local asset file. Returns a status message and no network I/O."""
    try:
        database = _local_path(db_path, field="database")
        assets = _local_path(assets_path, field="assets file")
        count = import_assets(database, assets)
    except (GuiError, InventoryError) as exc:
        return False, str(exc)
    return True, f"imported {count} assets into {database.name}"


def save_one(db_path: str, fields: Mapping[str, str]) -> tuple[bool, str]:
    """Save one asset typed into the form. Empty optional fields are omitted."""
    try:
        database = _local_path(db_path, field="database")
        asset_id = save_asset(
            database,
            {
                "asset_id": fields.get("asset_id", ""),
                "address": fields.get("address", ""),
                "name": _blank(fields.get("name", "")),
                "vendor": _blank(fields.get("vendor", "")),
                "product": _blank(fields.get("product", "")),
                "role": _blank(fields.get("role", "")),
                "notes": _blank(fields.get("notes", "")),
            },
        )
    except (GuiError, InventoryError) as exc:
        return False, str(exc)
    return True, f"saved {asset_id}"


def delete_one(db_path: str, asset_id: str) -> tuple[bool, str]:
    """Remove one local asset. Does not contact the address."""
    try:
        database = _local_path(db_path, field="database")
        if not database.is_file():
            raise GuiError("database file not found")
        remove_asset(database, asset_id)
    except (GuiError, InventoryError) as exc:
        return False, str(exc)
    return True, f"removed {asset_id.strip()}"


def add_note(db_path: str, asset_id: str, status: str, summary: str) -> tuple[bool, str]:
    """Store one operator note against an existing asset."""
    try:
        database = _local_path(db_path, field="database")
        if not database.is_file():
            raise GuiError("database file not found")
        run_id = start_run(database, source="note")
        record_findings(
            database,
            run_id,
            [{"asset_id": asset_id, "source": "operator", "status": status, "summary": summary}],
        )
    except (GuiError, InventoryError) as exc:
        return False, str(exc)
    return True, f"saved a {status} note on {asset_id.strip()}"


def export_inventory(db_path: str) -> tuple[bool, str, bytes]:
    """Return the inventory as JSON. Does not create a database."""
    ok, message, rows = list_inventory(db_path)
    if not ok:
        return False, message, b""
    payload = json.dumps({"assets": rows}, indent=2).encode()
    return True, message, payload


def describe_scope(scope_path: str) -> tuple[bool, str]:
    """Explain a scope file in plain language. Does not contact the network."""
    try:
        scope = load_scope(_scope_path(scope_path))
    except (GuiError, ScopeError) as exc:
        return False, str(exc)
    cidrs = ", ".join(str(item) for item in scope["allow_cidrs"])
    ports = ", ".join(str(item) for item in scope["allow_ports"])
    return True, (
        f"Allowed networks: {cidrs}. Allowed ports: {ports}. "
        f"At most {scope['max_hosts']} hosts, {scope['max_concurrency']} at a time, "
        f"timeout {scope['timeout_seconds']}s, "
        f"rate {scope['max_rate_per_second']}/s. "
        "Reading this file does not contact those networks."
    )


def list_inventory(db_path: str) -> tuple[bool, str, list[JSONObject]]:
    """List an existing local inventory. Does not create a database."""
    try:
        database = _local_path(db_path, field="database")
        if not database.is_file():
            raise GuiError("database file not found")
        rows = list_assets(database)
    except (GuiError, InventoryError) as exc:
        return False, str(exc), []
    return True, f"{len(rows)} assets", rows


def validate_discover(authorized: bool, scope_path: str, cidr: str) -> tuple[bool, str]:
    """Validate a CIDR against a scope file. Does not connect."""
    try:
        scope = authorize_scope(authorized=authorized, scope_path=_scope_path(scope_path))
        hosts = expand_scoped_cidr(cidr, authorized=True, scope=scope)
    except (GuiError, ScopeError) as exc:
        return False, str(exc)
    shown = ", ".join(hosts[:8])
    extra = "" if len(hosts) <= 8 else f", +{len(hosts) - 8} more"
    return True, (
        f"in scope: {len(hosts)} hosts ({shown}{extra}). "
        "No device connection was opened; discovery is not implemented."
    )


def validate_tls(authorized: bool, scope_path: str, target: str) -> tuple[bool, str]:
    """Validate an ip:port against a scope file. Does not connect."""
    try:
        scope = authorize_scope(authorized=authorized, scope_path=_scope_path(scope_path))
        ip, port = _split_target(target)
        checked = resolve_scoped_target(ip, port, authorized=True, scope=scope)
    except (GuiError, ScopeError) as exc:
        return False, str(exc)
    return True, (
        f"in scope: {checked[0]}:{checked[1]}. "
        "No device connection was opened; TLS checks are not implemented."
    )


class GuiHandler(BaseHTTPRequestHandler):
    """Loopback form handler. Responses are HTML-escaped."""

    server_version = "RoutRDefensiveGUI"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler name
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler name
        self._dispatch()

    def log_message(self, format: str, *args: object) -> None:
        return

    def _dispatch(self) -> None:
        if not _loopback_header(self.headers.get("Host", "")):
            self._send(403, _page(_View(message="Host is not loopback.", ok=False)))
            return
        if self.command == "POST" and not _origin_ok(self.headers.get("Origin")):
            self._send(403, _page(_View(message="Origin is not loopback.", ok=False)))
            return
        path = urlsplit(self.path).path
        form = self._form() if self.command == "POST" else _query(self.path)
        if path == "/export" and self.command == "GET":
            self._export(form.get("db", ""))
            return
        if path == "/inventory" and self.command == "POST":
            self._inventory(form)
            return
        if path == "/scope" and self.command == "POST":
            self._scope(form)
            return
        if path == "/":
            self._send(200, _render(form))
            return
        missing = "That page is not part of the defensive GUI."
        self._send(404, _page(_View(message=missing, ok=False)))

    def _inventory(self, form: Mapping[str, str]) -> None:
        action = form.get("action", "")
        database = form.get("db", "")
        if action == "import":
            ok, message = import_inventory(database, form.get("assets", ""))
        elif action == "add":
            ok, message = save_one(database, form)
        elif action == "remove":
            ok, message = delete_one(database, form.get("asset_id", ""))
        elif action == "note":
            ok, message = add_note(
                database,
                form.get("asset_id", ""),
                form.get("status", ""),
                form.get("summary", ""),
            )
        elif action == "list":
            ok, message, _rows = list_inventory(database)
            if ok:
                message = "Showing the saved inventory."
        else:
            ok, message = False, "Choose import, add, remove, note, or list."
        self._send(200 if ok else 400, _render(form, message=message, ok=ok))

    def _scope(self, form: Mapping[str, str]) -> None:
        authorized = form.get("authorized") == "yes"
        action = form.get("action", "")
        scope_path = form.get("scope", "")
        target = form.get("target", "")
        if action == "read":
            ok, message = describe_scope(scope_path)
        elif action == "discover":
            ok, message = validate_discover(authorized, scope_path, target)
        elif action == "tls":
            ok, message = validate_tls(authorized, scope_path, target)
        else:
            ok, message = False, "Choose read, discover, or TLS."
        self._send(200 if ok else 400, _render(form, message=message, ok=ok))

    def _export(self, db_path: str) -> None:
        ok, message, payload = export_inventory(db_path)
        if not ok:
            self._send(400, _render({"db": db_path}, message=message, ok=False))
            return
        self._send_bytes(
            200,
            payload,
            "application/json; charset=utf-8",
            'attachment; filename="inventory.json"',
        )

    def _form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length < 0 or length > _MAX_BODY:
            return {}
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        parsed = parse_qs(raw, keep_blank_values=True, max_num_fields=32)
        return {key: values[0] for key, values in parsed.items() if values}

    def _send(self, status: int, body: str) -> None:
        self._send_bytes(status, body.encode("utf-8"), "text/html; charset=utf-8")

    def _send_bytes(
        self,
        status: int,
        body: bytes,
        content_type: str,
        disposition: str = "",
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
        self.send_header("Cache-Control", "no-store")
        if disposition:
            self.send_header("Content-Disposition", disposition)
        self.end_headers()
        self.wfile.write(body)


class _View:
    def __init__(
        self,
        *,
        message: str = "",
        ok: bool | None = None,
        db: str = "",
        assets: str = "",
        scope: str = "",
        target: str = "",
        query: str = "",
        rows: list[JSONObject] | None = None,
        notes: list[JSONObject] | None = None,
    ) -> None:
        self.message = message
        self.ok = ok
        self.db = db
        self.assets = assets
        self.scope = scope
        self.target = target
        self.query = query
        self.rows = rows
        self.notes = notes


def _render(form: Mapping[str, str], *, message: str = "", ok: bool | None = None) -> str:
    database = form.get("db", "")
    rows: list[JSONObject] | None = None
    notes: list[JSONObject] | None = None
    if database:
        loaded, load_message, rows, notes = _load_dashboard(database, form.get("q", ""))
        if not loaded and ok is None:
            ok, message = False, load_message
    return _page(
        _View(
            message=message,
            ok=ok,
            db=database,
            assets=form.get("assets", ""),
            scope=form.get("scope", ""),
            target=form.get("target", ""),
            query=form.get("q", ""),
            rows=rows,
            notes=notes,
        )
    )


def _load_dashboard(
    db_path: str, query: str
) -> tuple[bool, str, list[JSONObject], list[JSONObject]]:
    try:
        database = _local_path(db_path, field="database")
        if not database.is_file():
            return True, "", [], []
        ok, message, rows = list_inventory(db_path)
        if not ok:
            return False, message, [], []
        with_notes = list_observations(database)
    except (GuiError, InventoryError) as exc:
        return False, str(exc), [], []
    return True, "", _filter_rows(rows, query), with_notes


def _page(view: _View) -> str:
    banner = ""
    if view.message:
        kind = "ok" if view.ok else "bad"
        banner = f'<p class="banner {kind}">{html.escape(view.message)}</p>'
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>RoutR defensive auditor</title>
<style>
body {{ font: 16px/1.45 ui-sans-serif, sans-serif; margin: 1.5rem auto; max-width: 64rem;
  color: #1c1917; background: #f6f3ee; padding: 0 1rem; }}
h1 {{ font-size: 1.7rem; margin-bottom: 0.2rem; }}
h2 {{ font-size: 1.1rem; margin: 0 0 0.4rem; }}
section {{ background: #fff; border: 1px solid #e7e5e4; padding: 1rem; margin: 0.8rem 0; }}
label {{ display: block; margin: 0.45rem 0; }}
input, select {{ width: 100%; box-sizing: border-box; padding: 0.4rem; }}
button {{ margin: 0.4rem 0.4rem 0 0; padding: 0.4rem 0.7rem; }}
.grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem 1rem; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border-bottom: 1px solid #e7e5e4; text-align: left;
  padding: 0.35rem; vertical-align: top; }}
.banner {{ padding: 0.7rem 0.8rem; }}
.ok {{ background: #ecfdf3; }}
.bad {{ background: #fef2f2; }}
.note, .help {{ color: #57534e; }}
.pills span {{ display: inline-block; margin: 0 0.4rem 0.4rem 0; padding: 0.15rem 0.45rem;
  background: #f5f5f4; border: 1px solid #e7e5e4; }}
.remove {{ width: auto; }}
</style>
</head>
<body>
<h1>RoutR defensive auditor</h1>
<p class="help">Authorized networks and your own systems only. This page does not scan devices.</p>
<p class="pills"><span>Inventory: local file</span><span>Scope: checked locally</span>
<span>Device probes: not connected</span></p>
{banner}
{_inventory_section(view)}
{_scope_section(view)}
<p class="note">Firmware evidence, CVE matching, baselines, and topology are not in this GUI yet.
The isolated research tree is not available here.</p>
</body>
</html>
"""


def _inventory_section(view: _View) -> str:
    db = _attr(view.db)
    assets = _attr(view.assets)
    query = _attr(view.query)
    download = ""
    if view.db and view.rows is not None and Path(view.db).expanduser().is_file():
        href = "/export?db=" + quote(view.db)
        download = f'<a href="{html.escape(href)}">Download inventory JSON</a>'
    return f"""
<section>
  <h2>1. Inventory</h2>
  <p class="help">Use a local database path. Addresses must be IP addresses, not names.
  Import replaces an asset when the same id is imported again.</p>
  <form method="post" action="/inventory">
    <label>Database <input name="db" required placeholder="audit.db" value="{db}"></label>
    <label>Assets JSON
      <input name="assets" placeholder="examples/assets.example.json" value="{assets}">
    </label>
    <button name="action" value="import" type="submit">Import file</button>
    <button name="action" value="list" type="submit">Refresh</button>
  </form>
  <p>{download} {_examples()}</p>
  <form method="get" action="/">
    <input type="hidden" name="db" value="{db}">
    <input type="hidden" name="assets" value="{assets}">
    <input type="hidden" name="scope" value="{_attr(view.scope)}">
    <label>Filter saved assets
      <input name="q" placeholder="name, address, vendor" value="{query}">
    </label>
    <button type="submit">Filter</button>
  </form>
  {_table(view)}
  <h2>Add or update one asset</h2>
  <form method="post" action="/inventory">
    <input type="hidden" name="db" value="{db}">
    <div class="grid">
      <label>Id <input name="asset_id" required placeholder="sw1"></label>
      <label>Address <input name="address" required placeholder="192.168.56.10"></label>
      <label>Name <input name="name" placeholder="lab switch"></label>
      <label>Vendor <input name="vendor"></label>
      <label>Product <input name="product"></label>
      <label>Role <input name="role" placeholder="access"></label>
    </div>
    <label>Notes <input name="notes" placeholder="where it sits, no passwords"></label>
    <button name="action" value="add" type="submit">Save asset</button>
  </form>
  {_notes_form(view)}
  {_notes_table(view.notes or [])}
</section>
"""


def _notes_form(view: _View) -> str:
    return f"""
<h2>Add a note</h2>
<p class="help">Notes are your own observations. Status is pass, alert, error, or unknown.</p>
<form method="post" action="/inventory">
  <input type="hidden" name="db" value="{_attr(view.db)}">
  <div class="grid">
    <label>Asset id <input name="asset_id" required placeholder="sw1"></label>
    <label>Status
      <select name="status">
        <option>unknown</option><option>pass</option><option>alert</option><option>error</option>
      </select>
    </label>
  </div>
  <label>Summary
    <input name="summary" required placeholder="seen on the lab switch">
  </label>
  <button name="action" value="note" type="submit">Save note</button>
</form>
"""


def _scope_section(view: _View) -> str:
    return f"""
<section>
  <h2>2. Scope check</h2>
  <p class="help">Read the file first. A target check only confirms it is inside that file.
  Nothing is contacted, even when the target is in scope.</p>
  <form method="post" action="/scope">
    <input type="hidden" name="db" value="{_attr(view.db)}">
    <input type="hidden" name="assets" value="{_attr(view.assets)}">
    <label>
      <input type="checkbox" name="authorized" value="yes">
      I am authorized to assess this scope
    </label>
    <label>Scope file
      <input name="scope" required placeholder="examples/scope.example.toml"
        value="{_attr(view.scope)}">
    </label>
    <label>Target
      <input name="target" placeholder="192.168.56.0/28 or 192.168.56.10:443"
        value="{_attr(view.target)}">
    </label>
    <button name="action" value="read" type="submit">Explain scope</button>
    <button name="action" value="discover" type="submit">Check address range</button>
    <button name="action" value="tls" type="submit">Check TLS target</button>
  </form>
</section>
"""


def _table(view: _View) -> str:
    if view.rows is None:
        return ""
    if not view.rows:
        return "<p>No saved assets to show yet.</p>"
    columns = ("asset_id", "address", "name", "vendor", "product", "role", "notes")
    head = "".join(f"<th>{html.escape(name)}</th>" for name in columns)
    body = []
    for row in view.rows:
        cells = "".join(f"<td>{html.escape(str(row.get(name) or ''))}</td>" for name in columns)
        remove = (
            '<form method="post" action="/inventory">'
            f'<input type="hidden" name="db" value="{_attr(view.db)}">'
            f'<input type="hidden" name="asset_id" value="{_attr(str(row.get("asset_id") or ""))}">'
            '<button class="remove" name="action" value="remove" type="submit">Remove</button>'
            "</form>"
        )
        body.append(f"<tr>{cells}<td>{remove}</td></tr>")
    return (
        "<table><thead><tr>"
        + head
        + "<th></th></tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table>"
    )


def _notes_table(notes: list[JSONObject]) -> str:
    if not notes:
        return ""
    body = []
    for note in notes:
        cells = "".join(
            f"<td>{html.escape(str(note.get(name) or ''))}</td>"
            for name in ("observed_at", "asset_id", "status", "summary")
        )
        body.append(f"<tr>{cells}</tr>")
    return (
        "<h2>Recent notes</h2><table><thead><tr>"
        "<th>when</th><th>asset</th><th>status</th><th>summary</th>"
        "</tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table>"
    )


def _examples() -> str:
    assets = Path("examples/assets.example.json")
    scope = Path("examples/scope.example.toml")
    if not assets.is_file() or not scope.is_file():
        return ""
    href = "/?" + "&".join(
        (
            "db=" + quote("audit.db"),
            "assets=" + quote(str(assets)),
            "scope=" + quote(str(scope)),
        )
    )
    return f'<a href="{html.escape(href)}">Fill the example lab paths</a>'


def _filter_rows(rows: list[JSONObject], query: str) -> list[JSONObject]:
    needle = query.strip().lower()[:64]
    if not needle:
        return rows
    keys = ("asset_id", "address", "name", "vendor", "product", "role", "notes")
    return [
        row
        for row in rows
        if any(needle in str(row.get(key) or "").lower() for key in keys)
    ]


def _attr(value: str) -> str:
    return html.escape(value, quote=True)


def _blank(value: str) -> str | None:
    text = value.strip()
    return text or None


def _query(path: str) -> dict[str, str]:
    parsed = parse_qs(urlsplit(path).query, keep_blank_values=True, max_num_fields=20)
    return {key: values[0] for key, values in parsed.items() if values}


def _local_path(value: str, *, field: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise GuiError(f"{field} is required")
    path = Path(value.strip())
    _refuse_research(path)
    return path


def _scope_path(value: str) -> Path:
    return _local_path(value, field="scope file")


def _refuse_research(path: Path) -> None:
    parts = [part.lower() for part in path.expanduser().parts]
    for index in range(len(parts) - 1):
        if parts[index] == "optional" and parts[index + 1] == "research":
            raise GuiError("refusing a path inside the isolated research tree")


def _loopback_header(value: str) -> bool:
    text = value.strip().lower()
    if text.startswith("["):
        name = text[1:].split("]", 1)[0]
    elif text.count(":") == 1:
        name = text.rsplit(":", 1)[0]
    else:
        name = text
    return name in {"127.0.0.1", "localhost", "::1"}


def _origin_ok(origin: str | None) -> bool:
    if origin is None:
        return True
    host = urlsplit(origin).hostname or ""
    return host.lower() in {"127.0.0.1", "localhost", "::1"}


def _split_target(target: str) -> tuple[str, int]:
    if target.startswith("["):
        host, sep, rest = target[1:].partition("]")
        if not sep or not rest.startswith(":"):
            raise ScopeError("tls target must look like [IPv6]:port")
        return host, _port(rest[1:])
    host, sep, port_text = target.rpartition(":")
    if not sep or not host:
        raise ScopeError("tls target must look like 192.168.56.10:443")
    return host, _port(port_text)


def _port(text: str) -> int:
    try:
        port = int(text)
    except ValueError as exc:
        raise ScopeError(f"invalid port: {text}") from exc
    if port < 1 or port > 65535:
        raise ScopeError(f"invalid port: {port}")
    return port
