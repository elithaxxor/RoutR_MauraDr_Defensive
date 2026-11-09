# Authorized networks / own systems ONLY.
# Loopback GUI. It never imports research material and never connects to devices.
"""Local browser GUI for the defensive auditor.

The server binds to a loopback address only. Inventory and scope checks are
local. Discovery and TLS validation do not open device connections.
"""

from __future__ import annotations

import html
import ipaddress
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .inventory import InventoryError, import_assets, list_assets
from .scope import ScopeError, authorize_scope, expand_scoped_cidr, resolve_scoped_target
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
    return True, f"imported {count} assets"


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
            self._send(403, _page("Rejected", "Host is not loopback.", ok=False))
            return
        if self.command == "POST" and not _origin_ok(self.headers.get("Origin")):
            self._send(403, _page("Rejected", "Origin is not loopback.", ok=False))
            return
        path = urlsplit(self.path).path
        form = self._form() if self.command == "POST" else {}
        if path == "/":
            self._send(200, _page("RoutR defensive auditor"))
            return
        if path == "/inventory" and self.command == "POST":
            self._inventory(form)
            return
        if path == "/scope" and self.command == "POST":
            self._scope(form)
            return
        self._send(404, _page("Not found", "That page is not part of the defensive GUI.", ok=False))

    def _inventory(self, form: Mapping[str, str]) -> None:
        action = form.get("action", "")
        database = form.get("db", "")
        if action == "import":
            ok, message = import_inventory(database, form.get("assets", ""))
            rows: list[JSONObject] = []
            if ok:
                _, _, rows = list_inventory(database)
        elif action == "list":
            ok, message, rows = list_inventory(database)
        else:
            ok, message, rows = False, "unknown inventory action", []
        self._send(200 if ok else 400, _page("Inventory", message, ok=ok, rows=rows))

    def _scope(self, form: Mapping[str, str]) -> None:
        authorized = form.get("authorized") == "yes"
        action = form.get("action", "")
        scope_path = form.get("scope", "")
        target = form.get("target", "")
        if action == "discover":
            ok, message = validate_discover(authorized, scope_path, target)
        elif action == "tls":
            ok, message = validate_tls(authorized, scope_path, target)
        else:
            ok, message = False, "unknown scope action"
        self._send(200 if ok else 400, _page("Scope check", message, ok=ok))

    def _form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length < 0 or length > _MAX_BODY:
            return {}
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        parsed = parse_qs(raw, keep_blank_values=True, max_num_fields=20)
        return {key: values[0] for key, values in parsed.items() if values}

    def _send(self, status: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


def _home() -> str:
    return """
    <p>Authorized networks and your own systems only. This page does not scan devices.</p>
    <section>
      <h2>Inventory</h2>
      <form method="post" action="/inventory">
        <label>Database <input name="db" required placeholder="audit.db"></label>
        <label>Assets JSON <input name="assets" placeholder="examples/assets.example.json"></label>
        <button name="action" value="import" type="submit">Import</button>
        <button name="action" value="list" type="submit">List</button>
      </form>
    </section>
    <section>
      <h2>Scope check</h2>
      <p>Validation only. An in-scope target is not contacted.</p>
      <form method="post" action="/scope">
        <label>
          <input type="checkbox" name="authorized" value="yes">
          I am authorized to assess this scope
        </label>
        <label>Scope file
          <input name="scope" required placeholder="examples/scope.example.toml">
        </label>
        <label>Target
          <input name="target" required placeholder="192.168.56.0/28 or 192.168.56.10:443">
        </label>
        <button name="action" value="discover" type="submit">Check discover</button>
        <button name="action" value="tls" type="submit">Check TLS</button>
      </form>
    </section>
    <p class="note">Firmware, CVE matching, baselines, topology, and export are not in this GUI.
    The isolated research tree is not available here.</p>
    """


def _page(
    title: str,
    message: str = "",
    *,
    ok: bool | None = None,
    rows: list[JSONObject] | None = None,
) -> str:
    banner = ""
    if message:
        kind = "ok" if ok else "bad"
        banner = f'<p class="banner {kind}">{html.escape(message)}</p>'
    table = _table(rows or [])
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
body {{ font: 16px/1.45 ui-sans-serif, sans-serif; margin: 2rem auto; max-width: 52rem;
  color: #1c1917; background: #f6f3ee; padding: 0 1rem; }}
h1 {{ font-size: 1.6rem; }}
section {{ background: #fff; border: 1px solid #e7e5e4; padding: 1rem; margin: 1rem 0; }}
label {{ display: block; margin: 0.5rem 0; }}
input[type] {{ width: 100%; box-sizing: border-box; padding: 0.4rem; }}
button {{ margin: 0.4rem 0.4rem 0 0; padding: 0.4rem 0.7rem; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border-bottom: 1px solid #e7e5e4; text-align: left; padding: 0.3rem; }}
.banner {{ padding: 0.6rem 0.8rem; }}
.ok {{ background: #ecfdf3; }}
.bad {{ background: #fef2f2; }}
.note {{ color: #57534e; }}
</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
{banner}
{table}
{_home()}
</body>
</html>
"""


def _table(rows: list[JSONObject]) -> str:
    if not rows:
        return ""
    columns = ("asset_id", "address", "name", "vendor", "product", "role")
    head = "".join(f"<th>{html.escape(name)}</th>" for name in columns)
    body = []
    for row in rows:
        cells = "".join(f"<td>{html.escape(str(row.get(name) or ''))}</td>" for name in columns)
        body.append(f"<tr>{cells}</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


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
