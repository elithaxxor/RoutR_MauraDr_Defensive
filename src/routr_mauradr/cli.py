# Authorized networks / own systems ONLY.
# Network commands validate scope and then stop. They do not open sockets.
# Inventory is a local file operation. This module never imports research material.
"""Command-line entry point for the defensive auditor.

--help and offline commands make no network connections.
discover and tls check require both --authorized and --scope.
Those commands only validate the scope; they do not connect.
"""

from __future__ import annotations

import json
import sys
from argparse import ArgumentParser, Namespace
from collections.abc import Sequence
from pathlib import Path

from .inventory import InventoryError, import_assets, list_assets
from .scope import ScopeError, authorize_scope, expand_scoped_cidr, resolve_scoped_target

_NETWORK_COMMANDS = frozenset({"discover", "tls"})
_OFFLINE_STUBS = frozenset({"firmware", "cve", "baseline", "topology", "export"})


def build_parser() -> ArgumentParser:
    """Build the defensive CLI parser. Parsing does not touch the network."""
    parser = ArgumentParser(
        prog="routr-audit",
        description=(
            "Defensive inventory and baseline checks for authorized networks / "
            "own systems only. Network commands require --authorized and --scope."
        ),
    )
    parser.add_argument("--db", default=None, help="Local inventory database path")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm this run is limited to systems you own or may assess",
    )
    parser.add_argument("--scope", default=None, help="Path to a TOML scope file")

    commands = parser.add_subparsers(dest="command")

    discover = commands.add_parser("discover", help="Validate a CIDR against the scope")
    discover.add_argument("target", help="CIDR, for example 192.168.56.0/28")

    tls = commands.add_parser("tls", help="TLS certificate checks")
    tls_commands = tls.add_subparsers(dest="tls_command")
    check = tls_commands.add_parser("check", help="Validate an ip:port against the scope")
    check.add_argument("target", help="IP literal and port, for example 192.168.56.10:443")
    check.add_argument("--server-name", default=None, help="Expected certificate hostname")

    inventory = commands.add_parser("inventory", help="Local asset inventory")
    inventory_commands = inventory.add_subparsers(dest="inventory_command")
    import_command = inventory_commands.add_parser("import", help="Import assets from JSON")
    import_command.add_argument("assets_json", help="Operator-supplied asset file")
    inventory_commands.add_parser("list", help="Print stored assets as JSON")

    gui = commands.add_parser("gui", help="Open the loopback defensive GUI")
    gui.add_argument("--listen", default="127.0.0.1", help="Loopback address only")
    gui.add_argument("--port", type=int, default=8765, help="Loopback port")

    for name in sorted(_OFFLINE_STUBS):
        commands.add_parser(name, help="Offline command (not implemented yet)")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run one CLI invocation. Returns a process status; does not raise for user errors."""
    parser = build_parser()
    args_list = list(sys.argv[1:] if argv is None else argv)
    if not args_list or args_list in (["-h"], ["--help"]):
        parser.print_help(sys.stdout)
        return 0
    try:
        args = parser.parse_args(args_list)
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        return code if isinstance(code, int) else 2

    command = args.command
    if command is None:
        parser.print_help(sys.stdout)
        return 2
    if command in _NETWORK_COMMANDS:
        return _network_command(args)
    if command == "inventory":
        return _inventory_command(args)
    if command == "gui":
        return _gui_command(args)
    if command in _OFFLINE_STUBS:
        print(f"error: {command} is not implemented", file=sys.stderr)
        return 2
    print(f"error: unknown command {command}", file=sys.stderr)
    return 2


def _inventory_command(args: Namespace) -> int:
    action = args.inventory_command
    if action not in {"import", "list"}:
        print("error: usage: routr-audit --db FILE inventory import|list", file=sys.stderr)
        return 2
    if not args.db:
        print("error: --db FILE is required for inventory", file=sys.stderr)
        return 2
    try:
        if action == "import":
            count = import_assets(Path(args.db), Path(args.assets_json))
            print(f"imported {count} assets")
            return 0
        print(json.dumps(list_assets(Path(args.db)), indent=2))
    except InventoryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def _gui_command(args: Namespace) -> int:
    from .gui import GuiError, serve

    try:
        return serve(host=str(args.listen), port=args.port)
    except GuiError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _network_command(args: Namespace) -> int:
    if args.command == "tls" and args.tls_command != "check":
        print("error: usage: routr-audit tls check IP:PORT", file=sys.stderr)
        return 2
    try:
        scope = authorize_scope(authorized=bool(args.authorized), scope_path=args.scope)
        if args.command == "discover":
            hosts = expand_scoped_cidr(args.target, authorized=True, scope=scope)
            print(
                f"error: discover is not implemented ({len(hosts)} in-scope hosts validated)",
                file=sys.stderr,
            )
            return 2
        ip, port = _split_target(args.target)
        resolve_scoped_target(ip, port, authorized=True, scope=scope)
    except ScopeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("error: tls check is not implemented", file=sys.stderr)
    return 2


def _split_target(target: str) -> tuple[str, int]:
    if target.startswith("["):
        host, sep, rest = target[1:].partition("]")
        if not sep or not rest.startswith(":"):
            raise ScopeError("tls target must look like [IPv6]:port")
        return host, _parse_port(rest[1:])
    host, sep, port_text = target.rpartition(":")
    if not sep or not host:
        raise ScopeError("tls target must look like 192.168.56.10:443")
    return host, _parse_port(port_text)


def _parse_port(text: str) -> int:
    try:
        port = int(text)
    except ValueError as exc:
        raise ScopeError(f"invalid port: {text}") from exc
    if port < 1 or port > 65535:
        raise ScopeError(f"invalid port: {port}")
    return port
