# Authorized networks / own systems ONLY.
# This module never opens a socket. Callers must pass every target through it
# before any connection. It does not import optional research material.
"""Fail-closed scope gate for authorized networks only.

IP literals only. No DNS. Budgets come from the scope file and are rejected
if they exceed hard ceilings.
"""

from __future__ import annotations

import ipaddress
import tomllib
from ipaddress import IPv4Network, IPv6Network
from pathlib import Path

from .types import Scope

_MAX_HOSTS = 256
_MAX_CONCURRENCY = 32
_MAX_TIMEOUT = 30.0
_MIN_TIMEOUT = 0.1
_MAX_RATE = 20.0
_MIN_RATE = 0.1

Network = IPv4Network | IPv6Network


class ScopeError(ValueError):
    """The request or scope file is not allowed."""


def load_scope(path: Path) -> Scope:
    """Parse and validate a TOML scope file. Does not touch the network."""
    file_path = Path(path)
    if not file_path.is_file():
        raise ScopeError(f"scope file not found: {file_path}")
    try:
        raw = tomllib.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ScopeError(f"scope file is not valid TOML: {file_path}") from exc
    if not isinstance(raw, dict):
        raise ScopeError("scope file must be a TOML table")
    return _validate(raw)


def authorize_scope(*, authorized: bool, scope_path: Path) -> Scope:
    """Refuse unless the operator set --authorized and the scope file is valid."""
    if authorized is not True:
        raise ScopeError("refusing: --authorized is required for network operations")
    if scope_path is None:
        raise ScopeError("refusing: --scope FILE is required for network operations")
    return load_scope(Path(scope_path))


def resolve_scoped_target(
    ip: str, port: int, *, authorized: bool, scope: Scope
) -> tuple[str, int]:
    """Accept an IP literal and port only when both are inside the scope."""
    _require_authorized(authorized)
    address = _literal_address(ip)
    port_n = _port(port)
    allowed_ports = _ports(scope)
    if port_n not in allowed_ports:
        raise ScopeError(f"refusing: port {port_n} is not in the scope allow list")
    if not _address_allowed(address, _networks(scope)):
        raise ScopeError(f"refusing: {address} is outside the authorized scope")
    return str(address), port_n


def expand_scoped_cidr(cidr: str, *, authorized: bool, scope: Scope) -> tuple[str, ...]:
    """Expand a CIDR that sits entirely inside scope, bounded by max_hosts."""
    _require_authorized(authorized)
    network = _literal_network(cidr)
    if not _network_allowed(network, _networks(scope)):
        raise ScopeError(f"refusing: {network} is outside the authorized scope")
    hosts = _host_addresses(network)
    limit = int(scope["max_hosts"])
    if len(hosts) > limit:
        raise ScopeError(
            f"refusing: {network} expands to {len(hosts)} hosts, above max_hosts={limit}"
        )
    if not hosts:
        raise ScopeError(f"refusing: {network} has no host addresses")
    return hosts


def _validate(raw: dict[str, object]) -> Scope:
    cidrs = _pick_list(raw, "allow_cidrs", "allow")
    ports = _pick_list(raw, "allow_ports", "ports")
    if not cidrs:
        raise ScopeError("scope requires a non-empty allow_cidrs list")
    if not ports:
        raise ScopeError("scope requires a non-empty allow_ports list")
    networks = tuple(_literal_network(item, label="allow_cidrs") for item in cidrs)
    port_set = tuple(sorted({_port(item, label="allow_ports") for item in ports}))
    max_hosts = _bounded_int(raw, ("max_hosts",), 1, _MAX_HOSTS, default=16)
    concurrency = _bounded_int(
        raw, ("max_concurrency", "concurrency"), 1, _MAX_CONCURRENCY, default=4
    )
    timeout = _bounded_float(
        raw, ("timeout_seconds",), _MIN_TIMEOUT, _MAX_TIMEOUT, default=3.0
    )
    rate = _bounded_float(
        raw,
        ("max_rate_per_second", "max_connections_per_second"),
        _MIN_RATE,
        _MAX_RATE,
        default=5.0,
    )
    return {
        "allow_cidrs": tuple(str(net) for net in networks),
        "allow_ports": port_set,
        "max_hosts": max_hosts,
        "max_concurrency": concurrency,
        "timeout_seconds": timeout,
        "max_rate_per_second": rate,
        "networks": networks,
    }


def _require_authorized(authorized: bool) -> None:
    if authorized is not True:
        raise ScopeError("refusing: --authorized is required for network operations")


def _pick_list(raw: dict[str, object], *keys: str) -> list[object]:
    for key in keys:
        if key in raw:
            value = raw[key]
            if not isinstance(value, list):
                raise ScopeError(f"{key} must be a list")
            return list(value)
    return []


def _bounded_int(
    raw: dict[str, object],
    keys: tuple[str, ...],
    low: int,
    high: int,
    *,
    default: int,
) -> int:
    value = _first(raw, keys, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ScopeError(f"{keys[0]} must be an integer")
    if value < low or value > high:
        raise ScopeError(f"{keys[0]} must be between {low} and {high}")
    return value


def _bounded_float(
    raw: dict[str, object],
    keys: tuple[str, ...],
    low: float,
    high: float,
    *,
    default: float,
) -> float:
    value = _first(raw, keys, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ScopeError(f"{keys[0]} must be a number")
    number = float(value)
    if number < low or number > high:
        raise ScopeError(f"{keys[0]} must be between {low} and {high}")
    return number


def _first(raw: dict[str, object], keys: tuple[str, ...], default: object) -> object:
    for key in keys:
        if key in raw:
            return raw[key]
    return default


def _literal_address(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(value, str):
        raise ScopeError("target must be an IP literal")
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ScopeError(f"refusing hostname or invalid IP literal: {value}") from exc


def _literal_network(value: object, *, label: str = "target") -> Network:
    if not isinstance(value, str):
        raise ScopeError(f"{label} must be a CIDR string")
    text = value.strip()
    if "/" not in text:
        raise ScopeError(f"{label} must be a CIDR such as 192.168.56.0/28, not {text!r}")
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise ScopeError(f"refusing invalid CIDR in {label}: {text}") from exc


def _port(value: object, *, label: str = "port") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ScopeError(f"{label} must be an integer")
    if value < 1 or value > 65535:
        raise ScopeError(f"{label} must be between 1 and 65535")
    return value


def _networks(scope: Scope) -> tuple[Network, ...]:
    networks = scope.get("networks")
    if not isinstance(networks, tuple) or not networks:
        raise ScopeError("scope has no authorized networks")
    checked: list[Network] = []
    for network in networks:
        if not isinstance(network, (IPv4Network, IPv6Network)):
            raise ScopeError("scope networks are invalid")
        checked.append(network)
    return tuple(checked)


def _ports(scope: Scope) -> frozenset[int]:
    ports = scope.get("allow_ports")
    if not isinstance(ports, tuple):
        raise ScopeError("scope has no authorized ports")
    return frozenset(int(port) for port in ports)


def _address_allowed(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address, networks: tuple[Network, ...]
) -> bool:
    return any(address in network for network in networks)


def _network_allowed(network: Network, networks: tuple[Network, ...]) -> bool:
    return any(
        network.version == allow.version and network.subnet_of(allow) for allow in networks
    )


def _host_addresses(network: Network) -> tuple[str, ...]:
    if isinstance(network, IPv4Network) and network.prefixlen < 31:
        return tuple(str(host) for host in network.hosts())
    return tuple(str(host) for host in network)
