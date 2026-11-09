# RoutR_MauraDr_Defensive

> Defensive rewrite of the original RoutR_MauraDr project.
> Original repository remains untouched at https://github.com/elithaxxor/RoutR_MauraDr

Network inventory and baseline checking for **authorized networks / own systems only**.
The defensive core collects observations and produces alerts and reports. It does not change device configurations.

## Current slice

Implemented and tested:

- `routr-audit --help` makes no network connection.
- `discover` and `tls check` refuse to run unless both `--authorized` and `--scope` are set.
- The scope file is TOML. Targets must be IP CIDRs or IP literals. Hostnames are rejected. Host count, concurrency, timeout, and rate have hard ceilings.
- An in-scope target is validated and the command then exits 2. The probe itself is not implemented yet, and no socket is opened.
- `inventory import` and `inventory list` use a local SQLite file. Addresses must be IP literals. Secret fields are rejected. The database is created mode 0600. No network connection is made.
- `routr-audit gui` serves a loopback-only page for inventory import/list and scope validation. It does not connect to devices, and it refuses paths inside `optional/research/`.
- `firmware`, `cve`, `baseline`, `topology`, and `export` still exit 2 and do not connect.

```bash
routr-audit --authorized --scope examples/scope.example.toml discover 192.168.56.0/28
routr-audit --db audit.db inventory import examples/assets.example.json
routr-audit --db audit.db inventory list
routr-audit gui
```

`routr-audit gui` listens on `http://127.0.0.1:8765/` only. Use `--listen` only with a loopback address.

Use that example range only if it belongs to a network you own or may assess.

## Planned defensive capabilities

- Bounded reachability discovery and local asset inventory.
- Firmware version evidence from supplied inventory or explicitly authorized, documented read-only device interfaces; unavailable values remain unknown.
- Offline informational CVE matching using explicit product mappings and supported version rules, with dataset source, age, and matching confidence.
- Baseline alerts evaluated against operator-supplied configuration snapshots.
- TLS certificate verification, hostname checks, and expiry information when available.
- Topology visualization from supplied mappings and evidenced relationships.
- JSON and escaped static HTML exports.

CVE candidates are informational matches, not confirmed vulnerabilities.
Missing evidence is unknown, never an automatic pass.

## Authorization and scope

Use only on your own systems or networks you have explicit permission to assess.
Every network operation requires `--authorized` and a scope file.

There is no default network. Installation, imports, help, and offline commands make no network connections.

## Installation

Python 3.11 or newer. Defensive core uses the standard library.

```bash
./build.sh
.venv/bin/routr-audit --help
```

`./build.sh` creates `.venv`, builds a wheel and sdist in `dist/`, checks that the research tree is not packaged, and installs the wheel. It does not install the research extra. `./build.sh --test` also runs the unit tests.

Or install into the current environment:

```bash
python -m pip install .
routr-audit --help
```

Optional research dependencies (isolated):
```bash
python -m pip install ".[research]"
```

## Preserved research material

Original project content is preserved unchanged under `optional/research/legacy/`.
It is outside the defensive package and neither imported nor launched by the defensive CLI.

The optional `[research]` extra declares `impacket` and `pgrok` only. It does not enable features or execute preserved material.

## Licensing

Review and resolve licensing before broader publication.
