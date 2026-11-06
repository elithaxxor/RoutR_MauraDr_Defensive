# RoutR_MauraDr_Defensive

> Defensive rewrite of the original RoutR_MauraDr project.
> Original repository remains untouched at https://github.com/elithaxxor/RoutR_MauraDr

Network inventory and baseline checking for **authorized networks / own systems only**.
The defensive core collects observations and produces alerts and reports. It does not change device configurations.

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
