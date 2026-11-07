#!/usr/bin/env bash
# Build the defensive core only.
# Does not install the research extra and does not run anything under optional/research/.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$root"

run_tests=0
if [[ "${1:-}" == "--test" ]]; then
  run_tests=1
elif [[ -n "${1:-}" ]]; then
  echo "usage: ./build.sh [--test]" >&2
  exit 2
fi

pick_python() {
  local cmd
  for cmd in python3.13 python3.12 python3.11 python3; do
    if command -v "$cmd" >/dev/null 2>&1; then
      if "$cmd" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
        echo "$cmd"
        return 0
      fi
    fi
  done
  echo "error: Python 3.11 or newer is required" >&2
  return 1
}

py="$(pick_python)"
venv="$root/.venv"

if [[ ! -x "$venv/bin/python" ]] || ! "$venv/bin/python" -m pip --version >/dev/null 2>&1; then
  rm -rf "$venv"
  if ! "$py" -m venv "$venv" >/dev/null 2>&1; then
    rm -rf "$venv"
    if command -v uv >/dev/null 2>&1; then
      uv venv --seed --python "$py" "$venv"
    else
      echo "error: could not create .venv. Install the Python venv package (for example python3-venv) and retry." >&2
      exit 1
    fi
  fi
fi

"$venv/bin/python" -m pip install --upgrade pip
"$venv/bin/python" -m pip install "build>=1"
rm -rf dist build ./*.egg-info src/*.egg-info
"$venv/bin/python" -m build

"$venv/bin/python" - << 'PY'
import sys
import tarfile
import zipfile
from pathlib import Path

def rejected(name: str) -> bool:
    lowered = name.replace("\\", "/")
    markers = (
        "optional/research",
        "/payloads/",
        "payloads/",
        "impacket/",
        "pgrok/",
    )
    return any(marker in lowered for marker in markers)

wheels = sorted(Path("dist").glob("*.whl"))
sdists = sorted(Path("dist").glob("*.tar.gz"))
if len(wheels) != 1 or len(sdists) != 1:
    sys.exit(f"expected one wheel and one sdist, found {wheels} {sdists}")

wheel_names = zipfile.ZipFile(wheels[0]).namelist()
sdist_names = tarfile.open(sdists[0]).getnames()
for label, names in (("wheel", wheel_names), ("sdist", sdist_names)):
    found = [name for name in names if rejected(name)]
    if found:
        print(f"{label} contains excluded paths:", *found, sep="\n")
        sys.exit(1)

if not any(name.startswith("routr_mauradr/") for name in wheel_names):
    sys.exit("wheel is missing the defensive package")

print(f"wheel ok: {wheels[0].name}")
print(f"sdist ok: {sdists[0].name}")
PY

"$venv/bin/python" -m pip install --force-reinstall dist/*.whl
"$venv/bin/routr-audit" --help >/dev/null

if [[ "$run_tests" -eq 1 ]]; then
  "$venv/bin/python" -m pip install -e ".[dev]"
  "$venv/bin/python" -m pytest
fi

echo "built dist/ and installed routr-audit in .venv"
echo "research extra was not installed"
