#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 IMAGE" >&2
  exit 2
fi

image=$1

# Keep this check credential-free: the image is exercised with no .env, mounts,
# or host credentials.  Disable networking so the smoke test cannot contact a
# VPN gateway or any other external service.
docker run --rm -i --network none --entrypoint /bin/sh "$image" -eu <<'CONTAINER_SCRIPT'
  export PYTHONPATH=/usr/local/lib/topsap-service
  vendor_root=/usr/local/lib/topsap-payload/cn.com.topvpn/files

  python3 - <<"PY"
import importlib

for name in ("common", "config", "healthcheck", "network", "otp", "service", "vpn_login"):
    importlib.import_module(name)
PY

  python3 - <<"PY"
from pathlib import Path
import os
import re
import subprocess

root = Path("/usr/local/lib/topsap-payload/cn.com.topvpn/files")
entrypoints = (root / "sv_websrv", root / "ele" / "TopSAP")
if not root.is_dir() or not all(path.is_file() for path in entrypoints):
    raise SystemExit("missing vendor runtime entrypoint")

# service.py launches sv_websrv and ele/TopSAP with APP as LD_LIBRARY_PATH.
# Match service.py's LD_LIBRARY_PATH exactly, then walk the vendor libraries
# reported by ldd for both runtime entrypoints.
environment = dict(os.environ, LD_LIBRARY_PATH=str(root))
pending = list(entrypoints)
checked = set()
while pending:
    path = pending.pop()
    if path in checked:
        continue
    checked.add(path)
    result = subprocess.run(
        ["ldd", str(path)], env=environment,
        capture_output=True, text=True, check=False,
    )
    output = result.stdout + result.stderr
    if "not found" in output:
        raise SystemExit(f"unresolved runtime ELF dependency in {path}:\n{output}")
    if result.returncode and "not a dynamic executable" not in output and "statically linked" not in output:
        raise SystemExit(f"ldd failed for {path}:\n{output}")
    for line in result.stdout.splitlines():
        match = re.search(r"=>\s+(\S+)", line) or re.match(r"\s*(/\S+)", line)
        if not match:
            continue
        dependency = Path(match.group(1))
        if dependency.is_file() and (dependency == root or root in dependency.parents):
            pending.append(dependency)

print(f"imported Python modules and checked runtime ELF closure ({len(checked)} files)")
PY

  mkdir -p /tmp/topsap-smoke-home
  Xvfb :99 -screen 0 1280x800x24 -nolisten tcp -noreset >/tmp/topsap-xvfb.log 2>&1 &
  xvfb_pid=$!
  electron_pid=
  cleanup() {
    if [ -n "$electron_pid" ]; then kill "$electron_pid" 2>/dev/null || true; fi
    kill "$xvfb_pid" 2>/dev/null || true
    wait "$electron_pid" 2>/dev/null || true
    wait "$xvfb_pid" 2>/dev/null || true
  }
  trap cleanup EXIT
  for _ in $(seq 1 50); do
    if [ -S /tmp/.X11-unix/X99 ]; then break; fi
    sleep 0.1
  done
  test -S /tmp/.X11-unix/X99

  test -x "$vendor_root/ele/TopSAP"
  DISPLAY=:99 HOME=/tmp/topsap-smoke-home LD_LIBRARY_PATH="$vendor_root" ELECTRON_RUN_AS_NODE=1 \
    "$vendor_root/ele/TopSAP" --version >/tmp/topsap-electron-version.txt 2>&1

  DISPLAY=:99 HOME=/tmp/topsap-smoke-home LD_LIBRARY_PATH="$vendor_root" \
    "$vendor_root/ele/TopSAP" --no-sandbox --disable-gpu --disable-dev-shm-usage \
    --remote-debugging-address=127.0.0.1 --remote-debugging-port=9222 \
    >/tmp/topsap-electron.log 2>&1 &
  electron_pid=$!
  ready=false
  for _ in $(seq 1 100); do
    if ! kill -0 "$electron_pid" 2>/dev/null; then break; fi
    if python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9222/json/version', timeout=0.2).read()" 2>/dev/null; then
      ready=true
      break
    fi
    sleep 0.2
  done
  if [ "$ready" != true ]; then
    cat /tmp/topsap-electron.log >&2 || true
    exit 1
  fi
  echo "Electron version: $(cat /tmp/topsap-electron-version.txt)"
CONTAINER_SCRIPT
