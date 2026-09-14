#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHR_VERSION="${CHR_VERSION:-7.24.1}"
CHR_ARCHIVE="${CHR_ARCHIVE:-/tmp/chr-${CHR_VERSION}.img.zip}"
CHR_IMAGE="${CHR_IMAGE:-/tmp/chr-common-lab.img}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:9480}"
OUTPUT="${1:-${ROOT}/evidence/test-harness/mikrotik-chr-common-lab.json}"
QEMU_PID_FILE="/tmp/chr-common-lab.pid"
SERIAL_LOG="/tmp/chr-common-lab-serial.log"

# shellcheck source=lab/common/network_lab.sh
source "${ROOT}/lab/common/network_lab.sh"

cleanup() {
  if [[ -f "${QEMU_PID_FILE}" ]]; then
    kill "$(cat "${QEMU_PID_FILE}")" 2>/dev/null || true
  fi
  ndh_cleanup_standard_topology
  rm -f "${QEMU_PID_FILE}"
}
trap cleanup EXIT

for command in curl ip python3 qemu-system-x86_64 sudo unzip; do
  ndh_require_command "${command}"
done

if [[ ! -s "${CHR_ARCHIVE}" ]]; then
  curl -4 --http1.1 -fL \
    --connect-timeout 15 \
    --max-time 180 \
    --retry 1 \
    --retry-delay 2 \
    --retry-all-errors \
    "https://download.mikrotik.com/routeros/${CHR_VERSION}/chr-${CHR_VERSION}.img.zip" \
    -o "${CHR_ARCHIVE}"
fi
unzip -t "${CHR_ARCHIVE}" >/dev/null
unzip -p "${CHR_ARCHIVE}" > "${CHR_IMAGE}"
test -s "${CHR_IMAGE}"

ndh_setup_standard_topology
ndh_assert_standard_topology
mkdir -p "$(dirname "${OUTPUT}")"
rm -f "${QEMU_PID_FILE}" "${SERIAL_LOG}"

qemu-system-x86_64 \
  -accel tcg,thread=multi \
  -smp 1 \
  -m 256 \
  -snapshot \
  -drive file="${CHR_IMAGE}",format=raw,if=virtio \
  -netdev user,id=mgmt,hostfwd=tcp:127.0.0.1:9480-:80 \
  -device virtio-net-pci,netdev=mgmt,mac=52:54:00:12:37:01 \
  -netdev tap,id=wan_primary,ifname="${NDH_TAP_WAN_PRIMARY}",script=no,downscript=no \
  -device virtio-net-pci,netdev=wan_primary,mac=52:54:00:12:37:02 \
  -netdev tap,id=wan_backup,ifname="${NDH_TAP_WAN_BACKUP}",script=no,downscript=no \
  -device virtio-net-pci,netdev=wan_backup,mac=52:54:00:12:37:03 \
  -netdev tap,id=lan,ifname="${NDH_TAP_LAN}",script=no,downscript=no \
  -device virtio-net-pci,netdev=lan,mac=52:54:00:12:37:04 \
  -display none \
  -serial file:"${SERIAL_LOG}" \
  -daemonize \
  -pidfile "${QEMU_PID_FILE}"

ready=0
for _attempt in $(seq 1 90); do
  if curl -fsS --max-time 2 --user 'admin:' \
    "${ADMIN_URL}/rest/system/resource" \
    > /tmp/chr-common-lab-resource.json; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "${ready}" -ne 1 ]]; then
  cat "${SERIAL_LOG}" >&2 || true
  exit 3
fi

curl -fsS --user 'admin:' "${ADMIN_URL}/rest/interface" \
  > /tmp/chr-common-lab-interfaces.json

python3 - "${OUTPUT}" \
  /tmp/chr-common-lab-resource.json \
  /tmp/chr-common-lab-interfaces.json <<'PY'
import json
import sys
from pathlib import Path

from router_configuration.test_lab import StandardLabTopology

output = Path(sys.argv[1])
resource = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
interfaces = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
if isinstance(resource, list):
    if len(resource) != 1:
        raise SystemExit("unexpected RouterOS resource response")
    resource = resource[0]
if not isinstance(resource, dict):
    raise SystemExit("RouterOS resource response must be an object")
if not isinstance(interfaces, list):
    raise SystemExit("RouterOS interface response must be a list")

expected = {
    "management": ("ether1", "52:54:00:12:37:01"),
    "wan_primary": ("ether2", "52:54:00:12:37:02"),
    "wan_backup": ("ether3", "52:54:00:12:37:03"),
    "lan": ("ether4", "52:54:00:12:37:04"),
}
by_name = {
    str(row.get("name")): row
    for row in interfaces
    if isinstance(row, dict) and row.get("name")
}
observed = {}
for role, (name, mac) in expected.items():
    row = by_name.get(name)
    if row is None:
        raise SystemExit(f"missing expected CHR interface {name} for {role}")
    observed_mac = str(row.get("mac-address") or "").upper()
    if observed_mac != mac.upper():
        raise SystemExit(
            f"CHR role mapping mismatch for {role}: expected {name}/{mac}, got {name}/{observed_mac}"
        )
    observed[role] = {"interface": name, "mac_address": observed_mac}

version = str(resource.get("version") or "").strip()
if not version:
    raise SystemExit("RouterOS observed version is missing")

payload = {
    "schema_version": "mikrotik-chr-common-lab-attachment/1",
    "acceptance": "PASS",
    "backend": {
        "vendor": "mikrotik",
        "product": "CHR",
        "kind": "virtual_appliance",
        "evidence_fidelity": "vendor_os",
        "routeros_observed_version": version,
    },
    "topology": StandardLabTopology.build().as_dict(),
    "role_mapping": observed,
    "role_mapping_verified": True,
    "scope": "vendor_os_boot_and_common_lab_attachment_only",
    "configuration_mutation_performed": False,
    "whole_vendor_software_certification_claimed": False,
    "physical_hardware_claimed": False,
    "production_writer_available": False,
    "write_authorized": False,
}
output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(payload, indent=2, sort_keys=True))
PY
