#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT="${1:-${ROOT}/evidence/test-harness/network-lab-selftest.json}"

# shellcheck source=lab/common/network_lab.sh
source "${ROOT}/lab/common/network_lab.sh"

cleanup() {
  ndh_cleanup_standard_topology
}
trap cleanup EXIT

ndh_setup_standard_topology
ndh_assert_standard_topology
mkdir -p "$(dirname "${OUTPUT}")"

python3 - "${OUTPUT}" \
  "${NDH_TAP_WAN_PRIMARY}" "${NDH_TAP_WAN_BACKUP}" "${NDH_TAP_LAN}" \
  "${NDH_NS_WAN_PRIMARY}" "${NDH_NS_WAN_BACKUP}" "${NDH_NS_LAN}" <<'PY'
import json
import sys
from pathlib import Path

from router_configuration.test_lab import StandardLabTopology

output = Path(sys.argv[1])
taps = {
    "wan_primary": sys.argv[2],
    "wan_backup": sys.argv[3],
    "lan": sys.argv[4],
}
namespaces = {
    "wan_primary": sys.argv[5],
    "wan_backup": sys.argv[6],
    "lan": sys.argv[7],
}
payload = {
    "schema_version": "network-device-linux-lab-selftest/1",
    "acceptance": "PASS",
    "topology": StandardLabTopology.build().as_dict(),
    "host_substrate": {
        "linux_bridges": True,
        "tap_interfaces": True,
        "network_namespaces": True,
        "static_addressing_verified": True,
        "service_loopbacks_verified": True,
        "dns_loopbacks_verified": True,
        "taps": taps,
        "namespaces": namespaces,
    },
    "scope": "host_network_substrate_only_no_vendor_os",
    "vendor_os_acceptance_claimed": False,
    "physical_hardware_claimed": False,
    "production_writer_available": False,
    "write_authorized": False,
}
output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(payload, indent=2, sort_keys=True))
PY
