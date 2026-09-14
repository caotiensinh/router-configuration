#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT="${1:-${ROOT}/evidence/test-harness/common-probe-selftest.json}"
EVIDENCE_DIR="$(dirname "${OUTPUT}")"
UDP_EVIDENCE="${EVIDENCE_DIR}/common-udp-flow.json"
UDP_PID=""

# shellcheck source=lab/common/network_lab.sh
source "${ROOT}/lab/common/network_lab.sh"

cleanup() {
  if [[ -n "${UDP_PID}" ]]; then
    sudo kill "${UDP_PID}" 2>/dev/null || true
  fi
  ndh_cleanup_standard_topology
}
trap cleanup EXIT

mkdir -p "${EVIDENCE_DIR}"
ndh_setup_standard_topology
ndh_assert_standard_topology

UDP_PID="$(
  sudo ip netns exec "${NDH_NS_WAN_PRIMARY}" \
    sh -c 'python3 "$1" --bind 203.0.113.100 --port 5000 --tag WAN_PRIMARY >/tmp/ndh-udp-selftest.log 2>&1 & echo $!' \
    _ "${ROOT}/lab/common/udp_tag_server.py"
)"

for _attempt in $(seq 1 40); do
  if sudo ip netns pids "${NDH_NS_WAN_PRIMARY}" | grep -Fxq "${UDP_PID}" && \
     sudo ip netns exec "${NDH_NS_WAN_PRIMARY}" ss -H -lun | grep -Eq '(:|])5000[[:space:]]'; then
    break
  fi
  sleep 0.05
done

sudo ip netns pids "${NDH_NS_WAN_PRIMARY}" | grep -Fxq "${UDP_PID}"
sudo ip netns exec "${NDH_NS_WAN_PRIMARY}" ss -H -lun | grep -Eq '(:|])5000[[:space:]]'

sudo ip netns exec "${NDH_NS_WAN_PRIMARY}" \
  python3 "${ROOT}/lab/common/udp_flow_probe.py" \
    --bind 192.0.2.1 \
    --destination 203.0.113.100 \
    --destination-port 5000 \
    --source-port-start 41000 \
    --count 8 \
    --timeout 0.2 \
    --output "${UDP_EVIDENCE}"

python3 - "${OUTPUT}" "${UDP_EVIDENCE}" <<'PY'
import json
import sys
from pathlib import Path

output = Path(sys.argv[1])
flow_path = Path(sys.argv[2])
flow = json.loads(flow_path.read_text(encoding="utf-8"))
assert flow["schema_version"] == "network-device-udp-flow-probe/1"
assert flow["requested_flows"] == 8
assert flow["successful_flows"] == 8
assert flow["failed_flows"] == 0
assert flow["tags"] == {"WAN_PRIMARY": 8}

payload = {
    "schema_version": "network-device-common-probe-selftest/1",
    "acceptance": "PASS",
    "scope": "common_linux_lab_probe_tools_only_no_vendor_os",
    "udp": {
        "responder_started": True,
        "requested_flows": flow["requested_flows"],
        "successful_flows": flow["successful_flows"],
        "expected_tag": "WAN_PRIMARY",
        "observed_tags": flow["tags"],
        "evidence": flow_path.name,
    },
    "router_forwarding_acceptance_claimed": False,
    "vendor_os_acceptance_claimed": False,
    "physical_hardware_claimed": False,
    "production_writer_available": False,
    "write_authorized": False,
}
output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(payload, indent=2, sort_keys=True))
PY
