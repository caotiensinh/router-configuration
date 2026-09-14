#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT="${1:-${ROOT}/evidence/test-harness/common-fault-executor-selftest.json}"
DNS_SCRIPT="$(mktemp)"
DNS_PID=""

# shellcheck source=lab/common/network_lab.sh
source "${ROOT}/lab/common/network_lab.sh"
# shellcheck source=lab/common/fault_executor.sh
source "${ROOT}/lab/common/fault_executor.sh"

cleanup() {
  if [[ -n "${DNS_PID}" ]]; then
    sudo kill "${DNS_PID}" 2>/dev/null || true
  fi
  rm -f "${DNS_SCRIPT}"
  NDH_ALLOW_FAULT_INJECTION=1 ndh_fault_recover_wan_primary_blackhole 2>/dev/null || true
  ndh_cleanup_standard_topology
}
trap cleanup EXIT

ndh_setup_standard_topology
ndh_assert_standard_topology

# Faults must fail closed until an explicitly disposable test opts in.
NDH_ALLOW_FAULT_INJECTION=0
if ndh_fault_inject_wan_primary_blackhole 2>/dev/null; then
  echo "WAN blackhole unexpectedly ran without explicit fault opt-in" >&2
  exit 50
fi

NDH_ALLOW_FAULT_INJECTION=1
ndh_fault_inject_wan_primary_blackhole
ndh_fault_wan_primary_blackhole_active
ndh_fault_recover_wan_primary_blackhole
if ndh_fault_wan_primary_blackhole_active; then
  echo "WAN-primary blackhole remained active after recovery" >&2
  exit 51
fi

cat >"${DNS_SCRIPT}" <<'PY'
import signal
import socket

running = True

def stop(_signum, _frame):
    global running
    running = False

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("203.0.113.53", 1053))
sock.settimeout(0.2)
try:
    while running:
        try:
            sock.recvfrom(2048)
        except socket.timeout:
            pass
finally:
    sock.close()
PY

# Start the listener as an orphaned namespace process and return its real PID.
# stdout/stderr are redirected so command substitution cannot remain attached to
# the long-running service process.
DNS_PID="$(
  sudo ip netns exec "${NDH_NS_WAN_PRIMARY}" \
    sh -c 'python3 "$1" >/tmp/ndh-dns-selftest.log 2>&1 & echo $!' _ "${DNS_SCRIPT}"
)"

for _attempt in $(seq 1 40); do
  if ndh_fault_pid_in_namespace "${NDH_NS_WAN_PRIMARY}" "${DNS_PID}" && \
     sudo ip netns exec "${NDH_NS_WAN_PRIMARY}" ss -H -lun | grep -Eq '(:|])1053[[:space:]]'; then
    break
  fi
  sleep 0.05
done

ndh_fault_pid_in_namespace "${NDH_NS_WAN_PRIMARY}" "${DNS_PID}"
sudo ip netns exec "${NDH_NS_WAN_PRIMARY}" ss -H -lun | grep -Eq '(:|])1053[[:space:]]'

ndh_fault_stop_primary_dns_responder "${DNS_PID}"
ndh_fault_assert_primary_dns_stopped "${DNS_PID}"
if sudo ip netns exec "${NDH_NS_WAN_PRIMARY}" ss -H -lun | grep -Eq '(:|])1053[[:space:]]'; then
  echo "DNS test listener socket remained present after service-stop fault" >&2
  exit 52
fi
DNS_PID=""

mkdir -p "$(dirname "${OUTPUT}")"
python3 - "${OUTPUT}" <<'PY'
import json
import sys
from pathlib import Path

output = Path(sys.argv[1])
payload = {
    "schema_version": "network-device-common-fault-executor-selftest/1",
    "acceptance": "PASS",
    "scope": "common_linux_lab_external_faults_only_no_vendor_os",
    "faults": {
        "wan_primary_blackhole": {
            "plane": "external_network",
            "action": "upstream_packet_blackhole",
            "target_role": "wan_primary",
            "injected": True,
            "observed": True,
            "recovered": True,
            "vendor_adapter_required": False,
        },
        "dns_responder_stop": {
            "plane": "service",
            "action": "dns_responder_stop",
            "target_role": "wan_primary",
            "listener_present_before_fault": True,
            "listener_absent_after_fault": True,
            "vendor_adapter_required": False,
        },
    },
    "fail_closed_without_explicit_fault_opt_in": True,
    "arbitrary_host_interface_targeting_available": False,
    "arbitrary_host_pid_targeting_available": False,
    "vendor_os_acceptance_claimed": False,
    "physical_hardware_claimed": False,
    "production_writer_available": False,
    "write_authorized": False,
}
output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(payload, indent=2, sort_keys=True))
PY
