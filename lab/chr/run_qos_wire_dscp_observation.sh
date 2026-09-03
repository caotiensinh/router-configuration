#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EVIDENCE_DIR="${EVIDENCE_DIR:-${ROOT}/evidence/qos-wire-dscp}"
COUNT="${FLOW_COUNT:-40}"
NS_TX="rc-qdbg-tx"
NS_RX="rc-qdbg-rx"
V_TX="vqd-tx"
V_RX="vqd-rx"
TCPDUMP_PID=""
SERVER_PID=""

cleanup() {
  if [[ -n "${TCPDUMP_PID}" ]]; then sudo kill "${TCPDUMP_PID}" 2>/dev/null || true; fi
  if [[ -n "${SERVER_PID}" ]]; then sudo kill "${SERVER_PID}" 2>/dev/null || true; fi
  sudo ip netns del "${NS_TX}" 2>/dev/null || true
  sudo ip netns del "${NS_RX}" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
trap cleanup EXIT
mkdir -p "${EVIDENCE_DIR}"

for command in python3 ip tcpdump sudo; do
  command -v "${command}" >/dev/null 2>&1 || { echo "missing required command: ${command}" >&2; exit 2; }
done

sudo ip netns add "${NS_TX}"
sudo ip netns add "${NS_RX}"
sudo ip link add "${V_TX}" type veth peer name "${V_RX}"
sudo ip link set "${V_TX}" netns "${NS_TX}"
sudo ip link set "${V_RX}" netns "${NS_RX}"
sudo ip netns exec "${NS_TX}" ip link set lo up
sudo ip netns exec "${NS_RX}" ip link set lo up
sudo ip netns exec "${NS_TX}" ip addr add 10.77.0.1/30 dev "${V_TX}"
sudo ip netns exec "${NS_RX}" ip addr add 10.77.0.2/30 dev "${V_RX}"
sudo ip netns exec "${NS_TX}" ip link set "${V_TX}" up
sudo ip netns exec "${NS_RX}" ip link set "${V_RX}" up

sudo ip netns exec "${NS_RX}" python3 "${ROOT}/lab/chr/udp_tag_server.py" \
  --bind 10.77.0.2 --port 5000 --tag RX >"${EVIDENCE_DIR}/server.log" 2>&1 &
SERVER_PID=$!
sleep 0.25
sudo ip netns exec "${NS_RX}" tcpdump -nn -vv -l -i "${V_RX}" \
  "udp and dst port 5000" >"${EVIDENCE_DIR}/tcpdump.txt" 2>&1 &
TCPDUMP_PID=$!
sleep 0.25

sudo ip netns exec "${NS_TX}" python3 "${ROOT}/lab/chr/udp_flow_probe.py" \
  --bind 10.77.0.1 --destination 10.77.0.2 --destination-port 5000 \
  --source-port-start 52000 --count "${COUNT}" --timeout 0.30 --dscp 46 \
  --output "${EVIDENCE_DIR}/flow.json"
sleep 0.5
sudo kill "${TCPDUMP_PID}" 2>/dev/null || true
TCPDUMP_PID=""

python3 - "${EVIDENCE_DIR}/flow.json" "${EVIDENCE_DIR}/tcpdump.txt" "${EVIDENCE_DIR}/summary.json" <<'PY'
import json, re, sys
from pathlib import Path
flow = json.load(open(sys.argv[1], encoding='utf-8'))
text = Path(sys.argv[2]).read_text(encoding='utf-8', errors='replace')
if flow.get('success_ratio') != 1.0 or int(flow.get('successful_flows', 0)) <= 0:
    raise SystemExit('DSCP wire probe flow was not reliable')
# Linux tcpdump renders DSCP EF (46 << 2) as TOS 0xb8.
tos_b8 = len(re.findall(r"tos 0xb8\b", text, flags=re.IGNORECASE))
udp_lines = len(re.findall(r"UDP, length", text))
if tos_b8 <= 0:
    raise SystemExit('tcpdump did not observe any EF/DSCP46 TOS 0xb8 packets')
summary = {
    'ok': True,
    'acceptance': 'PASS',
    'scope': 'linux_wire_dscp_generation_observation',
    'requested_flows': int(flow['requested_flows']),
    'successful_flows': int(flow['successful_flows']),
    'success_ratio': float(flow['success_ratio']),
    'tcpdump_tos_0xb8_observations': tos_b8,
    'tcpdump_udp_observations': udp_lines,
    'dscp46_generated_on_wire': True,
    'routeros_behavior_claimed': False,
    'production_packet_flow_acceptance': False,
    'production_renderer_modified': False,
    'production_writer_available': False,
    'physical_router_targeted': False,
}
Path(sys.argv[3]).write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
print(json.dumps(summary, indent=2, sort_keys=True))
PY
