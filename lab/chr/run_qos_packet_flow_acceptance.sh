#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHR_VERSION="${CHR_VERSION:-7.24.1}"
CHR_ARCHIVE="${CHR_ARCHIVE:-/tmp/chr-${CHR_VERSION}.img.zip}"
CHR_IMAGE="${CHR_IMAGE:-/tmp/chr-qos-packet-flow.img}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:9880}"
EVIDENCE_DIR="${EVIDENCE_DIR:-${ROOT}/evidence/chr-qos-packet-flow}"
FLOW_COUNT="${FLOW_COUNT:-80}"
FLOW_TIMEOUT="${FLOW_TIMEOUT:-0.30}"
SERVICE_IP="203.0.113.100"
SERVICE_PORT="5000"

NS_WAN="rc-qos-wan"
NS_CORE="rc-qos-core"
BR_WAN="br-rc-qos-wan"
BR_CORE="br-rc-qos-core"
TAP_WAN="tap-rc-qos-wan"
TAP_CORE="tap-rc-qos-core"
V_WAN_BR="vq-wan-br"
V_WAN_NS="vq-wan-ns"
V_CORE_BR="vq-core-br"
V_CORE_NS="vq-core-ns"
QEMU_PID_FILE="/tmp/chr-qos-packet-flow.pid"
SERIAL_LOG="/tmp/chr-qos-packet-flow-serial.log"
WAN_SERVER_LOG="/tmp/chr-qos-packet-flow-wan-server.log"
WAN_SERVER_PID=""

log() {
  printf '[chr-qos-flow] %s\n' "$*"
}

cleanup() {
  if [[ -n "${WAN_SERVER_PID}" ]]; then sudo kill "${WAN_SERVER_PID}" 2>/dev/null || true; fi
  if [[ -f "${QEMU_PID_FILE}" ]]; then
    kill "$(cat "${QEMU_PID_FILE}")" 2>/dev/null || true
  fi
  for ns in "${NS_CORE}" "${NS_WAN}"; do
    sudo ip netns del "${ns}" 2>/dev/null || true
  done
  for tap in "${TAP_CORE}" "${TAP_WAN}"; do
    sudo ip link del "${tap}" 2>/dev/null || true
  done
  for br in "${BR_CORE}" "${BR_WAN}"; do
    sudo ip link del "${br}" 2>/dev/null || true
  done
}
trap cleanup EXIT

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 2
  }
}

for command in python3 qemu-system-x86_64 unzip ip curl sudo; do
  require_command "${command}"
done

mkdir -p "${EVIDENCE_DIR}"
rm -f "${QEMU_PID_FILE}" "${SERIAL_LOG}" "${WAN_SERVER_LOG}"
cleanup
trap cleanup EXIT

if [[ ! -s "${CHR_ARCHIVE}" ]]; then
  log "downloading official MikroTik CHR ${CHR_VERSION}"
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
sha256sum "${CHR_ARCHIVE}" > "${EVIDENCE_DIR}/chr-download.sha256"

create_bridge_with_tap() {
  local bridge="$1"
  local tap="$2"
  sudo ip link add name "${bridge}" type bridge
  sudo ip link set "${bridge}" up
  sudo ip tuntap add dev "${tap}" mode tap user "$(id -un)"
  sudo ip link set "${tap}" master "${bridge}"
  sudo ip link set "${tap}" up
}

create_veth_into_ns() {
  local bridge="$1"
  local host_if="$2"
  local ns_if="$3"
  local ns="$4"
  sudo ip netns add "${ns}"
  sudo ip link add "${host_if}" type veth peer name "${ns_if}"
  sudo ip link set "${host_if}" master "${bridge}"
  sudo ip link set "${host_if}" up
  sudo ip link set "${ns_if}" netns "${ns}"
  sudo ip netns exec "${ns}" ip link set lo up
  sudo ip netns exec "${ns}" ip link set "${ns_if}" up
}

send_default_probe() {
  local start_port="$1"
  local output="$2"
  sudo ip netns exec "${NS_CORE}" python3 "${ROOT}/lab/chr/udp_flow_probe.py" \
    --bind 10.10.10.2 \
    --destination "${SERVICE_IP}" \
    --destination-port "${SERVICE_PORT}" \
    --source-port-start "${start_port}" \
    --count "${FLOW_COUNT}" \
    --timeout "${FLOW_TIMEOUT}" \
    --dscp 0 \
    --output "${output}"
}

send_ef_probe() {
  local start_port="$1"
  local output="$2"
  sudo ip netns exec "${NS_CORE}" python3 "${ROOT}/lab/chr/udp_flow_probe.py" \
    --bind 10.10.10.2 \
    --destination "${SERVICE_IP}" \
    --destination-port "${SERVICE_PORT}" \
    --source-port-start "${start_port}" \
    --count "${FLOW_COUNT}" \
    --timeout "${FLOW_TIMEOUT}" \
    --dscp 46 \
    --output "${output}"
}

log "creating isolated WAN/CORE dataplane"
create_bridge_with_tap "${BR_WAN}" "${TAP_WAN}"
create_bridge_with_tap "${BR_CORE}" "${TAP_CORE}"
create_veth_into_ns "${BR_WAN}" "${V_WAN_BR}" "${V_WAN_NS}" "${NS_WAN}"
create_veth_into_ns "${BR_CORE}" "${V_CORE_BR}" "${V_CORE_NS}" "${NS_CORE}"

sudo ip netns exec "${NS_WAN}" ip addr add 192.0.2.1/30 dev "${V_WAN_NS}"
sudo ip netns exec "${NS_WAN}" ip addr add "${SERVICE_IP}/32" dev lo
sudo ip netns exec "${NS_WAN}" ip route add 10.10.10.0/24 via 192.0.2.2 dev "${V_WAN_NS}"
sudo ip netns exec "${NS_CORE}" ip addr add 10.10.10.2/24 dev "${V_CORE_NS}"
sudo ip netns exec "${NS_CORE}" ip route add default via 10.10.10.1 dev "${V_CORE_NS}"

log "starting WAN UDP responder"
sudo ip netns exec "${NS_WAN}" python3 "${ROOT}/lab/chr/udp_tag_server.py" \
  --bind "${SERVICE_IP}" --port "${SERVICE_PORT}" --tag WAN \
  >"${WAN_SERVER_LOG}" 2>&1 &
WAN_SERVER_PID=$!
sleep 0.5

log "booting three-interface disposable CHR"
qemu-system-x86_64 \
  -accel tcg,thread=multi \
  -smp 1 \
  -m 256 \
  -snapshot \
  -drive file="${CHR_IMAGE}",format=raw,if=virtio \
  -netdev user,id=mgmt,hostfwd=tcp:127.0.0.1:9880-:80 \
  -device virtio-net-pci,netdev=mgmt,mac=52:54:00:12:61:01 \
  -netdev tap,id=wan,ifname="${TAP_WAN}",script=no,downscript=no \
  -device virtio-net-pci,netdev=wan,mac=52:54:00:12:61:02 \
  -netdev tap,id=core,ifname="${TAP_CORE}",script=no,downscript=no \
  -device virtio-net-pci,netdev=core,mac=52:54:00:12:61:03 \
  -display none \
  -serial file:"${SERIAL_LOG}" \
  -daemonize \
  -pidfile "${QEMU_PID_FILE}"

ready=0
for _attempt in $(seq 1 90); do
  if curl -fsS --max-time 2 --user 'admin:' \
    "${ADMIN_URL}/rest/system/resource" \
    > "${EVIDENCE_DIR}/chr-resource.json"; then
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
  > "${EVIDENCE_DIR}/chr-interfaces.json"

python3 - "${EVIDENCE_DIR}/chr-interfaces.json" <<'PY'
import json
import sys
rows = json.load(open(sys.argv[1], encoding='utf-8'))
names = {str(row.get('name')) for row in rows if isinstance(row, dict)}
required = {'ether1', 'ether2', 'ether3'}
missing = sorted(required - names)
if missing:
    raise SystemExit(f'missing CHR QoS packet-flow interfaces: {missing}')
print(json.dumps({'ok': True, 'interfaces': sorted(names)}))
PY

VERIFIER="${ROOT}/lab/chr/verify_qos_packet_flow_v2.py"
DIAG="${ROOT}/lab/chr/diagnose_qos_queue_tree_path.py"
GLOBAL_DIAG="${ROOT}/lab/chr/diagnose_qos_global_hierarchy.py"

log "applying lab routing plus production QoS renderer output"
python3 "${VERIFIER}" prepare \
  --admin-url "${ADMIN_URL}" \
  --output "${EVIDENCE_DIR}/prepare.json"

log "capturing clean QoS counters"
python3 "${VERIFIER}" counters \
  --admin-url "${ADMIN_URL}" \
  --prepare "${EVIDENCE_DIR}/prepare.json" \
  --output "${EVIDENCE_DIR}/counters-before.json"

log "sending unmarked/default DSCP0 traffic"
send_default_probe 22000 "${EVIDENCE_DIR}/flows-default.json"
python3 "${VERIFIER}" counters \
  --admin-url "${ADMIN_URL}" \
  --prepare "${EVIDENCE_DIR}/prepare.json" \
  --output "${EVIDENCE_DIR}/counters-after-default.json"

log "sending latency-class DSCP46 traffic"
send_ef_probe 24000 "${EVIDENCE_DIR}/flows-ef.json"
python3 "${VERIFIER}" counters \
  --admin-url "${ADMIN_URL}" \
  --prepare "${EVIDENCE_DIR}/prepare.json" \
  --output "${EVIDENCE_DIR}/counters-after-ef.json"

log "capturing FastPath/FastTrack environment before queue-path A/B diagnostic"
python3 "${DIAG}" inspect \
  --admin-url "${ADMIN_URL}" \
  --output "${EVIDENCE_DIR}/queue-path-environment.json"

log "testing a single EF leaf directly parented to ether2 with builtin default-small"
python3 "${DIAG}" install \
  --admin-url "${ADMIN_URL}" \
  --prepare "${EVIDENCE_DIR}/prepare.json" \
  --mode interface \
  --output "${EVIDENCE_DIR}/queue-path-interface-install.json"
send_ef_probe 26000 "${EVIDENCE_DIR}/flows-diag-interface.json"
python3 "${DIAG}" stats \
  --admin-url "${ADMIN_URL}" \
  --name routercfg-qos-diag-interface \
  --output "${EVIDENCE_DIR}/queue-path-interface-stats.json"

log "testing the same marked EF flow through a global leaf with builtin default-small"
python3 "${DIAG}" install \
  --admin-url "${ADMIN_URL}" \
  --prepare "${EVIDENCE_DIR}/prepare.json" \
  --mode global \
  --output "${EVIDENCE_DIR}/queue-path-global-install.json"
send_ef_probe 28000 "${EVIDENCE_DIR}/flows-diag-global.json"
python3 "${DIAG}" stats \
  --admin-url "${ADMIN_URL}" \
  --name routercfg-qos-diag-global \
  --output "${EVIDENCE_DIR}/queue-path-global-stats.json"
python3 "${DIAG}" cleanup \
  --admin-url "${ADMIN_URL}" \
  --output "${EVIDENCE_DIR}/queue-path-cleanup.json"

log "testing full global parent with per-WAN default and EF packet marks"
python3 "${GLOBAL_DIAG}" install \
  --admin-url "${ADMIN_URL}" \
  --prepare "${EVIDENCE_DIR}/prepare.json" \
  --output "${EVIDENCE_DIR}/global-hierarchy-install.json"
python3 "${GLOBAL_DIAG}" counters \
  --admin-url "${ADMIN_URL}" \
  --install "${EVIDENCE_DIR}/global-hierarchy-install.json" \
  --output "${EVIDENCE_DIR}/global-hierarchy-before.json"
send_default_probe 30000 "${EVIDENCE_DIR}/flows-global-default.json"
python3 "${GLOBAL_DIAG}" counters \
  --admin-url "${ADMIN_URL}" \
  --install "${EVIDENCE_DIR}/global-hierarchy-install.json" \
  --output "${EVIDENCE_DIR}/global-hierarchy-after-default.json"
send_ef_probe 32000 "${EVIDENCE_DIR}/flows-global-ef.json"
python3 "${GLOBAL_DIAG}" counters \
  --admin-url "${ADMIN_URL}" \
  --install "${EVIDENCE_DIR}/global-hierarchy-install.json" \
  --output "${EVIDENCE_DIR}/global-hierarchy-after-ef.json"
python3 "${GLOBAL_DIAG}" evaluate \
  --before "${EVIDENCE_DIR}/global-hierarchy-before.json" \
  --after-default "${EVIDENCE_DIR}/global-hierarchy-after-default.json" \
  --after-ef "${EVIDENCE_DIR}/global-hierarchy-after-ef.json" \
  --default-flow "${EVIDENCE_DIR}/flows-global-default.json" \
  --ef-flow "${EVIDENCE_DIR}/flows-global-ef.json" \
  --output "${EVIDENCE_DIR}/global-hierarchy-acceptance.json"
python3 "${GLOBAL_DIAG}" cleanup \
  --admin-url "${ADMIN_URL}" \
  --output "${EVIDENCE_DIR}/global-hierarchy-cleanup.json"

log "evaluating current production classification and queue traversal"
python3 "${VERIFIER}" evaluate \
  --prepare "${EVIDENCE_DIR}/prepare.json" \
  --before "${EVIDENCE_DIR}/counters-before.json" \
  --after-default "${EVIDENCE_DIR}/counters-after-default.json" \
  --after-ef "${EVIDENCE_DIR}/counters-after-ef.json" \
  --default-flow "${EVIDENCE_DIR}/flows-default.json" \
  --ef-flow "${EVIDENCE_DIR}/flows-ef.json" \
  --output "${EVIDENCE_DIR}/evaluation.json"

log "rolling back only owned QoS/lab objects and verifying exact baseline"
python3 "${VERIFIER}" finalize \
  --admin-url "${ADMIN_URL}" \
  --prepare "${EVIDENCE_DIR}/prepare.json" \
  --evaluation "${EVIDENCE_DIR}/evaluation.json" \
  --output "${EVIDENCE_DIR}/packet-flow-acceptance.json"

log "PASS: DSCP0 default and DSCP46 priority classification/traversal verified without latency claim"
