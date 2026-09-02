#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHR_VERSION="${CHR_VERSION:-7.24.1}"
CHR_ARCHIVE="${CHR_ARCHIVE:-/tmp/chr-${CHR_VERSION}.img.zip}"
CHR_IMAGE="${CHR_IMAGE:-/tmp/chr-packet-flow.img}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:9380}"
EVIDENCE_DIR="${EVIDENCE_DIR:-${ROOT}/evidence/chr-packet-flow}"
FLOW_COUNT="${FLOW_COUNT:-220}"
FLOW_TIMEOUT="${FLOW_TIMEOUT:-0.25}"
SERVICE_IP="203.0.113.100"
SERVICE_PORT="5000"

NS_WAN10="rc-wan10"
NS_WAN1="rc-wan1"
NS_CORE="rc-core"
BR_WAN10="br-rc-w10"
BR_WAN1="br-rc-w1"
BR_CORE="br-rc-core"
TAP_WAN10="tap-rc-w10"
TAP_WAN1="tap-rc-w1"
TAP_CORE="tap-rc-core"
V_WAN10_BR="v-w10-br"
V_WAN10_NS="v-w10-ns"
V_WAN1_BR="v-w1-br"
V_WAN1_NS="v-w1-ns"
V_CORE_BR="v-core-br"
V_CORE_NS="v-core-ns"
QEMU_PID_FILE="/tmp/chr-packet-flow.pid"
SERIAL_LOG="/tmp/chr-packet-flow-serial.log"
WAN10_SERVER_LOG="/tmp/chr-packet-flow-wan10-server.log"
WAN1_SERVER_LOG="/tmp/chr-packet-flow-wan1-server.log"
WAN10_SERVER_PID=""
WAN1_SERVER_PID=""

log() {
  printf '[chr-flow] %s\n' "$*"
}

cleanup() {
  set +e
  if [[ -n "${WAN10_SERVER_PID}" ]]; then sudo kill "${WAN10_SERVER_PID}" 2>/dev/null || true; fi
  if [[ -n "${WAN1_SERVER_PID}" ]]; then sudo kill "${WAN1_SERVER_PID}" 2>/dev/null || true; fi
  if [[ -f "${QEMU_PID_FILE}" ]]; then
    kill "$(cat "${QEMU_PID_FILE}")" 2>/dev/null || true
  fi
  for ns in "${NS_CORE}" "${NS_WAN1}" "${NS_WAN10}"; do
    sudo ip netns del "${ns}" 2>/dev/null || true
  done
  for tap in "${TAP_CORE}" "${TAP_WAN1}" "${TAP_WAN10}"; do
    sudo ip link del "${tap}" 2>/dev/null || true
  done
  for br in "${BR_CORE}" "${BR_WAN1}" "${BR_WAN10}"; do
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
rm -f "${QEMU_PID_FILE}" "${SERIAL_LOG}" "${WAN10_SERVER_LOG}" "${WAN1_SERVER_LOG}"
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

log "creating isolated WAN10/WAN1/CORE dataplane"
create_bridge_with_tap "${BR_WAN10}" "${TAP_WAN10}"
create_bridge_with_tap "${BR_WAN1}" "${TAP_WAN1}"
create_bridge_with_tap "${BR_CORE}" "${TAP_CORE}"
create_veth_into_ns "${BR_WAN10}" "${V_WAN10_BR}" "${V_WAN10_NS}" "${NS_WAN10}"
create_veth_into_ns "${BR_WAN1}" "${V_WAN1_BR}" "${V_WAN1_NS}" "${NS_WAN1}"
create_veth_into_ns "${BR_CORE}" "${V_CORE_BR}" "${V_CORE_NS}" "${NS_CORE}"

sudo ip netns exec "${NS_WAN10}" ip addr add 192.0.2.1/30 dev "${V_WAN10_NS}"
sudo ip netns exec "${NS_WAN10}" ip addr add "${SERVICE_IP}/32" dev lo
sudo ip netns exec "${NS_WAN10}" ip addr add 1.1.1.1/32 dev lo
sudo ip netns exec "${NS_WAN10}" ip addr add 8.8.8.8/32 dev lo
sudo ip netns exec "${NS_WAN10}" ip route add 10.10.10.0/24 via 192.0.2.2 dev "${V_WAN10_NS}"

sudo ip netns exec "${NS_WAN1}" ip addr add 198.51.100.1/30 dev "${V_WAN1_NS}"
sudo ip netns exec "${NS_WAN1}" ip addr add "${SERVICE_IP}/32" dev lo
sudo ip netns exec "${NS_WAN1}" ip addr add 9.9.9.9/32 dev lo
sudo ip netns exec "${NS_WAN1}" ip addr add 208.67.222.222/32 dev lo
sudo ip netns exec "${NS_WAN1}" ip route add 10.10.10.0/24 via 198.51.100.2 dev "${V_WAN1_NS}"

sudo ip netns exec "${NS_CORE}" ip addr add 10.10.10.2/24 dev "${V_CORE_NS}"
sudo ip netns exec "${NS_CORE}" ip route add default via 10.10.10.1 dev "${V_CORE_NS}"

log "starting tagged WAN responders"
sudo ip netns exec "${NS_WAN10}" python3 "${ROOT}/lab/chr/udp_tag_server.py" \
  --bind "${SERVICE_IP}" --port "${SERVICE_PORT}" --tag WAN10 \
  >"${WAN10_SERVER_LOG}" 2>&1 &
WAN10_SERVER_PID=$!
sudo ip netns exec "${NS_WAN1}" python3 "${ROOT}/lab/chr/udp_tag_server.py" \
  --bind "${SERVICE_IP}" --port "${SERVICE_PORT}" --tag WAN1 \
  >"${WAN1_SERVER_LOG}" 2>&1 &
WAN1_SERVER_PID=$!
sleep 0.5

log "booting four-interface disposable CHR"
qemu-system-x86_64 \
  -accel tcg,thread=multi \
  -smp 1 \
  -m 256 \
  -snapshot \
  -drive file="${CHR_IMAGE}",format=raw,if=virtio \
  -netdev user,id=mgmt,hostfwd=tcp:127.0.0.1:9380-:80 \
  -device virtio-net-pci,netdev=mgmt,mac=52:54:00:12:36:01 \
  -netdev tap,id=wan10,ifname="${TAP_WAN10}",script=no,downscript=no \
  -device virtio-net-pci,netdev=wan10,mac=52:54:00:12:36:02 \
  -netdev tap,id=wan1,ifname="${TAP_WAN1}",script=no,downscript=no \
  -device virtio-net-pci,netdev=wan1,mac=52:54:00:12:36:03 \
  -netdev tap,id=core,ifname="${TAP_CORE}",script=no,downscript=no \
  -device virtio-net-pci,netdev=core,mac=52:54:00:12:36:04 \
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
required = {'ether1', 'ether2', 'ether3', 'ether4'}
missing = sorted(required - names)
if missing:
    raise SystemExit(f'missing CHR packet-flow interfaces: {missing}')
print(json.dumps({'ok': True, 'interfaces': sorted(names)}))
PY

log "rendering and applying 17 recursive + 21 PCC commands"
python3 "${ROOT}/lab/chr/verify_packet_flow_behavior.py" prepare \
  --admin-url "${ADMIN_URL}" \
  --output "${EVIDENCE_DIR}/prepare.json"
python3 "${ROOT}/lab/chr/verify_packet_flow_behavior.py" wait-routes \
  --admin-url "${ADMIN_URL}" \
  --expected normal \
  --timeout-seconds 15 \
  --output "${EVIDENCE_DIR}/routes-normal.json"

probe_phase() {
  local start_port="$1"
  local output="$2"
  sudo ip netns exec "${NS_CORE}" python3 "${ROOT}/lab/chr/udp_flow_probe.py" \
    --bind 10.10.10.2 \
    --destination "${SERVICE_IP}" \
    --destination-port "${SERVICE_PORT}" \
    --source-port-start "${start_port}" \
    --count "${FLOW_COUNT}" \
    --timeout "${FLOW_TIMEOUT}" \
    --output "${output}"
}

log "measuring normal 10:1 PCC distribution"
probe_phase 20000 "${EVIDENCE_DIR}/flows-normal.json"
curl -fsS --user 'admin:' "${ADMIN_URL}/rest/ip/firewall/mangle" \
  > "${EVIDENCE_DIR}/mangle-after-normal.json"

log "cutting WAN10 reachability and waiting for recursive failover"
sudo ip link set "${V_WAN10_BR}" down
python3 "${ROOT}/lab/chr/verify_packet_flow_behavior.py" wait-routes \
  --admin-url "${ADMIN_URL}" \
  --expected wan10_failed \
  --timeout-seconds 15 \
  --output "${EVIDENCE_DIR}/routes-wan10-failed.json"
probe_phase 30000 "${EVIDENCE_DIR}/flows-failover.json"
curl -fsS --user 'admin:' "${ADMIN_URL}/rest/ip/route" \
  > "${EVIDENCE_DIR}/routes-after-failover.json"

log "restoring WAN10 and waiting for failback"
sudo ip link set "${V_WAN10_BR}" up
python3 "${ROOT}/lab/chr/verify_packet_flow_behavior.py" wait-routes \
  --admin-url "${ADMIN_URL}" \
  --expected recovered \
  --timeout-seconds 15 \
  --output "${EVIDENCE_DIR}/routes-recovered.json"
probe_phase 40000 "${EVIDENCE_DIR}/flows-recovery.json"
curl -fsS --user 'admin:' "${ADMIN_URL}/rest/ip/firewall/mangle" \
  > "${EVIDENCE_DIR}/mangle-after-recovery.json"

log "evaluating end-to-end packet-flow acceptance"
python3 "${ROOT}/lab/chr/verify_packet_flow_behavior.py" evaluate \
  --normal "${EVIDENCE_DIR}/flows-normal.json" \
  --failover "${EVIDENCE_DIR}/flows-failover.json" \
  --recovery "${EVIDENCE_DIR}/flows-recovery.json" \
  --failed-routes "${EVIDENCE_DIR}/routes-wan10-failed.json" \
  --recovered-routes "${EVIDENCE_DIR}/routes-recovered.json" \
  --output "${EVIDENCE_DIR}/packet-flow-acceptance.json"

cp "${SERIAL_LOG}" "${EVIDENCE_DIR}/chr-serial.log" || true
cp "${WAN10_SERVER_LOG}" "${EVIDENCE_DIR}/wan10-server.log" || true
cp "${WAN1_SERVER_LOG}" "${EVIDENCE_DIR}/wan1-server.log" || true
log "PASS: real CHR PCC distribution, failover and failback behavior verified"
