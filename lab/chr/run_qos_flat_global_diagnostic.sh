#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHR_VERSION="${CHR_VERSION:-7.24.1}"
CHR_ARCHIVE="${CHR_ARCHIVE:-/tmp/chr-${CHR_VERSION}.img.zip}"
CHR_IMAGE="${CHR_IMAGE:-/tmp/chr-qos-flat-global.img}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:9890}"
EVIDENCE_DIR="${EVIDENCE_DIR:-${ROOT}/evidence/chr-qos-flat-global}"
FLOW_COUNT="${FLOW_COUNT:-80}"
FLOW_TIMEOUT="${FLOW_TIMEOUT:-0.30}"
SERVICE_IP="203.0.113.100"
SERVICE_PORT="5000"

NS_WAN="rc-qos-flat-wan"
NS_CORE="rc-qos-flat-core"
BR_WAN="br-rc-qos-flat-wan"
BR_CORE="br-rc-qos-flat-core"
TAP_WAN="tap-rc-qos-flat-wan"
TAP_CORE="tap-rc-qos-flat-core"
V_WAN_BR="vqf-wan-br"
V_WAN_NS="vqf-wan-ns"
V_CORE_BR="vqf-core-br"
V_CORE_NS="vqf-core-ns"
QEMU_PID_FILE="/tmp/chr-qos-flat-global.pid"
SERIAL_LOG="/tmp/chr-qos-flat-global-serial.log"
WAN_SERVER_LOG="/tmp/chr-qos-flat-global-wan.log"
WAN_SERVER_PID=""

log() {
  printf '[chr-qos-flat] %s\n' "$*"
}

cleanup() {
  if [[ -n "${WAN_SERVER_PID}" ]]; then sudo kill "${WAN_SERVER_PID}" 2>/dev/null || true; fi
  if [[ -f "${QEMU_PID_FILE}" ]]; then kill "$(cat "${QEMU_PID_FILE}")" 2>/dev/null || true; fi
  for ns in "${NS_CORE}" "${NS_WAN}"; do sudo ip netns del "${ns}" 2>/dev/null || true; done
  for tap in "${TAP_CORE}" "${TAP_WAN}"; do sudo ip link del "${tap}" 2>/dev/null || true; done
  for br in "${BR_CORE}" "${BR_WAN}"; do sudo ip link del "${br}" 2>/dev/null || true; done
}
trap cleanup EXIT

for command in python3 qemu-system-x86_64 unzip ip curl sudo; do
  command -v "${command}" >/dev/null 2>&1 || { echo "missing required command: ${command}" >&2; exit 2; }
done

mkdir -p "${EVIDENCE_DIR}"
rm -f "${QEMU_PID_FILE}" "${SERIAL_LOG}" "${WAN_SERVER_LOG}"
cleanup
trap cleanup EXIT

if [[ ! -s "${CHR_ARCHIVE}" ]]; then
  log "downloading official MikroTik CHR ${CHR_VERSION}"
  curl -4 --http1.1 -fL --connect-timeout 15 --max-time 180 --retry 1 --retry-delay 2 --retry-all-errors \
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

send_probe() {
  local dscp="$1"
  local start_port="$2"
  local output="$3"
  sudo ip netns exec "${NS_CORE}" python3 "${ROOT}/lab/chr/udp_flow_probe.py" \
    --bind 10.10.10.2 \
    --destination "${SERVICE_IP}" \
    --destination-port "${SERVICE_PORT}" \
    --source-port-start "${start_port}" \
    --count "${FLOW_COUNT}" \
    --timeout "${FLOW_TIMEOUT}" \
    --dscp "${dscp}" \
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

sudo ip netns exec "${NS_WAN}" python3 "${ROOT}/lab/chr/udp_tag_server.py" \
  --bind "${SERVICE_IP}" --port "${SERVICE_PORT}" --tag WAN \
  >"${WAN_SERVER_LOG}" 2>&1 &
WAN_SERVER_PID=$!
sleep 0.5

log "booting disposable three-interface CHR snapshot"
qemu-system-x86_64 \
  -accel tcg,thread=multi -smp 1 -m 256 -snapshot \
  -drive file="${CHR_IMAGE}",format=raw,if=virtio \
  -netdev user,id=mgmt,hostfwd=tcp:127.0.0.1:9890-:80 \
  -device virtio-net-pci,netdev=mgmt,mac=52:54:00:12:71:01 \
  -netdev tap,id=wan,ifname="${TAP_WAN}",script=no,downscript=no \
  -device virtio-net-pci,netdev=wan,mac=52:54:00:12:71:02 \
  -netdev tap,id=core,ifname="${TAP_CORE}",script=no,downscript=no \
  -device virtio-net-pci,netdev=core,mac=52:54:00:12:71:03 \
  -display none -serial file:"${SERIAL_LOG}" -daemonize -pidfile "${QEMU_PID_FILE}"

ready=0
for _attempt in $(seq 1 90); do
  if curl -fsS --max-time 2 --user 'admin:' "${ADMIN_URL}/rest/system/resource" \
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
curl -fsS --user 'admin:' "${ADMIN_URL}/rest/interface" > "${EVIDENCE_DIR}/chr-interfaces.json"
python3 - "${EVIDENCE_DIR}/chr-interfaces.json" <<'PY'
import json, sys
rows = json.load(open(sys.argv[1], encoding='utf-8'))
names = {str(row.get('name')) for row in rows if isinstance(row, dict)}
missing = sorted({'ether1', 'ether2', 'ether3'} - names)
if missing:
    raise SystemExit(f'missing CHR flat-global interfaces: {missing}')
print(json.dumps({'ok': True, 'interfaces': sorted(names)}))
PY

VERIFIER="${ROOT}/lab/chr/verify_qos_packet_flow_v2.py"
FLAT="${ROOT}/lab/chr/diagnose_qos_flat_global.py"

log "preparing production-owned EF mark and lab routing facts"
python3 "${VERIFIER}" prepare --admin-url "${ADMIN_URL}" --output "${EVIDENCE_DIR}/prepare.json"

run_mode() {
  local queue="$1"
  local slug="$2"
  local default_port="$3"
  local ef_port="$4"

  log "testing flat-global leaves with queue=${queue}"
  python3 "${FLAT}" install \
    --admin-url "${ADMIN_URL}" --prepare "${EVIDENCE_DIR}/prepare.json" --queue "${queue}" \
    --output "${EVIDENCE_DIR}/${slug}-install.json"
  python3 "${FLAT}" counters \
    --admin-url "${ADMIN_URL}" --install "${EVIDENCE_DIR}/${slug}-install.json" \
    --output "${EVIDENCE_DIR}/${slug}-before.json"

  send_probe 0 "${default_port}" "${EVIDENCE_DIR}/${slug}-flows-default.json"
  python3 "${FLAT}" counters \
    --admin-url "${ADMIN_URL}" --install "${EVIDENCE_DIR}/${slug}-install.json" \
    --output "${EVIDENCE_DIR}/${slug}-after-default.json"

  send_probe 46 "${ef_port}" "${EVIDENCE_DIR}/${slug}-flows-ef.json"
  python3 "${FLAT}" counters \
    --admin-url "${ADMIN_URL}" --install "${EVIDENCE_DIR}/${slug}-install.json" \
    --output "${EVIDENCE_DIR}/${slug}-after-ef.json"

  python3 "${FLAT}" evaluate \
    --before "${EVIDENCE_DIR}/${slug}-before.json" \
    --after-default "${EVIDENCE_DIR}/${slug}-after-default.json" \
    --after-ef "${EVIDENCE_DIR}/${slug}-after-ef.json" \
    --default-flow "${EVIDENCE_DIR}/${slug}-flows-default.json" \
    --ef-flow "${EVIDENCE_DIR}/${slug}-flows-ef.json" \
    --output "${EVIDENCE_DIR}/${slug}-acceptance.json"

  python3 "${FLAT}" cleanup --admin-url "${ADMIN_URL}" --output "${EVIDENCE_DIR}/${slug}-cleanup.json"
}

run_mode "default-small" "flat-default-small" 34000 36000
run_mode "routercfg-qos-fq" "flat-fq-codel" 38000 40000

python3 - "${EVIDENCE_DIR}/flat-default-small-acceptance.json" "${EVIDENCE_DIR}/flat-fq-codel-acceptance.json" "${EVIDENCE_DIR}/summary.json" <<'PY'
import json, sys
from pathlib import Path
builtin = json.load(open(sys.argv[1], encoding='utf-8'))
fq = json.load(open(sys.argv[2], encoding='utf-8'))
if builtin.get('acceptance') != 'PASS' or builtin.get('packet_flow_acceptance') is not True:
    raise SystemExit('default-small flat-global candidate did not pass')
if fq.get('acceptance') != 'PASS' or fq.get('packet_flow_acceptance') is not True:
    raise SystemExit('fq-codel flat-global candidate did not pass')
summary = {
    'ok': True,
    'acceptance': 'PASS',
    'scope': 'flat_global_candidate_dataplane_only',
    'builtin_queue_pass': True,
    'fq_codel_pass': True,
    'production_renderer_migrated': False,
    'production_packet_flow_acceptance': False,
    'multi_wan_isolation_claimed': False,
    'aggregate_shaping_claimed': False,
    'latency_performance_claimed': False,
    'bandwidth_guarantee_claimed': False,
    'production_writer_available': False,
    'physical_router_targeted': False,
}
Path(sys.argv[3]).write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
print(json.dumps(summary, indent=2, sort_keys=True))
PY

log "PASS: flat-global default-small and FQ-CoDel candidates both traversed correct leaves"
