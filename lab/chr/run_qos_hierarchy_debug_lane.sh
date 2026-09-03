#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHR_VERSION="${CHR_VERSION:-7.24.1}"
CHR_ARCHIVE="${CHR_ARCHIVE:-/tmp/chr-${CHR_VERSION}.img.zip}"
CHR_IMAGE="${CHR_IMAGE:-/tmp/chr-qos-hdbg.img}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:9896}"
EVIDENCE_DIR="${EVIDENCE_DIR:-${ROOT}/evidence/chr-qos-hierarchy-debug}"
DEBUG_LANE="${DEBUG_LANE:?DEBUG_LANE is required}"
FLOW_COUNT="${FLOW_COUNT:-80}"
FLOW_TIMEOUT="${FLOW_TIMEOUT:-0.30}"
SERVICE_IP="203.0.113.100"
SERVICE_PORT="5000"

NS_WAN="rc-qhdbg-wan"
NS_CORE="rc-qhdbg-core"
BR_WAN="brqhdbgwan"
BR_CORE="brqhdbgcore"
TAP_WAN="tapqhdbgwan"
TAP_CORE="tapqhdbgcore"
V_WAN_BR="vqh-wan-br"
V_WAN_NS="vqh-wan-ns"
V_CORE_BR="vqh-core-br"
V_CORE_NS="vqh-core-ns"
QEMU_PID_FILE="/tmp/chr-qos-hdbg.pid"
SERIAL_LOG="/tmp/chr-qos-hdbg-serial.log"
SERVER_LOG="/tmp/chr-qos-hdbg-server.log"
SERVER_PID=""

log() { printf '[chr-qos-hdbg:%s] %s\n' "${DEBUG_LANE}" "$*"; }

cleanup_host() {
  if [[ -n "${SERVER_PID}" ]]; then sudo kill "${SERVER_PID}" 2>/dev/null || true; fi
  if [[ -f "${QEMU_PID_FILE}" ]]; then kill "$(cat "${QEMU_PID_FILE}")" 2>/dev/null || true; fi
  for ns in "${NS_CORE}" "${NS_WAN}"; do sudo ip netns del "${ns}" 2>/dev/null || true; done
  for tap in "${TAP_CORE}" "${TAP_WAN}"; do sudo ip link del "${tap}" 2>/dev/null || true; done
  for br in "${BR_CORE}" "${BR_WAN}"; do sudo ip link del "${br}" 2>/dev/null || true; done
}
trap cleanup_host EXIT

case "${DEBUG_LANE}" in
  prod-dscp-global-single)
    MODE=single
    SINGLE_DSCP=46
    SINGLE_PORT=54000
    ;;
  prerouting-port-interface-single)
    MODE=single
    SINGLE_DSCP=0
    SINGLE_PORT=55000
    ;;
  port-global-hierarchy)
    MODE=hierarchy
    DEFAULT_PORT=57000
    SPECIAL_PORT=56000
    SPECIAL_DSCP=0
    ;;
  prod-dscp-global-hierarchy)
    MODE=hierarchy
    DEFAULT_PORT=59000
    SPECIAL_PORT=58000
    SPECIAL_DSCP=46
    ;;
  prerouting-dscp-global-hierarchy)
    MODE=hierarchy
    DEFAULT_PORT=61000
    SPECIAL_PORT=60000
    SPECIAL_DSCP=46
    ;;
  *)
    echo "unsupported DEBUG_LANE=${DEBUG_LANE}" >&2
    exit 2
    ;;
esac

for command in python3 qemu-system-x86_64 unzip ip curl sudo; do
  command -v "${command}" >/dev/null 2>&1 || { echo "missing required command: ${command}" >&2; exit 2; }
done
mkdir -p "${EVIDENCE_DIR}"
rm -f "${QEMU_PID_FILE}" "${SERIAL_LOG}" "${SERVER_LOG}"
cleanup_host
trap cleanup_host EXIT

if [[ ! -s "${CHR_ARCHIVE}" ]]; then
  log "downloading official MikroTik CHR ${CHR_VERSION}"
  curl -4 --http1.1 -fL --connect-timeout 15 --max-time 180 --retry 1 --retry-delay 2 --retry-all-errors \
    "https://download.mikrotik.com/routeros/${CHR_VERSION}/chr-${CHR_VERSION}.img.zip" -o "${CHR_ARCHIVE}"
fi
unzip -t "${CHR_ARCHIVE}" >/dev/null
unzip -p "${CHR_ARCHIVE}" > "${CHR_IMAGE}"
test -s "${CHR_IMAGE}"
sha256sum "${CHR_ARCHIVE}" > "${EVIDENCE_DIR}/chr-download.sha256"

create_bridge_with_tap() {
  local bridge="$1" tap="$2"
  sudo ip link add name "${bridge}" type bridge
  sudo ip link set "${bridge}" up
  sudo ip tuntap add dev "${tap}" mode tap user "$(id -un)"
  sudo ip link set "${tap}" master "${bridge}"
  sudo ip link set "${tap}" up
}

create_veth_into_ns() {
  local bridge="$1" host_if="$2" ns_if="$3" ns="$4"
  sudo ip netns add "${ns}"
  sudo ip link add "${host_if}" type veth peer name "${ns_if}"
  sudo ip link set "${host_if}" master "${bridge}"
  sudo ip link set "${host_if}" up
  sudo ip link set "${ns_if}" netns "${ns}"
  sudo ip netns exec "${ns}" ip link set lo up
  sudo ip netns exec "${ns}" ip link set "${ns_if}" up
}

send_probe() {
  local dscp="$1" source_port="$2" output="$3"
  sudo ip netns exec "${NS_CORE}" python3 "${ROOT}/lab/chr/udp_flow_probe.py" \
    --bind 10.10.10.2 --destination "${SERVICE_IP}" --destination-port "${SERVICE_PORT}" \
    --source-port-start "${source_port}" --count "${FLOW_COUNT}" --timeout "${FLOW_TIMEOUT}" \
    --dscp "${dscp}" --output "${output}"
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
  --bind "${SERVICE_IP}" --port "${SERVICE_PORT}" --tag WAN >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 0.5

log "booting official disposable three-interface CHR snapshot"
qemu-system-x86_64 \
  -accel tcg,thread=multi -smp 1 -m 256 -snapshot \
  -drive file="${CHR_IMAGE}",format=raw,if=virtio \
  -netdev user,id=mgmt,hostfwd=tcp:127.0.0.1:9896-:80 \
  -device virtio-net-pci,netdev=mgmt,mac=52:54:00:12:86:01 \
  -netdev tap,id=wan,ifname="${TAP_WAN}",script=no,downscript=no \
  -device virtio-net-pci,netdev=wan,mac=52:54:00:12:86:02 \
  -netdev tap,id=core,ifname="${TAP_CORE}",script=no,downscript=no \
  -device virtio-net-pci,netdev=core,mac=52:54:00:12:86:03 \
  -display none -serial file:"${SERIAL_LOG}" -daemonize -pidfile "${QEMU_PID_FILE}"

ready=0
for _attempt in $(seq 1 90); do
  if curl -fsS --max-time 2 --user 'admin:' "${ADMIN_URL}/rest/system/resource" > "${EVIDENCE_DIR}/chr-resource.json"; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "${ready}" -ne 1 ]]; then cat "${SERIAL_LOG}" >&2 || true; exit 3; fi

PREPARE="${ROOT}/lab/chr/verify_qos_packet_flow_v2.py"
DEBUG="${ROOT}/lab/chr/debug_qos_hierarchy_paths.py"
python3 "${PREPARE}" prepare --admin-url "${ADMIN_URL}" --output "${EVIDENCE_DIR}/prepare.json"
python3 "${DEBUG}" install --admin-url "${ADMIN_URL}" --prepare "${EVIDENCE_DIR}/prepare.json" \
  --lane "${DEBUG_LANE}" --output "${EVIDENCE_DIR}/install.json"
python3 "${DEBUG}" counters --admin-url "${ADMIN_URL}" --prepare "${EVIDENCE_DIR}/prepare.json" \
  --lane "${DEBUG_LANE}" --output "${EVIDENCE_DIR}/before.json"

if [[ "${MODE}" == "single" ]]; then
  send_probe "${SINGLE_DSCP}" "${SINGLE_PORT}" "${EVIDENCE_DIR}/flow.json"
  for attempt in $(seq 1 20); do
    python3 "${DEBUG}" counters --admin-url "${ADMIN_URL}" --prepare "${EVIDENCE_DIR}/prepare.json" \
      --lane "${DEBUG_LANE}" --output "${EVIDENCE_DIR}/after.json"
    if python3 - "${EVIDENCE_DIR}/before.json" "${EVIDENCE_DIR}/after.json" <<'PY'
import json, sys
b = json.load(open(sys.argv[1], encoding='utf-8'))
a = json.load(open(sys.argv[2], encoding='utf-8'))
ready = int(a['classifier_packets']) > int(b['classifier_packets']) and int(a['leaf_packets']) > int(b['leaf_packets'])
raise SystemExit(0 if ready else 1)
PY
    then break; fi
    sleep 0.25
  done
  python3 "${DEBUG}" evaluate-single --lane "${DEBUG_LANE}" \
    --before "${EVIDENCE_DIR}/before.json" --after "${EVIDENCE_DIR}/after.json" \
    --flow "${EVIDENCE_DIR}/flow.json" --output "${EVIDENCE_DIR}/acceptance.json"
else
  send_probe 0 "${DEFAULT_PORT}" "${EVIDENCE_DIR}/default-flow.json"
  for attempt in $(seq 1 20); do
    python3 "${DEBUG}" counters --admin-url "${ADMIN_URL}" --prepare "${EVIDENCE_DIR}/prepare.json" \
      --lane "${DEBUG_LANE}" --output "${EVIDENCE_DIR}/after-default.json"
    if python3 - "${EVIDENCE_DIR}/before.json" "${EVIDENCE_DIR}/after-default.json" <<'PY'
import json, sys
b = json.load(open(sys.argv[1], encoding='utf-8'))
a = json.load(open(sys.argv[2], encoding='utf-8'))
ready = int(a['parent_packets']) > int(b['parent_packets'])
raise SystemExit(0 if ready else 1)
PY
    then break; fi
    sleep 0.25
  done

  send_probe "${SPECIAL_DSCP}" "${SPECIAL_PORT}" "${EVIDENCE_DIR}/special-flow.json"
  for attempt in $(seq 1 20); do
    python3 "${DEBUG}" counters --admin-url "${ADMIN_URL}" --prepare "${EVIDENCE_DIR}/prepare.json" \
      --lane "${DEBUG_LANE}" --output "${EVIDENCE_DIR}/after-special.json"
    if python3 - "${EVIDENCE_DIR}/after-default.json" "${EVIDENCE_DIR}/after-special.json" <<'PY'
import json, sys
b = json.load(open(sys.argv[1], encoding='utf-8'))
a = json.load(open(sys.argv[2], encoding='utf-8'))
ready = (
    int(a['classifier_packets']) > int(b['classifier_packets'])
    and int(a['child_packets']) > int(b['child_packets'])
    and int(a['parent_packets']) > int(b['parent_packets'])
)
raise SystemExit(0 if ready else 1)
PY
    then break; fi
    sleep 0.25
  done

  python3 "${DEBUG}" evaluate-hierarchy --lane "${DEBUG_LANE}" \
    --before "${EVIDENCE_DIR}/before.json" --after-default "${EVIDENCE_DIR}/after-default.json" \
    --after-special "${EVIDENCE_DIR}/after-special.json" --default-flow "${EVIDENCE_DIR}/default-flow.json" \
    --special-flow "${EVIDENCE_DIR}/special-flow.json" --output "${EVIDENCE_DIR}/acceptance.json"
fi

python3 "${DEBUG}" cleanup --admin-url "${ADMIN_URL}" --prepare "${EVIDENCE_DIR}/prepare.json" \
  --output "${EVIDENCE_DIR}/cleanup.json"
python3 - "${EVIDENCE_DIR}/acceptance.json" "${EVIDENCE_DIR}/summary.json" <<'PY'
import json, sys
from pathlib import Path
result = json.load(open(sys.argv[1], encoding='utf-8'))
if result.get('acceptance') != 'PASS':
    raise SystemExit('hierarchy debug lane did not pass')
summary = {
    'ok': True,
    'acceptance': 'PASS',
    'lane': result['lane'],
    'scope': result['scope'],
    'production_packet_flow_acceptance': False,
    'production_renderer_modified': False,
    'production_writer_available': False,
    'physical_router_targeted': False,
}
Path(sys.argv[2]).write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
print(json.dumps(summary, indent=2, sort_keys=True))
PY
log "PASS: hierarchy/attachment debug lane completed"
