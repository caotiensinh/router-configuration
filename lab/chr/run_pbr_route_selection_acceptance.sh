#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHR_VERSION="${CHR_VERSION:-7.24.1}"
CHR_ARCHIVE="${CHR_ARCHIVE:-/tmp/chr-${CHR_VERSION}.img.zip}"
CHR_IMAGE="${CHR_IMAGE:-/tmp/chr-pbr-flow.img}"
WORKFLOW_SHA="${WORKFLOW_SHA:-${GITHUB_SHA:-local}}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:10280}"
EVIDENCE_DIR="${EVIDENCE_DIR:-${ROOT}/evidence/chr-pbr-route-selection}"
FLOW_COUNT="${FLOW_COUNT:-30}"
SERVICE_IP="203.0.113.100"
SERVICE_PORT="5000"

BR_CORE="br-pbr-core"
BR_WAN="br-pbr-wan"
TAP_CORE="tap-pbr-core"
TAP_WAN="tap-pbr-wan"
NS_CORE="rc-pbr-core"
NS_WAN="rc-pbr-wan"
V_CORE_BR="vpc-br"
V_CORE_NS="vpc-ns"
V_WAN_BR="vpw-br"
V_WAN_NS="vpw-ns"
PID_FILE="/tmp/chr-pbr-flow.pid"
SERIAL_LOG="/tmp/chr-pbr-flow-serial.log"
SERVER_LOG="/tmp/chr-pbr-flow-server.log"
SERVER_PID=""

log() {
  printf '[chr-pbr-flow] %s\n' "$*"
}

cleanup() {
  if [[ -n "${SERVER_PID}" ]]; then sudo kill "${SERVER_PID}" 2>/dev/null || true; fi
  if [[ -f "${PID_FILE}" ]]; then kill "$(cat "${PID_FILE}")" 2>/dev/null || true; fi
  sudo ip netns del "${NS_CORE}" 2>/dev/null || true
  sudo ip netns del "${NS_WAN}" 2>/dev/null || true
  for dev in "${TAP_CORE}" "${TAP_WAN}" "${BR_CORE}" "${BR_WAN}"; do
    sudo ip link del "${dev}" 2>/dev/null || true
  done
}
trap cleanup EXIT

for command in python3 qemu-system-x86_64 unzip ip curl sudo; do
  command -v "${command}" >/dev/null 2>&1 || { echo "missing required command: ${command}" >&2; exit 2; }
done

mkdir -p "${EVIDENCE_DIR}"
rm -f "${PID_FILE}" "${SERIAL_LOG}" "${SERVER_LOG}"
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

bridge_tap() {
  local bridge="$1"
  local tap="$2"
  sudo ip link add name "${bridge}" type bridge
  sudo ip link set "${bridge}" up
  sudo ip tuntap add dev "${tap}" mode tap user "$(id -un)"
  sudo ip link set "${tap}" master "${bridge}"
  sudo ip link set "${tap}" up
}

bridge_tap "${BR_CORE}" "${TAP_CORE}"
bridge_tap "${BR_WAN}" "${TAP_WAN}"

sudo ip netns add "${NS_CORE}"
sudo ip link add "${V_CORE_BR}" type veth peer name "${V_CORE_NS}"
sudo ip link set "${V_CORE_BR}" master "${BR_CORE}"
sudo ip link set "${V_CORE_BR}" up
sudo ip link set "${V_CORE_NS}" netns "${NS_CORE}"
sudo ip netns exec "${NS_CORE}" ip link set lo up
sudo ip netns exec "${NS_CORE}" ip link set "${V_CORE_NS}" up
sudo ip netns exec "${NS_CORE}" ip addr add 198.51.100.2/24 dev "${V_CORE_NS}"
sudo ip netns exec "${NS_CORE}" ip route add default via 198.51.100.1 dev "${V_CORE_NS}"

sudo ip netns add "${NS_WAN}"
sudo ip link add "${V_WAN_BR}" type veth peer name "${V_WAN_NS}"
sudo ip link set "${V_WAN_BR}" master "${BR_WAN}"
sudo ip link set "${V_WAN_BR}" up
sudo ip link set "${V_WAN_NS}" netns "${NS_WAN}"
sudo ip netns exec "${NS_WAN}" ip link set lo up
sudo ip netns exec "${NS_WAN}" ip link set "${V_WAN_NS}" up
sudo ip netns exec "${NS_WAN}" ip addr add 192.0.2.1/30 dev "${V_WAN_NS}"
sudo ip netns exec "${NS_WAN}" ip addr add "${SERVICE_IP}/32" dev lo
sudo ip netns exec "${NS_WAN}" ip route add 198.51.100.0/24 via 192.0.2.2 dev "${V_WAN_NS}"

log "starting selected-WAN tagged UDP responder"
sudo ip netns exec "${NS_WAN}" python3 "${ROOT}/lab/chr/udp_tag_server.py" \
  --bind "${SERVICE_IP}" --port "${SERVICE_PORT}" --tag PBR \
  > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 0.5

log "booting three-interface disposable CHR"
qemu-system-x86_64 \
  -accel tcg,thread=multi \
  -smp 1 \
  -m 256 \
  -snapshot \
  -drive file="${CHR_IMAGE}",format=raw,if=virtio \
  -netdev user,id=mgmt,hostfwd=tcp:127.0.0.1:10280-:80 \
  -device virtio-net-pci,netdev=mgmt,mac=52:54:00:12:3c:01 \
  -netdev tap,id=core,ifname="${TAP_CORE}",script=no,downscript=no \
  -device virtio-net-pci,netdev=core,mac=52:54:00:12:3c:02 \
  -netdev tap,id=wan,ifname="${TAP_WAN}",script=no,downscript=no \
  -device virtio-net-pci,netdev=wan,mac=52:54:00:12:3c:03 \
  -display none \
  -serial file:"${SERIAL_LOG}" \
  -daemonize \
  -pidfile "${PID_FILE}"

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
curl -fsS --user 'admin:' "${ADMIN_URL}/rest/interface" > "${EVIDENCE_DIR}/chr-interfaces.json"

VERIFIER="${ROOT}/lab/chr/verify_pbr_route_selection.py"
log "preparing isolated custom-table route without PBR rule"
python3 "${VERIFIER}" prepare \
  --admin-url "${ADMIN_URL}" \
  --workflow-sha "${WORKFLOW_SHA}" \
  --output "${EVIDENCE_DIR}/prepared.json"

log "negative control: service must be unreachable before PBR rule exists"
set +e
sudo ip netns exec "${NS_CORE}" python3 "${ROOT}/lab/chr/udp_flow_probe.py" \
  --bind 198.51.100.2 \
  --destination "${SERVICE_IP}" \
  --destination-port "${SERVICE_PORT}" \
  --source-port-start 36000 \
  --count "${FLOW_COUNT}" \
  --timeout 0.20 \
  --output "${EVIDENCE_DIR}/flow-without-pbr.json"
negative_rc=$?
set -e
if [[ "${negative_rc}" -ne 16 ]]; then
  echo "Expected no-success PBR negative probe rc=16, observed ${negative_rc}" >&2
  exit 17
fi

log "applying exact production-rendered PBR routing rule"
python3 "${VERIFIER}" apply \
  --admin-url "${ADMIN_URL}" \
  --prepared "${EVIDENCE_DIR}/prepared.json" \
  --output "${EVIDENCE_DIR}/applied.json"

log "warming selected routing-table path before measured flow"
: > "${EVIDENCE_DIR}/warmup.txt"
warm=0
for attempt in $(seq 1 5); do
  echo "attempt=${attempt}" >> "${EVIDENCE_DIR}/warmup.txt"
  if sudo ip netns exec "${NS_CORE}" ping -c 1 -W 1 "${SERVICE_IP}" >> "${EVIDENCE_DIR}/warmup.txt" 2>&1; then
    warm=1
    break
  fi
  sleep 1
done
if [[ "${warm}" -ne 1 ]]; then
  echo "PBR selected-table path did not converge during warm-up" >&2
  cat "${EVIDENCE_DIR}/warmup.txt" >&2 || true
  exit 18
fi

log "measuring source-policy selected-table packet flow"
sudo ip netns exec "${NS_CORE}" python3 "${ROOT}/lab/chr/udp_flow_probe.py" \
  --bind 198.51.100.2 \
  --destination "${SERVICE_IP}" \
  --destination-port "${SERVICE_PORT}" \
  --source-port-start 38000 \
  --count "${FLOW_COUNT}" \
  --timeout 0.40 \
  --output "${EVIDENCE_DIR}/flow-with-pbr.json"

log "evaluating PBR route selection and exact rollback"
python3 "${VERIFIER}" finalize \
  --admin-url "${ADMIN_URL}" \
  --prepared "${EVIDENCE_DIR}/prepared.json" \
  --applied "${EVIDENCE_DIR}/applied.json" \
  --negative-flow "${EVIDENCE_DIR}/flow-without-pbr.json" \
  --positive-flow "${EVIDENCE_DIR}/flow-with-pbr.json" \
  --output "${EVIDENCE_DIR}/acceptance.json"

cp "${SERVER_LOG}" "${EVIDENCE_DIR}/server.log" || true
log "PASS: source-based PBR route selection verified on disposable CHR"
