#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHR_VERSION="${CHR_VERSION:-7.24.1}"
CHR_ARCHIVE="${CHR_ARCHIVE:-/tmp/chr-${CHR_VERSION}.img.zip}"
CHR_IMAGE="${CHR_IMAGE:-/tmp/chr-pbr-route-selection.img}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:9980}"
WORKFLOW_SHA="${WORKFLOW_SHA:-${GITHUB_SHA:-local}}"
EVIDENCE_DIR="${EVIDENCE_DIR:-${ROOT}/evidence/chr-pbr-route-selection}"
FLOW_COUNT="${FLOW_COUNT:-50}"
SERVICE_IP="203.0.113.100"
SERVICE_PORT=5000

NS_MAIN=rc-pbr-main
NS_PBR=rc-pbr-policy
NS_CORE=rc-pbr-core
BR_MAIN=brp-main
BR_PBR=brp-policy
BR_CORE=brp-core
TAP_MAIN=tap-pbr-main
TAP_PBR=tap-pbr-policy
TAP_CORE=tap-pbr-core
PID_FILE=/tmp/chr-pbr-route-selection.pid
MAIN_SERVER_PID=""
PBR_SERVER_PID=""

cleanup() {
  [[ -n "${MAIN_SERVER_PID}" ]] && sudo kill "${MAIN_SERVER_PID}" 2>/dev/null || true
  [[ -n "${PBR_SERVER_PID}" ]] && sudo kill "${PBR_SERVER_PID}" 2>/dev/null || true
  [[ -f "${PID_FILE}" ]] && kill "$(cat "${PID_FILE}")" 2>/dev/null || true
  sudo ip netns del "${NS_CORE}" 2>/dev/null || true
  sudo ip netns del "${NS_PBR}" 2>/dev/null || true
  sudo ip netns del "${NS_MAIN}" 2>/dev/null || true
  sudo ip link del "${TAP_CORE}" 2>/dev/null || true
  sudo ip link del "${TAP_PBR}" 2>/dev/null || true
  sudo ip link del "${TAP_MAIN}" 2>/dev/null || true
  sudo ip link del "${BR_CORE}" 2>/dev/null || true
  sudo ip link del "${BR_PBR}" 2>/dev/null || true
  sudo ip link del "${BR_MAIN}" 2>/dev/null || true
}
trap cleanup EXIT
mkdir -p "${EVIDENCE_DIR}"
cleanup
trap cleanup EXIT

if [[ ! -s "${CHR_ARCHIVE}" ]]; then
  curl -4 --http1.1 -fL --connect-timeout 15 --max-time 180 --retry 1 --retry-delay 2 --retry-all-errors \
    "https://download.mikrotik.com/routeros/${CHR_VERSION}/chr-${CHR_VERSION}.img.zip" -o "${CHR_ARCHIVE}"
fi
unzip -t "${CHR_ARCHIVE}" >/dev/null
unzip -p "${CHR_ARCHIVE}" > "${CHR_IMAGE}"
sha256sum "${CHR_ARCHIVE}" > "${EVIDENCE_DIR}/chr-download.sha256"

bridge_tap() {
  sudo ip link add name "$1" type bridge
  sudo ip link set "$1" up
  sudo ip tuntap add dev "$2" mode tap user "$(id -un)"
  sudo ip link set "$2" master "$1"
  sudo ip link set "$2" up
}
bridge_tap "${BR_MAIN}" "${TAP_MAIN}"
bridge_tap "${BR_PBR}" "${TAP_PBR}"
bridge_tap "${BR_CORE}" "${TAP_CORE}"

sudo ip netns add "${NS_MAIN}"
sudo ip netns add "${NS_PBR}"
sudo ip netns add "${NS_CORE}"

sudo ip link add pbrm-br type veth peer name pbrm-ns
sudo ip link set pbrm-br master "${BR_MAIN}"
sudo ip link set pbrm-br up
sudo ip link set pbrm-ns netns "${NS_MAIN}"

sudo ip link add pbrp-br type veth peer name pbrp-ns
sudo ip link set pbrp-br master "${BR_PBR}"
sudo ip link set pbrp-br up
sudo ip link set pbrp-ns netns "${NS_PBR}"

sudo ip link add pbrc-br type veth peer name pbrc-ns
sudo ip link set pbrc-br master "${BR_CORE}"
sudo ip link set pbrc-br up
sudo ip link set pbrc-ns netns "${NS_CORE}"

for ns in "${NS_MAIN}" "${NS_PBR}" "${NS_CORE}"; do
  sudo ip netns exec "${ns}" ip link set lo up
done
sudo ip netns exec "${NS_MAIN}" ip link set pbrm-ns up
sudo ip netns exec "${NS_PBR}" ip link set pbrp-ns up
sudo ip netns exec "${NS_CORE}" ip link set pbrc-ns up

sudo ip netns exec "${NS_MAIN}" ip addr add 192.0.2.1/30 dev pbrm-ns
sudo ip netns exec "${NS_MAIN}" ip addr add "${SERVICE_IP}/32" dev lo
sudo ip netns exec "${NS_MAIN}" ip route add 10.10.10.0/24 via 192.0.2.2

sudo ip netns exec "${NS_PBR}" ip addr add 198.51.100.1/30 dev pbrp-ns
sudo ip netns exec "${NS_PBR}" ip addr add "${SERVICE_IP}/32" dev lo
sudo ip netns exec "${NS_PBR}" ip route add 10.10.10.0/24 via 198.51.100.2

sudo ip netns exec "${NS_CORE}" ip addr add 10.10.10.2/24 dev pbrc-ns
sudo ip netns exec "${NS_CORE}" ip route add "${SERVICE_IP}/32" via 10.10.10.1

sudo ip netns exec "${NS_MAIN}" python3 "${ROOT}/lab/chr/udp_tag_server.py" \
  --bind "${SERVICE_IP}" --port "${SERVICE_PORT}" --tag MAIN > /tmp/pbr-main-server.log 2>&1 &
MAIN_SERVER_PID=$!
sudo ip netns exec "${NS_PBR}" python3 "${ROOT}/lab/chr/udp_tag_server.py" \
  --bind "${SERVICE_IP}" --port "${SERVICE_PORT}" --tag PBR > /tmp/pbr-policy-server.log 2>&1 &
PBR_SERVER_PID=$!

qemu-system-x86_64 \
  -accel tcg,thread=multi \
  -smp 1 \
  -m 256 \
  -snapshot \
  -drive file="${CHR_IMAGE}",format=raw,if=virtio \
  -netdev user,id=mgmt,hostfwd=tcp:127.0.0.1:9980-:80 \
  -device virtio-net-pci,netdev=mgmt \
  -netdev tap,id=main,ifname="${TAP_MAIN}",script=no,downscript=no \
  -device virtio-net-pci,netdev=main \
  -netdev tap,id=pbr,ifname="${TAP_PBR}",script=no,downscript=no \
  -device virtio-net-pci,netdev=pbr \
  -netdev tap,id=core,ifname="${TAP_CORE}",script=no,downscript=no \
  -device virtio-net-pci,netdev=core \
  -display none \
  -serial file:/tmp/chr-pbr-route-selection.log \
  -daemonize \
  -pidfile "${PID_FILE}"

ready=0
for _ in $(seq 1 90); do
  if curl -fsS --max-time 2 --user 'admin:' "${ADMIN_URL}/rest/system/resource" > "${EVIDENCE_DIR}/chr-resource.json"; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "${ready}" -ne 1 ]]; then
  cat /tmp/chr-pbr-route-selection.log >&2 || true
  exit 3
fi

V="${ROOT}/lab/chr/verify_pbr_route_selection.py"
python3 "${V}" prepare \
  --admin-url "${ADMIN_URL}" \
  --workflow-sha "${WORKFLOW_SHA}" \
  --output "${EVIDENCE_DIR}/prepare.json"

probe() {
  local source_port="$1"
  local output="$2"
  sudo ip netns exec "${NS_CORE}" python3 "${ROOT}/lab/chr/udp_flow_probe.py" \
    --bind 10.10.10.2 \
    --destination "${SERVICE_IP}" \
    --destination-port "${SERVICE_PORT}" \
    --source-port-start "${source_port}" \
    --count "${FLOW_COUNT}" \
    --timeout 0.35 \
    --output "${output}"
}

probe 22000 "${EVIDENCE_DIR}/flow-baseline-main.json"
python3 "${V}" apply \
  --admin-url "${ADMIN_URL}" \
  --prepare "${EVIDENCE_DIR}/prepare.json" \
  --output "${EVIDENCE_DIR}/apply.json"

# Capture RouterOS FIB resolution before the policy measurement. This phase is
# intentionally diagnostic: it does not infer route selection from config
# syntax and it does not weaken the subsequent packet-flow acceptance gate.
python3 "${ROOT}/lab/chr/diagnose_pbr_fib.py" \
  --admin-url "${ADMIN_URL}" \
  --workflow-sha "${WORKFLOW_SHA}" \
  --output "${EVIDENCE_DIR}/fib-diagnostic.json"

probe 24000 "${EVIDENCE_DIR}/flow-policy-pbr.json"
python3 "${V}" rollback \
  --admin-url "${ADMIN_URL}" \
  --prepare "${EVIDENCE_DIR}/prepare.json" \
  --output "${EVIDENCE_DIR}/rollback.json"
probe 26000 "${EVIDENCE_DIR}/flow-rollback-main.json"
python3 "${V}" finalize \
  --admin-url "${ADMIN_URL}" \
  --prepare "${EVIDENCE_DIR}/prepare.json" \
  --baseline-flow "${EVIDENCE_DIR}/flow-baseline-main.json" \
  --pbr-flow "${EVIDENCE_DIR}/flow-policy-pbr.json" \
  --rollback-flow "${EVIDENCE_DIR}/flow-rollback-main.json" \
  --output "${EVIDENCE_DIR}/acceptance.json"
