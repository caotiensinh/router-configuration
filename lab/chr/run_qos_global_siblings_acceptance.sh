#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHR_VERSION="${CHR_VERSION:-7.24.1}"
CHR_ARCHIVE="${CHR_ARCHIVE:-/tmp/chr-${CHR_VERSION}.img.zip}"
CHR_IMAGE="${CHR_IMAGE:-/tmp/chr-qos-global.img}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:9880}"
EVIDENCE_DIR="${EVIDENCE_DIR:-${ROOT}/evidence/chr-qos-global-siblings}"
FLOW_COUNT="${FLOW_COUNT:-80}"
SERVICE_IP="203.0.113.100"
SERVICE_PORT=5000
NS_WAN=rc-qg-wan; NS_CORE=rc-qg-core
BR_WAN=br-rc-qg-wan; BR_CORE=br-rc-qg-core
TAP_WAN=tap-rc-qg-wan; TAP_CORE=tap-rc-qg-core
PID_FILE=/tmp/chr-qos-global.pid
SERVER_PID=""

cleanup() {
  [[ -n "${SERVER_PID}" ]] && sudo kill "${SERVER_PID}" 2>/dev/null || true
  [[ -f "${PID_FILE}" ]] && kill "$(cat "${PID_FILE}")" 2>/dev/null || true
  sudo ip netns del "${NS_CORE}" 2>/dev/null || true
  sudo ip netns del "${NS_WAN}" 2>/dev/null || true
  sudo ip link del "${TAP_CORE}" 2>/dev/null || true
  sudo ip link del "${TAP_WAN}" 2>/dev/null || true
  sudo ip link del "${BR_CORE}" 2>/dev/null || true
  sudo ip link del "${BR_WAN}" 2>/dev/null || true
}
trap cleanup EXIT
mkdir -p "${EVIDENCE_DIR}"
cleanup
trap cleanup EXIT

if [[ ! -s "${CHR_ARCHIVE}" ]]; then
  curl -4 --http1.1 -fL --connect-timeout 15 --max-time 180 --retry 1 \
    "https://download.mikrotik.com/routeros/${CHR_VERSION}/chr-${CHR_VERSION}.img.zip" -o "${CHR_ARCHIVE}"
fi
unzip -t "${CHR_ARCHIVE}" >/dev/null
unzip -p "${CHR_ARCHIVE}" > "${CHR_IMAGE}"
sha256sum "${CHR_ARCHIVE}" > "${EVIDENCE_DIR}/chr-download.sha256"

bridge_tap() {
  sudo ip link add name "$1" type bridge; sudo ip link set "$1" up
  sudo ip tuntap add dev "$2" mode tap user "$(id -un)"; sudo ip link set "$2" master "$1"; sudo ip link set "$2" up
}
bridge_tap "${BR_WAN}" "${TAP_WAN}"
bridge_tap "${BR_CORE}" "${TAP_CORE}"
sudo ip netns add "${NS_WAN}"; sudo ip netns add "${NS_CORE}"
sudo ip link add qgw-br type veth peer name qgw-ns; sudo ip link set qgw-br master "${BR_WAN}"; sudo ip link set qgw-br up; sudo ip link set qgw-ns netns "${NS_WAN}"
sudo ip link add qgc-br type veth peer name qgc-ns; sudo ip link set qgc-br master "${BR_CORE}"; sudo ip link set qgc-br up; sudo ip link set qgc-ns netns "${NS_CORE}"
sudo ip netns exec "${NS_WAN}" ip link set lo up; sudo ip netns exec "${NS_WAN}" ip link set qgw-ns up
sudo ip netns exec "${NS_CORE}" ip link set lo up; sudo ip netns exec "${NS_CORE}" ip link set qgc-ns up
sudo ip netns exec "${NS_WAN}" ip addr add 192.0.2.1/30 dev qgw-ns
sudo ip netns exec "${NS_WAN}" ip addr add "${SERVICE_IP}/32" dev lo
sudo ip netns exec "${NS_WAN}" ip route add 10.10.10.0/24 via 192.0.2.2
sudo ip netns exec "${NS_CORE}" ip addr add 10.10.10.2/24 dev qgc-ns
sudo ip netns exec "${NS_CORE}" ip route add default via 10.10.10.1

sudo ip netns exec "${NS_WAN}" python3 "${ROOT}/lab/chr/udp_tag_server.py" --bind "${SERVICE_IP}" --port "${SERVICE_PORT}" --tag WAN > /tmp/qg-server.log 2>&1 &
SERVER_PID=$!

qemu-system-x86_64 -accel tcg,thread=multi -smp 1 -m 256 -snapshot \
  -drive file="${CHR_IMAGE}",format=raw,if=virtio \
  -netdev user,id=mgmt,hostfwd=tcp:127.0.0.1:9880-:80 -device virtio-net-pci,netdev=mgmt \
  -netdev tap,id=wan,ifname="${TAP_WAN}",script=no,downscript=no -device virtio-net-pci,netdev=wan \
  -netdev tap,id=core,ifname="${TAP_CORE}",script=no,downscript=no -device virtio-net-pci,netdev=core \
  -display none -serial file:/tmp/chr-qos-global.log -daemonize -pidfile "${PID_FILE}"

ready=0
for _ in $(seq 1 90); do
  if curl -fsS --max-time 2 --user 'admin:' "${ADMIN_URL}/rest/system/resource" > "${EVIDENCE_DIR}/chr-resource.json"; then ready=1; break; fi
  sleep 2
done
[[ "${ready}" -eq 1 ]] || exit 3

V="${ROOT}/lab/chr/verify_qos_global_siblings.py"
python3 "${V}" prepare --admin-url "${ADMIN_URL}" --output "${EVIDENCE_DIR}/prepare.json"
python3 "${V}" counters --admin-url "${ADMIN_URL}" --prepare "${EVIDENCE_DIR}/prepare.json" --output "${EVIDENCE_DIR}/before.json"

probe() {
  sudo ip netns exec "${NS_CORE}" python3 "${ROOT}/lab/chr/udp_flow_probe.py" \
    --bind 10.10.10.2 --destination "${SERVICE_IP}" --destination-port "${SERVICE_PORT}" \
    --source-port-start "$1" --count "${FLOW_COUNT}" --timeout 0.30 --dscp "$2" --output "$3"
}
probe 22000 0 "${EVIDENCE_DIR}/flow-default.json"
sleep 2
python3 "${V}" counters --admin-url "${ADMIN_URL}" --prepare "${EVIDENCE_DIR}/prepare.json" --output "${EVIDENCE_DIR}/after-default.json"
probe 24000 46 "${EVIDENCE_DIR}/flow-ef.json"
sleep 2
python3 "${V}" counters --admin-url "${ADMIN_URL}" --prepare "${EVIDENCE_DIR}/prepare.json" --output "${EVIDENCE_DIR}/after-ef.json"
python3 "${V}" evaluate --before "${EVIDENCE_DIR}/before.json" --after-default "${EVIDENCE_DIR}/after-default.json" --after-ef "${EVIDENCE_DIR}/after-ef.json" --default-flow "${EVIDENCE_DIR}/flow-default.json" --ef-flow "${EVIDENCE_DIR}/flow-ef.json" --output "${EVIDENCE_DIR}/evaluation.json"
python3 "${V}" finalize --admin-url "${ADMIN_URL}" --prepare "${EVIDENCE_DIR}/prepare.json" --evaluation "${EVIDENCE_DIR}/evaluation.json" --output "${EVIDENCE_DIR}/acceptance.json"
