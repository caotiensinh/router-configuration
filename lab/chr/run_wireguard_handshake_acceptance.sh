#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHR_VERSION="${CHR_VERSION:-7.24.1}"
CHR_ARCHIVE="${CHR_ARCHIVE:-/tmp/chr-${CHR_VERSION}.img.zip}"
WORKFLOW_SHA="${WORKFLOW_SHA:-${GITHUB_SHA:-local}}"
EVIDENCE_DIR="${EVIDENCE_DIR:-${ROOT}/evidence/chr-wireguard-handshake}"
FLOW_COUNT="${FLOW_COUNT:-30}"
ADMIN_A_URL="${ADMIN_A_URL:-http://127.0.0.1:10080}"
ADMIN_B_URL="${ADMIN_B_URL:-http://127.0.0.1:10081}"
SERVICE_PORT=5000
WG_UNDERLAY_SOCKET_PORT="${WG_UNDERLAY_SOCKET_PORT:-12020}"

BR_A_LAN=brwg-alan
BR_B_LAN=brwg-blan
TAP_A_L=tap-wg-al
TAP_B_L=tap-wg-bl
NS_A=rc-wg-host-a
NS_B=rc-wg-host-b
PID_A=/tmp/chr-wg-a.pid
PID_B=/tmp/chr-wg-b.pid
SERVER_PID=""

cleanup() {
  [[ -n "${SERVER_PID}" ]] && sudo kill "${SERVER_PID}" 2>/dev/null || true
  [[ -f "${PID_A}" ]] && kill "$(cat "${PID_A}")" 2>/dev/null || true
  [[ -f "${PID_B}" ]] && kill "$(cat "${PID_B}")" 2>/dev/null || true
  sudo ip netns del "${NS_A}" 2>/dev/null || true
  sudo ip netns del "${NS_B}" 2>/dev/null || true
  for dev in "${TAP_A_L}" "${TAP_B_L}" "${BR_A_LAN}" "${BR_B_LAN}"; do
    sudo ip link del "${dev}" 2>/dev/null || true
  done
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
unzip -p "${CHR_ARCHIVE}" > /tmp/chr-wg-a.img
cp /tmp/chr-wg-a.img /tmp/chr-wg-b.img
sha256sum "${CHR_ARCHIVE}" > "${EVIDENCE_DIR}/chr-download.sha256"

bridge_tap() {
  local bridge="$1" tap="$2"
  sudo ip link add name "${bridge}" type bridge
  sudo ip link set "${bridge}" up
  sudo ip tuntap add dev "${tap}" mode tap user "$(id -un)"
  sudo ip link set "${tap}" master "${bridge}"
  sudo ip link set "${tap}" up
}
bridge_tap "${BR_A_LAN}" "${TAP_A_L}"
bridge_tap "${BR_B_LAN}" "${TAP_B_L}"

sudo ip netns add "${NS_A}"
sudo ip netns add "${NS_B}"
sudo ip link add wga-br type veth peer name wga-ns
sudo ip link set wga-br master "${BR_A_LAN}"
sudo ip link set wga-br up
sudo ip link set wga-ns netns "${NS_A}"
sudo ip link add wgb-br type veth peer name wgb-ns
sudo ip link set wgb-br master "${BR_B_LAN}"
sudo ip link set wgb-br up
sudo ip link set wgb-ns netns "${NS_B}"

sudo ip netns exec "${NS_A}" ip link set lo up
sudo ip netns exec "${NS_A}" ip link set wga-ns up
sudo ip netns exec "${NS_A}" ip addr add 10.60.1.2/24 dev wga-ns
sudo ip netns exec "${NS_A}" ip route add 10.60.2.0/24 via 10.60.1.1
sudo ip netns exec "${NS_B}" ip link set lo up
sudo ip netns exec "${NS_B}" ip link set wgb-ns up
sudo ip netns exec "${NS_B}" ip addr add 10.60.2.2/24 dev wgb-ns
sudo ip netns exec "${NS_B}" ip route add 10.60.1.0/24 via 10.60.2.1

# The first two iterations used Linux TAPs joined by a host bridge for the
# CHR-to-CHR WireGuard underlay. Both peers transmitted keepalives but neither
# observed authenticated RX or a handshake. This acceptance topology therefore
# removes that host switching layer entirely: QEMU's point-to-point socket
# backend connects the two underlay NICs directly while the LAN test path still
# uses independent namespaces and TAP bridges.
qemu-system-x86_64 \
  -accel tcg,thread=multi -smp 1 -m 256 -snapshot \
  -drive file=/tmp/chr-wg-a.img,format=raw,if=virtio \
  -netdev user,id=mgmta,hostfwd=tcp:127.0.0.1:10080-:80 -device virtio-net-pci,netdev=mgmta \
  -netdev socket,id=ua,listen=127.0.0.1:"${WG_UNDERLAY_SOCKET_PORT}" -device virtio-net-pci,netdev=ua \
  -netdev tap,id=la,ifname="${TAP_A_L}",script=no,downscript=no -device virtio-net-pci,netdev=la \
  -display none -serial file:/tmp/chr-wg-a.log -daemonize -pidfile "${PID_A}"

qemu-system-x86_64 \
  -accel tcg,thread=multi -smp 1 -m 256 -snapshot \
  -drive file=/tmp/chr-wg-b.img,format=raw,if=virtio \
  -netdev user,id=mgmtb,hostfwd=tcp:127.0.0.1:10081-:80 -device virtio-net-pci,netdev=mgmtb \
  -netdev socket,id=ub,connect=127.0.0.1:"${WG_UNDERLAY_SOCKET_PORT}" -device virtio-net-pci,netdev=ub \
  -netdev tap,id=lb,ifname="${TAP_B_L}",script=no,downscript=no -device virtio-net-pci,netdev=lb \
  -display none -serial file:/tmp/chr-wg-b.log -daemonize -pidfile "${PID_B}"

wait_rest() {
  local url="$1" log="$2" output="$3"
  local ready=0
  for _ in $(seq 1 100); do
    if curl -fsS --max-time 2 --user 'admin:' "${url}/rest/system/resource" > "${output}"; then
      ready=1
      break
    fi
    sleep 2
  done
  if [[ "${ready}" -ne 1 ]]; then
    cat "${log}" >&2 || true
    exit 3
  fi
}
wait_rest "${ADMIN_A_URL}" /tmp/chr-wg-a.log "${EVIDENCE_DIR}/chr-a-resource.json"
wait_rest "${ADMIN_B_URL}" /tmp/chr-wg-b.log "${EVIDENCE_DIR}/chr-b-resource.json"

V="${ROOT}/lab/chr/verify_wireguard_handshake.py"
D="${ROOT}/lab/chr/diagnose_wireguard_handshake.py"
python3 "${V}" configure \
  --admin-a-url "${ADMIN_A_URL}" \
  --admin-b-url "${ADMIN_B_URL}" \
  --workflow-sha "${WORKFLOW_SHA}" \
  --output "${EVIDENCE_DIR}/configured.json"

sudo ip netns exec "${NS_B}" python3 "${ROOT}/lab/chr/udp_tag_server.py" \
  --bind 10.60.2.2 --port "${SERVICE_PORT}" --tag WG > /tmp/wg-server.log 2>&1 &
SERVER_PID=$!

# Allow the configured persistent keepalive interval to elapse once, then record
# peer state before any measured LAN traffic. This is diagnostic evidence only.
sleep 7
python3 "${D}" \
  --admin-a-url "${ADMIN_A_URL}" \
  --admin-b-url "${ADMIN_B_URL}" \
  --phase pre-flow \
  --output "${EVIDENCE_DIR}/diagnostic-pre-flow.json"

set +e
sudo ip netns exec "${NS_A}" python3 "${ROOT}/lab/chr/udp_flow_probe.py" \
  --bind 10.60.1.2 \
  --destination 10.60.2.2 \
  --destination-port "${SERVICE_PORT}" \
  --source-port-start 30000 \
  --count "${FLOW_COUNT}" \
  --timeout 0.60 \
  --output "${EVIDENCE_DIR}/flow.json"
flow_rc=$?
set -e

sleep 2
python3 "${D}" \
  --admin-a-url "${ADMIN_A_URL}" \
  --admin-b-url "${ADMIN_B_URL}" \
  --phase post-flow \
  --output "${EVIDENCE_DIR}/diagnostic-post-flow.json"

acceptance_rc=0
if [[ "${flow_rc}" -eq 0 ]]; then
  set +e
  python3 "${V}" evaluate \
    --admin-a-url "${ADMIN_A_URL}" \
    --admin-b-url "${ADMIN_B_URL}" \
    --configured "${EVIDENCE_DIR}/configured.json" \
    --flow "${EVIDENCE_DIR}/flow.json" \
    --output "${EVIDENCE_DIR}/acceptance.json"
  acceptance_rc=$?
  set -e
fi

set +e
python3 "${V}" cleanup \
  --admin-a-url "${ADMIN_A_URL}" \
  --admin-b-url "${ADMIN_B_URL}" \
  --configured "${EVIDENCE_DIR}/configured.json" \
  --output "${EVIDENCE_DIR}/cleanup.json"
cleanup_rc=$?
set -e

if [[ "${cleanup_rc}" -ne 0 ]]; then
  echo "WireGuard CHR cleanup failed with rc=${cleanup_rc}" >&2
  exit "${cleanup_rc}"
fi
if [[ "${flow_rc}" -ne 0 ]]; then
  echo "WireGuard measured LAN flow failed with rc=${flow_rc}; peer diagnostics and cleanup were preserved" >&2
  exit "${flow_rc}"
fi
if [[ "${acceptance_rc}" -ne 0 ]]; then
  echo "WireGuard acceptance evaluation failed with rc=${acceptance_rc}" >&2
  exit "${acceptance_rc}"
fi
