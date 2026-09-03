#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHR_VERSION="${CHR_VERSION:-7.24.1}"
CHR_ARCHIVE="${CHR_ARCHIVE:-/tmp/chr-${CHR_VERSION}.img.zip}"
WORKFLOW_SHA="${WORKFLOW_SHA:-${GITHUB_SHA:-local}}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:10180}"
EVIDENCE_DIR="${EVIDENCE_DIR:-${ROOT}/evidence/chr-vlan-data-plane}"
FLOW_COUNT="${FLOW_COUNT:-30}"
SERVICE_PORT=5000
BR_TRUNK=brvl-trunk
BR_ACCESS=brvl-access
TAP_TRUNK=tap-vl-trunk
TAP_ACCESS=tap-vl-access
NS_TRUNK=rc-vlan-trunk
NS_ACCESS=rc-vlan-access
PID_FILE=/tmp/chr-vlan-dp.pid
SERVER_PID=""
cleanup() {
  [[ -n "${SERVER_PID}" ]] && sudo kill "${SERVER_PID}" 2>/dev/null || true
  [[ -f "${PID_FILE}" ]] && kill "$(cat "${PID_FILE}")" 2>/dev/null || true
  sudo ip netns del "${NS_TRUNK}" 2>/dev/null || true
  sudo ip netns del "${NS_ACCESS}" 2>/dev/null || true
  for dev in "${TAP_TRUNK}" "${TAP_ACCESS}" "${BR_TRUNK}" "${BR_ACCESS}"; do sudo ip link del "${dev}" 2>/dev/null || true; done
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
unzip -p "${CHR_ARCHIVE}" > /tmp/chr-vlan-dp.img
sha256sum "${CHR_ARCHIVE}" > "${EVIDENCE_DIR}/chr-download.sha256"
bridge_tap() {
  sudo ip link add name "$1" type bridge
  sudo ip link set "$1" up
  sudo ip tuntap add dev "$2" mode tap user "$(id -un)"
  sudo ip link set "$2" master "$1"
  sudo ip link set "$2" up
}
bridge_tap "${BR_TRUNK}" "${TAP_TRUNK}"
bridge_tap "${BR_ACCESS}" "${TAP_ACCESS}"
sudo ip netns add "${NS_TRUNK}"
sudo ip netns add "${NS_ACCESS}"
sudo ip link add vlt-br type veth peer name vlt-ns
sudo ip link set vlt-br master "${BR_TRUNK}"
sudo ip link set vlt-br up
sudo ip link set vlt-ns netns "${NS_TRUNK}"
sudo ip link add vla-br type veth peer name vla-ns
sudo ip link set vla-br master "${BR_ACCESS}"
sudo ip link set vla-br up
sudo ip link set vla-ns netns "${NS_ACCESS}"
sudo ip netns exec "${NS_TRUNK}" ip link set lo up
sudo ip netns exec "${NS_TRUNK}" ip link set vlt-ns up
sudo ip netns exec "${NS_TRUNK}" ip link add link vlt-ns name vlt20 type vlan id 20
sudo ip netns exec "${NS_TRUNK}" ip link set vlt20 up
sudo ip netns exec "${NS_TRUNK}" ip addr add 10.20.0.2/24 dev vlt20
sudo ip netns exec "${NS_ACCESS}" ip link set lo up
sudo ip netns exec "${NS_ACCESS}" ip link set vla-ns up
sudo ip netns exec "${NS_ACCESS}" ip addr add 10.20.0.3/24 dev vla-ns
sudo ip netns exec "${NS_ACCESS}" python3 "${ROOT}/lab/chr/udp_tag_server.py" --bind 10.20.0.3 --port "${SERVICE_PORT}" --tag VLAN20 > /tmp/vlan-server.log 2>&1 &
SERVER_PID=$!
qemu-system-x86_64 -accel tcg,thread=multi -smp 1 -m 256 -snapshot \
  -drive file=/tmp/chr-vlan-dp.img,format=raw,if=virtio \
  -netdev user,id=mgmt,hostfwd=tcp:127.0.0.1:10180-:80 -device virtio-net-pci,netdev=mgmt \
  -netdev tap,id=trunk,ifname="${TAP_TRUNK}",script=no,downscript=no -device virtio-net-pci,netdev=trunk \
  -netdev tap,id=access,ifname="${TAP_ACCESS}",script=no,downscript=no -device virtio-net-pci,netdev=access \
  -display none -serial file:/tmp/chr-vlan-dp.log -daemonize -pidfile "${PID_FILE}"
ready=0
for _ in $(seq 1 90); do
  if curl -fsS --max-time 2 --user 'admin:' "${ADMIN_URL}/rest/system/resource" > "${EVIDENCE_DIR}/chr-resource.json"; then ready=1; break; fi
  sleep 2
done
[[ "${ready}" -eq 1 ]] || { cat /tmp/chr-vlan-dp.log >&2 || true; exit 3; }
V="${ROOT}/lab/chr/verify_vlan_data_plane.py"
python3 "${V}" prepare --admin-url "${ADMIN_URL}" --workflow-sha "${WORKFLOW_SHA}" --output "${EVIDENCE_DIR}/prepared.json"
sleep 1
sudo ip netns exec "${NS_TRUNK}" python3 "${ROOT}/lab/chr/udp_flow_probe.py" \
  --bind 10.20.0.2 --destination 10.20.0.3 --destination-port "${SERVICE_PORT}" \
  --source-port-start 32000 --count "${FLOW_COUNT}" --timeout 0.40 --output "${EVIDENCE_DIR}/flow-tagged.json"
sudo ip netns exec "${NS_TRUNK}" ip addr del 10.20.0.2/24 dev vlt20
sudo ip netns exec "${NS_TRUNK}" ip link del vlt20
sudo ip netns exec "${NS_TRUNK}" ip addr add 10.20.0.2/24 dev vlt-ns
sudo ip netns exec "${NS_TRUNK}" ip neigh flush all || true
set +e
sudo ip netns exec "${NS_TRUNK}" python3 "${ROOT}/lab/chr/udp_flow_probe.py" \
  --bind 10.20.0.2 --destination 10.20.0.3 --destination-port "${SERVICE_PORT}" \
  --source-port-start 34000 --count "${FLOW_COUNT}" --timeout 0.20 --output "${EVIDENCE_DIR}/flow-untagged-negative.json"
negative_rc=$?
set -e
if [[ "${negative_rc}" -ne 16 ]]; then
  echo "Expected zero-success negative probe rc=16, observed ${negative_rc}" >&2
  exit 17
fi
python3 "${V}" finalize --admin-url "${ADMIN_URL}" --prepared "${EVIDENCE_DIR}/prepared.json" \
  --tagged-flow "${EVIDENCE_DIR}/flow-tagged.json" --untagged-flow "${EVIDENCE_DIR}/flow-untagged-negative.json" \
  --output "${EVIDENCE_DIR}/acceptance.json"
