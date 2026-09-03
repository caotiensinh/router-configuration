#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHR_VERSION="${CHR_VERSION:-7.24.1}"
CHR_ARCHIVE="${CHR_ARCHIVE:-/tmp/chr-${CHR_VERSION}.img.zip}"
CHR_IMAGE="${CHR_IMAGE:-/tmp/chr-wg-handshake.img}"
WORKFLOW_SHA="${WORKFLOW_SHA:-${GITHUB_SHA:-local}}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:10380}"
EVIDENCE_DIR="${EVIDENCE_DIR:-${ROOT}/evidence/chr-wireguard-handshake}"

BR_UNDERLAY="br-wg-underlay"
TAP_UNDERLAY="tap-wg-underlay"
NS_PEER="rc-wg-peer"
V_PEER_BR="vwg-br"
V_PEER_NS="vwg-ns"
WG_IF="wg0"
PID_FILE="/tmp/chr-wg-handshake.pid"
SERIAL_LOG="/tmp/chr-wg-handshake-serial.log"
LINUX_PRIVATE_KEY=""

log() {
  printf '[chr-wg-flow] %s\n' "$*"
}

cleanup() {
  LINUX_PRIVATE_KEY=""
  if [[ -f "${PID_FILE}" ]]; then kill "$(cat "${PID_FILE}")" 2>/dev/null || true; fi
  sudo ip netns del "${NS_PEER}" 2>/dev/null || true
  for dev in "${TAP_UNDERLAY}" "${BR_UNDERLAY}"; do sudo ip link del "${dev}" 2>/dev/null || true; done
  rm -f /tmp/wg-latest.txt /tmp/wg-transfer.txt
}
trap cleanup EXIT

for command in python3 qemu-system-x86_64 unzip ip curl sudo wg ping; do
  command -v "${command}" >/dev/null 2>&1 || { echo "missing required command: ${command}" >&2; exit 2; }
done

mkdir -p "${EVIDENCE_DIR}"
rm -f "${PID_FILE}" "${SERIAL_LOG}" /tmp/wg-latest.txt /tmp/wg-transfer.txt
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

log "creating isolated Linux WireGuard underlay"
sudo ip link add name "${BR_UNDERLAY}" type bridge
sudo ip link set "${BR_UNDERLAY}" up
sudo ip tuntap add dev "${TAP_UNDERLAY}" mode tap user "$(id -un)"
sudo ip link set "${TAP_UNDERLAY}" master "${BR_UNDERLAY}"
sudo ip link set "${TAP_UNDERLAY}" up
sudo ip netns add "${NS_PEER}"
sudo ip link add "${V_PEER_BR}" type veth peer name "${V_PEER_NS}"
sudo ip link set "${V_PEER_BR}" master "${BR_UNDERLAY}"
sudo ip link set "${V_PEER_BR}" up
sudo ip link set "${V_PEER_NS}" netns "${NS_PEER}"
sudo ip netns exec "${NS_PEER}" ip link set lo up
sudo ip netns exec "${NS_PEER}" ip link set "${V_PEER_NS}" up
sudo ip netns exec "${NS_PEER}" ip addr add 192.0.2.1/30 dev "${V_PEER_NS}"

log "creating Linux WireGuard interface with ephemeral private key"
LINUX_PRIVATE_KEY="$(wg genkey)"
LINUX_PUBLIC_KEY="$(printf '%s\n' "${LINUX_PRIVATE_KEY}" | wg pubkey)"
sudo ip netns exec "${NS_PEER}" ip link add "${WG_IF}" type wireguard
printf '%s\n' "${LINUX_PRIVATE_KEY}" | sudo ip netns exec "${NS_PEER}" wg set "${WG_IF}" private-key /dev/stdin
LINUX_PRIVATE_KEY=""
sudo ip netns exec "${NS_PEER}" ip addr add 10.252.0.2/24 dev "${WG_IF}"
sudo ip netns exec "${NS_PEER}" ip link set "${WG_IF}" up

log "booting two-interface disposable CHR"
qemu-system-x86_64 \
  -accel tcg,thread=multi \
  -smp 1 \
  -m 256 \
  -snapshot \
  -drive file="${CHR_IMAGE}",format=raw,if=virtio \
  -netdev user,id=mgmt,hostfwd=tcp:127.0.0.1:10380-:80 \
  -device virtio-net-pci,netdev=mgmt,mac=52:54:00:12:3d:01 \
  -netdev tap,id=underlay,ifname="${TAP_UNDERLAY}",script=no,downscript=no \
  -device virtio-net-pci,netdev=underlay,mac=52:54:00:12:3d:02 \
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

VERIFIER="${ROOT}/lab/chr/verify_wireguard_handshake.py"
log "applying production WireGuard templates with lab-only ephemeral secret binding"
python3 "${VERIFIER}" prepare \
  --admin-url "${ADMIN_URL}" \
  --workflow-sha "${WORKFLOW_SHA}" \
  --remote-public-key "${LINUX_PUBLIC_KEY}" \
  --output "${EVIDENCE_DIR}/prepared.json"

log "negative control: tunnel address must be unreachable before Linux peer activation"
set +e
sudo ip netns exec "${NS_PEER}" python3 "${ROOT}/lab/chr/icmp_probe.py" \
  --destination 10.252.0.1 \
  --count 5 \
  --timeout 1 \
  --output "${EVIDENCE_DIR}/negative-probe.json"
negative_rc=$?
set -e
if [[ "${negative_rc}" -ne 16 ]]; then
  echo "Expected zero-receive WireGuard negative probe rc=16, observed ${negative_rc}" >&2
  exit 17
fi

CHR_PUBLIC_KEY="$(python3 - "${EVIDENCE_DIR}/prepared.json" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], encoding='utf-8'))
print(payload['chr_public_key'])
PY
)"
if [[ -z "${CHR_PUBLIC_KEY}" ]]; then
  echo "Prepared WireGuard evidence did not expose CHR public key" >&2
  exit 18
fi

log "activating Linux peer toward CHR responder"
sudo ip netns exec "${NS_PEER}" wg set "${WG_IF}" \
  peer "${CHR_PUBLIC_KEY}" \
  endpoint 192.0.2.2:51820 \
  allowed-ips 10.252.0.1/32 \
  persistent-keepalive 1
CHR_PUBLIC_KEY=""
LINUX_PUBLIC_KEY=""

log "warming handshake outside measured acceptance window"
warm=0
for attempt in $(seq 1 8); do
  if sudo ip netns exec "${NS_PEER}" ping -n -c 1 -W 1 10.252.0.1 >/dev/null 2>&1; then
    warm=1
    break
  fi
  sleep 1
done
if [[ "${warm}" -ne 1 ]]; then
  echo "WireGuard handshake did not converge during warm-up" >&2
  exit 19
fi

log "measuring encrypted ICMP transfer over WireGuard"
sudo ip netns exec "${NS_PEER}" python3 "${ROOT}/lab/chr/icmp_probe.py" \
  --destination 10.252.0.1 \
  --count 20 \
  --timeout 1 \
  --output "${EVIDENCE_DIR}/positive-probe.json"

sudo ip netns exec "${NS_PEER}" wg show "${WG_IF}" latest-handshakes > /tmp/wg-latest.txt
sudo ip netns exec "${NS_PEER}" wg show "${WG_IF}" transfer > /tmp/wg-transfer.txt
python3 - /tmp/wg-latest.txt /tmp/wg-transfer.txt "${EVIDENCE_DIR}/linux-wg-stats.json" <<'PY'
import json
import sys
from pathlib import Path

latest = Path(sys.argv[1]).read_text(encoding='utf-8').strip().splitlines()
transfer = Path(sys.argv[2]).read_text(encoding='utf-8').strip().splitlines()
if len(latest) != 1 or len(transfer) != 1:
    raise SystemExit('expected exactly one Linux WireGuard peer')
latest_parts = latest[0].split('\t')
transfer_parts = transfer[0].split('\t')
if len(latest_parts) != 2 or len(transfer_parts) != 3:
    raise SystemExit('unexpected wg show machine-readable output')
payload = {
    'latest_handshake_epoch': int(latest_parts[1]),
    'rx_bytes': int(transfer_parts[1]),
    'tx_bytes': int(transfer_parts[2]),
    'peer_public_key_recorded': False,
    'private_key_recorded': False,
}
Path(sys.argv[3]).write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')
print(json.dumps(payload, indent=2, sort_keys=True))
PY
rm -f /tmp/wg-latest.txt /tmp/wg-transfer.txt

log "evaluating handshake counters, encrypted transfer and exact rollback"
python3 "${VERIFIER}" finalize \
  --admin-url "${ADMIN_URL}" \
  --prepared "${EVIDENCE_DIR}/prepared.json" \
  --negative-probe "${EVIDENCE_DIR}/negative-probe.json" \
  --positive-probe "${EVIDENCE_DIR}/positive-probe.json" \
  --linux-stats "${EVIDENCE_DIR}/linux-wg-stats.json" \
  --output "${EVIDENCE_DIR}/acceptance.json"

rm -f "${EVIDENCE_DIR}/prepared.json"
log "PASS: WireGuard handshake and encrypted packet transfer verified"
