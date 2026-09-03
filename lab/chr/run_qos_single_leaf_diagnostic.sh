#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHR_VERSION="${CHR_VERSION:-7.24.1}"
CHR_ARCHIVE="${CHR_ARCHIVE:-/tmp/chr-${CHR_VERSION}.img.zip}"
CHR_IMAGE="${CHR_IMAGE:-/tmp/chr-qos-single-leaf.img}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:9892}"
EVIDENCE_DIR="${EVIDENCE_DIR:-${ROOT}/evidence/chr-qos-single-leaf}"
FLOW_COUNT="${FLOW_COUNT:-80}"
FLOW_TIMEOUT="${FLOW_TIMEOUT:-0.30}"
DIAGNOSTIC_MODE="${DIAGNOSTIC_MODE:-full}"
COUNTER_SETTLE_ATTEMPTS="${COUNTER_SETTLE_ATTEMPTS:-20}"
COUNTER_SETTLE_INTERVAL="${COUNTER_SETTLE_INTERVAL:-0.25}"
SERVICE_IP="203.0.113.100"
SERVICE_PORT="5000"

NS_WAN="rc-qos-single-wan"
NS_CORE="rc-qos-single-core"
BR_WAN="brqswan"
BR_CORE="brqscore"
TAP_WAN="tapqswan"
TAP_CORE="tapqscore"
V_WAN_BR="vqs-wan-br"
V_WAN_NS="vqs-wan-ns"
V_CORE_BR="vqs-core-br"
V_CORE_NS="vqs-core-ns"
QEMU_PID_FILE="/tmp/chr-qos-single-leaf.pid"
SERIAL_LOG="/tmp/chr-qos-single-leaf-serial.log"
WAN_SERVER_LOG="/tmp/chr-qos-single-leaf-wan.log"
WAN_SERVER_PID=""

log() {
  printf '[chr-qos-single] %s\n' "$*"
}

cleanup_host() {
  if [[ -n "${WAN_SERVER_PID}" ]]; then sudo kill "${WAN_SERVER_PID}" 2>/dev/null || true; fi
  if [[ -f "${QEMU_PID_FILE}" ]]; then kill "$(cat "${QEMU_PID_FILE}")" 2>/dev/null || true; fi
  for ns in "${NS_CORE}" "${NS_WAN}"; do sudo ip netns del "${ns}" 2>/dev/null || true; done
  for tap in "${TAP_CORE}" "${TAP_WAN}"; do sudo ip link del "${tap}" 2>/dev/null || true; done
  for br in "${BR_CORE}" "${BR_WAN}"; do sudo ip link del "${br}" 2>/dev/null || true; done
}
trap cleanup_host EXIT

for command in python3 qemu-system-x86_64 unzip ip curl sudo; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "missing required command: ${command}" >&2
    exit 2
  }
done

mkdir -p "${EVIDENCE_DIR}"
rm -f "${QEMU_PID_FILE}" "${SERIAL_LOG}" "${WAN_SERVER_LOG}"
cleanup_host
trap cleanup_host EXIT

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

wait_for_counter_visibility() {
  local install_file="$1"
  local before_file="$2"
  local after_file="$3"
  local settle_file="$4"
  local attempt=0
  local visible=0

  while (( attempt < COUNTER_SETTLE_ATTEMPTS )); do
    attempt=$((attempt + 1))
    python3 "${DIAG}" counters \
      --admin-url "${ADMIN_URL}" \
      --install "${install_file}" \
      --output "${after_file}"
    if python3 - "${before_file}" "${after_file}" <<'PY'
import json, sys
before = json.load(open(sys.argv[1], encoding='utf-8'))
after = json.load(open(sys.argv[2], encoding='utf-8'))
mangle_delta = int(after['mangle_packets']) - int(before['mangle_packets'])
leaf_delta = int(after['leaf_packets']) - int(before['leaf_packets'])
mangle_required = bool(before.get('mangle_counter_required', True))
visible = leaf_delta > 0 and (not mangle_required or mangle_delta > 0)
raise SystemExit(0 if visible else 1)
PY
    then
      visible=1
      break
    fi
    sleep "${COUNTER_SETTLE_INTERVAL}"
  done

  python3 - \
    "${before_file}" "${after_file}" "${settle_file}" \
    "${attempt}" "${COUNTER_SETTLE_ATTEMPTS}" "${COUNTER_SETTLE_INTERVAL}" "${visible}" <<'PY'
import json, sys
from pathlib import Path
before = json.load(open(sys.argv[1], encoding='utf-8'))
after = json.load(open(sys.argv[2], encoding='utf-8'))
attempt = int(sys.argv[4])
max_attempts = int(sys.argv[5])
interval = float(sys.argv[6])
visible = sys.argv[7] == '1'
payload = {
    'ok': True,
    'counter_visibility_observed': visible,
    'attempts_used': attempt,
    'max_attempts': max_attempts,
    'interval_seconds': interval,
    'bounded_window_seconds': max_attempts * interval,
    'mangle_counter_required': bool(before.get('mangle_counter_required', True)),
    'mangle_packet_delta': int(after['mangle_packets']) - int(before['mangle_packets']),
    'leaf_packet_delta': int(after['leaf_packets']) - int(before['leaf_packets']),
    'acceptance_relaxed': False,
    'counter_source': 'queue_tree_print_stats',
}
Path(sys.argv[3]).write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')
print(json.dumps(payload, indent=2, sort_keys=True))
PY
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
  -accel tcg,thread=multi \
  -smp 1 \
  -m 256 \
  -snapshot \
  -drive file="${CHR_IMAGE}",format=raw,if=virtio \
  -netdev user,id=mgmt,hostfwd=tcp:127.0.0.1:9892-:80 \
  -device virtio-net-pci,netdev=mgmt,mac=52:54:00:12:81:01 \
  -netdev tap,id=wan,ifname="${TAP_WAN}",script=no,downscript=no \
  -device virtio-net-pci,netdev=wan,mac=52:54:00:12:81:02 \
  -netdev tap,id=core,ifname="${TAP_CORE}",script=no,downscript=no \
  -device virtio-net-pci,netdev=core,mac=52:54:00:12:81:03 \
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
import json, sys
rows = json.load(open(sys.argv[1], encoding='utf-8'))
names = {str(row.get('name')) for row in rows if isinstance(row, dict)}
missing = sorted({'ether1', 'ether2', 'ether3'} - names)
if missing:
    raise SystemExit(f'missing CHR single-leaf interfaces: {missing}')
print(json.dumps({'ok': True, 'interfaces': sorted(names)}))
PY

PREPARE="${ROOT}/lab/chr/verify_qos_packet_flow_v2.py"
DIAG="${DIAG_OVERRIDE:-${ROOT}/lab/chr/diagnose_qos_single_leaf.py}"

log "preparing lab routing plus production renderer facts"
python3 "${PREPARE}" prepare \
  --admin-url "${ADMIN_URL}" \
  --output "${EVIDENCE_DIR}/prepare.json"

run_phase() {
  local mode="$1"
  local queue="$2"
  local slug="$3"
  local dscp="$4"
  local source_port="$5"

  log "testing mode=${mode} queue=${queue} with exactly one global leaf"
  python3 "${DIAG}" install \
    --admin-url "${ADMIN_URL}" \
    --prepare "${EVIDENCE_DIR}/prepare.json" \
    --mode "${mode}" \
    --queue "${queue}" \
    --output "${EVIDENCE_DIR}/${slug}-install.json"
  python3 "${DIAG}" counters \
    --admin-url "${ADMIN_URL}" \
    --install "${EVIDENCE_DIR}/${slug}-install.json" \
    --output "${EVIDENCE_DIR}/${slug}-before.json"
  send_probe "${dscp}" "${source_port}" "${EVIDENCE_DIR}/${slug}-flow.json"
  wait_for_counter_visibility \
    "${EVIDENCE_DIR}/${slug}-install.json" \
    "${EVIDENCE_DIR}/${slug}-before.json" \
    "${EVIDENCE_DIR}/${slug}-after.json" \
    "${EVIDENCE_DIR}/${slug}-counter-settle.json"
  python3 "${DIAG}" evaluate \
    --mode "${mode}" \
    --before "${EVIDENCE_DIR}/${slug}-before.json" \
    --after "${EVIDENCE_DIR}/${slug}-after.json" \
    --flow "${EVIDENCE_DIR}/${slug}-flow.json" \
    --output "${EVIDENCE_DIR}/${slug}-acceptance.json"
  python3 "${DIAG}" cleanup \
    --admin-url "${ADMIN_URL}" \
    --output "${EVIDENCE_DIR}/${slug}-cleanup.json"
}

if [[ "${DIAGNOSTIC_MODE}" == "prerouting-default-only" ]]; then
  run_phase default default-small prerouting-default-small 0 42000
  python3 - \
    "${EVIDENCE_DIR}/prerouting-default-small-acceptance.json" \
    "${EVIDENCE_DIR}/summary.json" <<'PY'
import json, sys
from pathlib import Path
result = json.load(open(sys.argv[1], encoding='utf-8'))
if result.get('acceptance') != 'PASS' or result.get('diagnostic_packet_flow_acceptance') is not True:
    raise SystemExit('prerouting default-only single-leaf diagnostic did not pass')
summary = {
    'ok': True,
    'acceptance': 'PASS',
    'scope': 'prerouting_default_only_single_global_leaf_timing_probe',
    'default_small_pass': True,
    'mark_chain': 'prerouting',
    'ingress_interface': 'ether3',
    'counter_visibility_bounded': True,
    'production_renderer_modified': False,
    'production_packet_flow_acceptance': False,
    'aggregate_shaping_claimed': False,
    'latency_performance_claimed': False,
    'bandwidth_guarantee_claimed': False,
    'production_writer_available': False,
    'physical_router_targeted': False,
}
Path(sys.argv[2]).write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
print(json.dumps(summary, indent=2, sort_keys=True))
PY
  log "PASS: prerouting default mark traversed one isolated global leaf"
  exit 0
fi

if [[ "${DIAGNOSTIC_MODE}" == "production-global" ]]; then
  run_phase no-mark default-small no-mark-default-small 0 42000
  run_phase ef default-small ef-default-small 46 44000
  run_phase no-mark routercfg-qos-fq no-mark-fq-codel 0 46000
  run_phase ef routercfg-qos-fq ef-fq-codel 46 48000

  python3 - \
    "${EVIDENCE_DIR}/no-mark-default-small-acceptance.json" \
    "${EVIDENCE_DIR}/ef-default-small-acceptance.json" \
    "${EVIDENCE_DIR}/no-mark-fq-codel-acceptance.json" \
    "${EVIDENCE_DIR}/ef-fq-codel-acceptance.json" \
    "${EVIDENCE_DIR}/summary.json" <<'PY'
import json, sys
from pathlib import Path
labels = (
    'no_mark_default_small',
    'ef_default_small',
    'no_mark_fq_codel',
    'ef_fq_codel',
)
results = [json.load(open(path, encoding='utf-8')) for path in sys.argv[1:5]]
for label, result in zip(labels, results):
    if result.get('acceptance') != 'PASS' or result.get('diagnostic_packet_flow_acceptance') is not True:
        raise SystemExit(f'{label} production-global single-leaf diagnostic did not pass')
no_mark_results = (results[0], results[2])
if any(result.get('mangle_counter_required') is not False for result in no_mark_results):
    raise SystemExit('no-mark diagnostic unexpectedly required a default mangle counter')
summary = {
    'ok': True,
    'acceptance': 'PASS',
    'scope': 'production_ef_classifier_and_unmarked_default_to_global_leaf_diagnostic',
    'phases': {label: True for label in labels},
    'default_small_pass': True,
    'fq_codel_pass': True,
    'no_mark_default_to_leaf_pass': True,
    'production_ef_mark_to_leaf_pass': True,
    'default_mangle_required': False,
    'queue_parent': 'global',
    'counter_visibility_bounded': True,
    'production_renderer_modified': False,
    'production_packet_flow_acceptance': False,
    'aggregate_shaping_claimed': False,
    'latency_performance_claimed': False,
    'bandwidth_guarantee_claimed': False,
    'production_writer_available': False,
    'physical_router_targeted': False,
}
Path(sys.argv[5]).write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
print(json.dumps(summary, indent=2, sort_keys=True))
PY

  log "PASS: unmarked default and production EF classifier each traverse one global leaf"
  exit 0
fi

if [[ "${DIAGNOSTIC_MODE}" != "full" ]]; then
  echo "unsupported DIAGNOSTIC_MODE=${DIAGNOSTIC_MODE}" >&2
  exit 4
fi

run_phase default default-small default-default-small 0 42000
run_phase ef default-small ef-default-small 46 44000
run_phase default routercfg-qos-fq default-fq-codel 0 46000
run_phase ef routercfg-qos-fq ef-fq-codel 46 48000

python3 - \
  "${EVIDENCE_DIR}/default-default-small-acceptance.json" \
  "${EVIDENCE_DIR}/ef-default-small-acceptance.json" \
  "${EVIDENCE_DIR}/default-fq-codel-acceptance.json" \
  "${EVIDENCE_DIR}/ef-fq-codel-acceptance.json" \
  "${EVIDENCE_DIR}/summary.json" <<'PY'
import json, sys
from pathlib import Path
labels = (
    'default_default_small',
    'ef_default_small',
    'default_fq_codel',
    'ef_fq_codel',
)
results = [json.load(open(path, encoding='utf-8')) for path in sys.argv[1:5]]
for label, result in zip(labels, results):
    if result.get('acceptance') != 'PASS' or result.get('diagnostic_packet_flow_acceptance') is not True:
        raise SystemExit(f'{label} single-leaf diagnostic did not pass')
summary = {
    'ok': True,
    'acceptance': 'PASS',
    'scope': 'isolated_single_mark_to_single_global_leaf_diagnostic',
    'phases': {label: True for label in labels},
    'default_small_pass': True,
    'fq_codel_pass': True,
    'default_mark_to_leaf_pass': True,
    'ef_mark_to_leaf_pass': True,
    'counter_visibility_bounded': True,
    'production_renderer_modified': False,
    'production_packet_flow_acceptance': False,
    'aggregate_shaping_claimed': False,
    'latency_performance_claimed': False,
    'bandwidth_guarantee_claimed': False,
    'production_writer_available': False,
    'physical_router_targeted': False,
}
Path(sys.argv[5]).write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
print(json.dumps(summary, indent=2, sort_keys=True))
PY

log "PASS: default and EF marks each traverse one isolated global leaf on default-small and FQ-CoDel"
