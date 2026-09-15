#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE="${ROOT}/lab/chr/run_packet_flow_acceptance.sh"
PATCHED="${ROOT}/lab/chr/.generated-dns-failure-acceptance.sh"

cleanup_wrapper() {
  rm -f "${PATCHED}"
}
trap cleanup_wrapper EXIT

python3 - "${SOURCE}" "${PATCHED}" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
target = Path(sys.argv[2])
text = source.read_text(encoding="utf-8")

variables_marker = 'SERVICE_PORT="5000"\n'
variables = r'''DNS_IP="203.0.113.53"
DNS_PORT="53"
DNS_NAME="routercfg.test"
WAN10_DNS_ANSWER="192.0.2.53"
WAN1_DNS_ANSWER="198.51.100.53"
'''
if text.count(variables_marker) != 1:
    raise SystemExit("expected exactly one service-port marker")
text = text.replace(variables_marker, variables_marker + variables, 1)

pid_marker = 'WAN1_SERVER_PID=""\n'
pids = r'''WAN10_DNS_PID=""
WAN1_DNS_PID=""
WAN10_DNS_LOG="/tmp/chr-dns-failure-wan10.log"
WAN1_DNS_LOG="/tmp/chr-dns-failure-wan1.log"
'''
if text.count(pid_marker) != 1:
    raise SystemExit("expected exactly one WAN1 server PID marker")
text = text.replace(pid_marker, pid_marker + pids, 1)

cleanup_marker = 'cleanup() {\n'
cleanup_dns = r'''  if [[ -n "${WAN10_DNS_PID}" ]]; then sudo kill "${WAN10_DNS_PID}" 2>/dev/null || true; fi
  if [[ -n "${WAN1_DNS_PID}" ]]; then sudo kill "${WAN1_DNS_PID}" 2>/dev/null || true; fi
'''
if text.count(cleanup_marker) != 1:
    raise SystemExit("expected exactly one cleanup function")
text = text.replace(cleanup_marker, cleanup_marker + cleanup_dns, 1)

rm_marker = 'rm -f "${QEMU_PID_FILE}" "${SERIAL_LOG}" "${WAN10_SERVER_LOG}" "${WAN1_SERVER_LOG}"\n'
if text.count(rm_marker) != 1:
    raise SystemExit("expected exactly one log cleanup marker")
text = text.replace(
    rm_marker,
    rm_marker + 'rm -f "${WAN10_DNS_LOG}" "${WAN1_DNS_LOG}"\n',
    1,
)

wan10_service = 'sudo ip netns exec "${NS_WAN10}" ip addr add "${SERVICE_IP}/32" dev lo\n'
wan1_service = 'sudo ip netns exec "${NS_WAN1}" ip addr add "${SERVICE_IP}/32" dev lo\n'
if text.count(wan10_service) != 1 or text.count(wan1_service) != 1:
    raise SystemExit("expected exactly one service loopback per WAN namespace")
text = text.replace(
    wan10_service,
    wan10_service + 'sudo ip netns exec "${NS_WAN10}" ip addr add "${DNS_IP}/32" dev lo\n',
    1,
)
text = text.replace(
    wan1_service,
    wan1_service + 'sudo ip netns exec "${NS_WAN1}" ip addr add "${DNS_IP}/32" dev lo\n',
    1,
)

start_marker = 'WAN1_SERVER_PID=$!\nsleep 0.5\n'
dns_start = r'''WAN1_SERVER_PID=$!

log "starting deterministic DNS responders"
sudo ip netns exec "${NS_WAN10}" python3 "${ROOT}/lab/chr/dns_probe.py" serve \
  --bind "${DNS_IP}" --port "${DNS_PORT}" --name "${DNS_NAME}" --answer-ip "${WAN10_DNS_ANSWER}" \
  >"${WAN10_DNS_LOG}" 2>&1 &
WAN10_DNS_PID=$!
sudo ip netns exec "${NS_WAN1}" python3 "${ROOT}/lab/chr/dns_probe.py" serve \
  --bind "${DNS_IP}" --port "${DNS_PORT}" --name "${DNS_NAME}" --answer-ip "${WAN1_DNS_ANSWER}" \
  >"${WAN1_DNS_LOG}" 2>&1 &
WAN1_DNS_PID=$!
sleep 0.5
'''
if text.count(start_marker) != 1:
    raise SystemExit("expected exactly one tagged-responder start marker")
text = text.replace(start_marker, dns_start, 1)

old_verifier = 'verify_packet_flow_behavior.py'
if text.count(old_verifier) != 5:
    raise SystemExit(
        f"expected exactly five packet-flow verifier call sites, found {text.count(old_verifier)}"
    )
text = text.replace(old_verifier, 'verify_link_up_recursive_failover.py')

pcc_start = 'log "diagnosing RouterOS runtime validity of PCC and routing-mark rules"\n'
pcc_end = 'python3 "${ROOT}/lab/chr/verify_link_up_recursive_failover.py" wait-routes \\\n'
start = text.find(pcc_start)
end = text.find(pcc_end, start + len(pcc_start)) if start >= 0 else -1
if start < 0 or end < 0:
    raise SystemExit("could not isolate PCC-only diagnostic block")
text = text[:start] + text[end:]
text = text.replace(
    'log "rendering and applying 17 recursive + 21 PCC commands"',
    'log "rendering and applying 17 recursive routing commands for DNS service-failure acceptance"',
    1,
)

phase_start = 'log "measuring normal 10:1 PCC distribution"\n'
final_line = 'log "PASS: real CHR PCC distribution, failover and failback behavior verified"\n'
start = text.find(phase_start)
end = text.find(final_line, start + len(phase_start)) if start >= 0 else -1
if start < 0 or end < 0:
    raise SystemExit("could not isolate original packet-flow phase block")
end += len(final_line)

phase_block = r'''log "measuring normal DNS and non-DNS connectivity on preferred WAN10"
probe_phase 50000 "${EVIDENCE_DIR}/connectivity-normal.json"
sudo ip netns exec "${NS_CORE}" python3 "${ROOT}/lab/chr/dns_probe.py" probe \
  --bind 10.10.10.2 --server "${DNS_IP}" --port "${DNS_PORT}" \
  --name "${DNS_NAME}" --expected-ip "${WAN10_DNS_ANSWER}" \
  --timeout 0.6 --expect success --output "${EVIDENCE_DIR}/dns-normal.json"

log "stopping only the WAN10 DNS responder while WAN10 routing and link remain healthy"
sudo kill "${WAN10_DNS_PID}"
wait "${WAN10_DNS_PID}" 2>/dev/null || true
WAN10_DNS_PID=""
dns_stopped=0
for _attempt in $(seq 1 20); do
  if ! sudo ip netns exec "${NS_WAN10}" ss -H -lun | grep -Eq '(:|])53[[:space:]]'; then
    dns_stopped=1
    break
  fi
  sleep 0.05
done
sudo ip netns exec "${NS_WAN10}" ss -H -lunp > "${EVIDENCE_DIR}/dns-wan10-stopped-sockets.txt" || true
if [[ "${dns_stopped}" -ne 1 ]]; then
  echo "WAN10 DNS responder socket remained open after targeted service stop" >&2
  exit 24
fi
curl -fsS --user 'admin:' "${ADMIN_URL}/rest/interface" > "${EVIDENCE_DIR}/dns-failure-routeros-interfaces.json"
python3 "${ROOT}/lab/chr/verify_link_up_recursive_failover.py" wait-routes \
  --admin-url "${ADMIN_URL}" --expected normal --timeout-seconds 15 \
  --output "${EVIDENCE_DIR}/routes-dns-failure.json"
probe_phase 51000 "${EVIDENCE_DIR}/connectivity-dns-failure.json"
sudo ip netns exec "${NS_CORE}" python3 "${ROOT}/lab/chr/dns_probe.py" probe \
  --bind 10.10.10.2 --server "${DNS_IP}" --port "${DNS_PORT}" \
  --name "${DNS_NAME}" --expected-ip "${WAN10_DNS_ANSWER}" \
  --timeout 0.6 --expect failure --output "${EVIDENCE_DIR}/dns-failure.json"

log "restarting WAN10 DNS responder and proving DNS recovery without route failover"
sudo ip netns exec "${NS_WAN10}" python3 "${ROOT}/lab/chr/dns_probe.py" serve \
  --bind "${DNS_IP}" --port "${DNS_PORT}" --name "${DNS_NAME}" --answer-ip "${WAN10_DNS_ANSWER}" \
  >>"${WAN10_DNS_LOG}" 2>&1 &
WAN10_DNS_PID=$!
dns_recovered=0
for _attempt in $(seq 1 20); do
  if sudo ip netns exec "${NS_WAN10}" ss -H -lun | grep -Eq '(:|])53[[:space:]]'; then
    dns_recovered=1
    break
  fi
  sleep 0.05
done
sudo ip netns exec "${NS_WAN10}" ss -H -lunp > "${EVIDENCE_DIR}/dns-wan10-recovered-sockets.txt" || true
if [[ "${dns_recovered}" -ne 1 ]]; then
  echo "WAN10 DNS responder socket did not recover" >&2
  exit 25
fi
python3 "${ROOT}/lab/chr/verify_link_up_recursive_failover.py" wait-routes \
  --admin-url "${ADMIN_URL}" --expected normal --timeout-seconds 15 \
  --output "${EVIDENCE_DIR}/routes-dns-recovered.json"
probe_phase 52000 "${EVIDENCE_DIR}/connectivity-dns-recovery.json"
sudo ip netns exec "${NS_CORE}" python3 "${ROOT}/lab/chr/dns_probe.py" probe \
  --bind 10.10.10.2 --server "${DNS_IP}" --port "${DNS_PORT}" \
  --name "${DNS_NAME}" --expected-ip "${WAN10_DNS_ANSWER}" \
  --timeout 0.6 --expect success --output "${EVIDENCE_DIR}/dns-recovery.json"

log "evaluating isolated DNS service-failure acceptance"
python3 "${ROOT}/lab/chr/verify_dns_failure_acceptance.py" \
  --dns-normal "${EVIDENCE_DIR}/dns-normal.json" \
  --dns-failure "${EVIDENCE_DIR}/dns-failure.json" \
  --dns-recovery "${EVIDENCE_DIR}/dns-recovery.json" \
  --connectivity-normal "${EVIDENCE_DIR}/connectivity-normal.json" \
  --connectivity-failure "${EVIDENCE_DIR}/connectivity-dns-failure.json" \
  --connectivity-recovery "${EVIDENCE_DIR}/connectivity-dns-recovery.json" \
  --routes-normal "${EVIDENCE_DIR}/routes-normal.json" \
  --routes-failure "${EVIDENCE_DIR}/routes-dns-failure.json" \
  --routes-recovery "${EVIDENCE_DIR}/routes-dns-recovered.json" \
  --failure-interfaces "${EVIDENCE_DIR}/dns-failure-routeros-interfaces.json" \
  --failed-sockets "${EVIDENCE_DIR}/dns-wan10-stopped-sockets.txt" \
  --recovered-sockets "${EVIDENCE_DIR}/dns-wan10-recovered-sockets.txt" \
  --output "${EVIDENCE_DIR}/dns-failure-acceptance.json"

cp "${SERIAL_LOG}" "${EVIDENCE_DIR}/chr-serial.log" || true
cp "${WAN10_SERVER_LOG}" "${EVIDENCE_DIR}/wan10-server.log" || true
cp "${WAN1_SERVER_LOG}" "${EVIDENCE_DIR}/wan1-server.log" || true
cp "${WAN10_DNS_LOG}" "${EVIDENCE_DIR}/wan10-dns.log" || true
cp "${WAN1_DNS_LOG}" "${EVIDENCE_DIR}/wan1-dns.log" || true
log "PASS: DNS service failure and recovery verified while WAN10 link, route and non-DNS data plane remained healthy"
'''
text = text[:start] + phase_block + text[end:]

target.write_text(text, encoding="utf-8")
target.chmod(0o755)
PY

exec bash "${PATCHED}"
