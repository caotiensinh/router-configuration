#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE="${ROOT}/lab/chr/run_packet_flow_acceptance.sh"
PATCHED="${ROOT}/lab/chr/.generated-route-loss-acceptance.sh"

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
    'log "rendering and applying 17 recursive routing commands for default-route-loss acceptance"',
    1,
)

phase_start = 'log "measuring normal 10:1 PCC distribution"\n'
final_line = 'log "PASS: real CHR PCC distribution, failover and failback behavior verified"\n'
start = text.find(phase_start)
end = text.find(final_line, start + len(phase_start)) if start >= 0 else -1
if start < 0 or end < 0:
    raise SystemExit("could not isolate original packet-flow phase block")
end += len(final_line)

phase_block = r'''log "measuring normal preferred-WAN routing before route loss"
probe_phase 60000 "${EVIDENCE_DIR}/flows-normal.json"

log "disabling only the owned WAN10 default routes while keeping WAN10 links healthy"
python3 "${ROOT}/lab/chr/verify_route_loss_acceptance.py" set-state \
  --admin-url "${ADMIN_URL}" --disabled true --timeout-seconds 15 \
  --output "${EVIDENCE_DIR}/route-loss-control.json"
ip -j link show "${V_WAN10_BR}" > "${EVIDENCE_DIR}/route-loss-host-link.json"
sudo ip netns exec "${NS_WAN10}" ip -j link show "${V_WAN10_NS}" \
  > "${EVIDENCE_DIR}/route-loss-namespace-link.json"
curl -fsS --user 'admin:' "${ADMIN_URL}/rest/interface" \
  > "${EVIDENCE_DIR}/route-loss-routeros-interfaces.json"
python3 "${ROOT}/lab/chr/verify_link_up_recursive_failover.py" wait-routes \
  --admin-url "${ADMIN_URL}" --expected wan10_failed --timeout-seconds 15 \
  --output "${EVIDENCE_DIR}/routes-route-loss.json"
probe_phase 61000 "${EVIDENCE_DIR}/flows-route-loss.json"

log "restoring the same WAN10 default routes and waiting for deterministic failback"
python3 "${ROOT}/lab/chr/verify_route_loss_acceptance.py" set-state \
  --admin-url "${ADMIN_URL}" --disabled false --timeout-seconds 15 \
  --output "${EVIDENCE_DIR}/route-recovery-control.json"
python3 "${ROOT}/lab/chr/verify_link_up_recursive_failover.py" wait-routes \
  --admin-url "${ADMIN_URL}" --expected recovered --timeout-seconds 15 \
  --output "${EVIDENCE_DIR}/routes-recovered.json"
probe_phase 62000 "${EVIDENCE_DIR}/flows-recovery.json"

log "evaluating default-route-loss acceptance"
python3 "${ROOT}/lab/chr/verify_route_loss_acceptance.py" evaluate \
  --flow-normal "${EVIDENCE_DIR}/flows-normal.json" \
  --flow-loss "${EVIDENCE_DIR}/flows-route-loss.json" \
  --flow-recovery "${EVIDENCE_DIR}/flows-recovery.json" \
  --routes-normal "${EVIDENCE_DIR}/routes-normal.json" \
  --routes-loss "${EVIDENCE_DIR}/routes-route-loss.json" \
  --routes-recovery "${EVIDENCE_DIR}/routes-recovered.json" \
  --loss-control "${EVIDENCE_DIR}/route-loss-control.json" \
  --recovery-control "${EVIDENCE_DIR}/route-recovery-control.json" \
  --failure-interfaces "${EVIDENCE_DIR}/route-loss-routeros-interfaces.json" \
  --host-link "${EVIDENCE_DIR}/route-loss-host-link.json" \
  --namespace-link "${EVIDENCE_DIR}/route-loss-namespace-link.json" \
  --host-interface "${V_WAN10_BR}" \
  --namespace-interface "${V_WAN10_NS}" \
  --output "${EVIDENCE_DIR}/route-loss-acceptance.json"

cp "${SERIAL_LOG}" "${EVIDENCE_DIR}/chr-serial.log" || true
cp "${WAN10_SERVER_LOG}" "${EVIDENCE_DIR}/wan10-server.log" || true
cp "${WAN1_SERVER_LOG}" "${EVIDENCE_DIR}/wan1-server.log" || true
log "PASS: default-route loss, WAN1 failover and exact WAN10 route recovery verified with links UP"
'''
text = text[:start] + phase_block + text[end:]

target.write_text(text, encoding="utf-8")
target.chmod(0o755)
PY

exec bash "${PATCHED}"
