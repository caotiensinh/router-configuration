#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE="${ROOT}/lab/chr/run_packet_flow_acceptance.sh"
PATCHED="${ROOT}/lab/chr/.generated-link-up-failure-acceptance.sh"

cleanup() {
  rm -f "${PATCHED}"
}
trap cleanup EXIT

python3 - "${SOURCE}" "${PATCHED}" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
target = Path(sys.argv[2])
text = source.read_text(encoding="utf-8")

old_fail = 'sudo ip link set "${V_WAN10_BR}" down'
new_fail = r'''sudo ip netns exec "${NS_WAN10}" ip addr del 1.1.1.1/32 dev lo
sudo ip netns exec "${NS_WAN10}" ip addr del 8.8.8.8/32 dev lo
ip -j link show "${V_WAN10_BR}" > "${EVIDENCE_DIR}/linkup-host-veth.json"
sudo ip netns exec "${NS_WAN10}" ip -j link show "${V_WAN10_NS}" > "${EVIDENCE_DIR}/linkup-namespace-veth.json"
curl -fsS --user 'admin:' "${ADMIN_URL}/rest/interface" > "${EVIDENCE_DIR}/linkup-routeros-interfaces.json"
python3 "${ROOT}/lab/chr/evaluate_link_up_failure_state.py" \
  --host-link "${EVIDENCE_DIR}/linkup-host-veth.json" \
  --namespace-link "${EVIDENCE_DIR}/linkup-namespace-veth.json" \
  --routeros-interfaces "${EVIDENCE_DIR}/linkup-routeros-interfaces.json" \
  --host-interface "${V_WAN10_BR}" \
  --namespace-interface "${V_WAN10_NS}" \
  --output "${EVIDENCE_DIR}/internet-down-link-up.json"'''

old_recover = 'sudo ip link set "${V_WAN10_BR}" up'
new_recover = r'''sudo ip netns exec "${NS_WAN10}" ip addr add 1.1.1.1/32 dev lo
sudo ip netns exec "${NS_WAN10}" ip addr add 8.8.8.8/32 dev lo'''

if text.count(old_fail) != 1:
    raise SystemExit(f"expected exactly one failure injection line, found {text.count(old_fail)}")
if text.count(old_recover) != 1:
    raise SystemExit(f"expected exactly one recovery injection line, found {text.count(old_recover)}")

patched = text.replace(old_fail, new_fail, 1).replace(old_recover, new_recover, 1)
target.write_text(patched, encoding="utf-8")
target.chmod(0o755)
PY

exec bash "${PATCHED}"
