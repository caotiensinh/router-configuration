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
new_fail = r'''sudo ip netns exec "${NS_WAN10}" tc qdisc replace dev "${V_WAN10_NS}" root netem loss 100%
ip -j link show "${V_WAN10_BR}" > "${EVIDENCE_DIR}/linkup-host-veth.json"
sudo ip netns exec "${NS_WAN10}" ip -j link show "${V_WAN10_NS}" > "${EVIDENCE_DIR}/linkup-namespace-veth.json"
sudo ip netns exec "${NS_WAN10}" tc qdisc show dev "${V_WAN10_NS}" > "${EVIDENCE_DIR}/linkup-namespace-qdisc.txt"
curl -fsS --user 'admin:' "${ADMIN_URL}/rest/interface" > "${EVIDENCE_DIR}/linkup-routeros-interfaces.json"
python3 "${ROOT}/lab/chr/evaluate_link_up_failure_state.py" \
  --host-link "${EVIDENCE_DIR}/linkup-host-veth.json" \
  --namespace-link "${EVIDENCE_DIR}/linkup-namespace-veth.json" \
  --namespace-qdisc "${EVIDENCE_DIR}/linkup-namespace-qdisc.txt" \
  --routeros-interfaces "${EVIDENCE_DIR}/linkup-routeros-interfaces.json" \
  --host-interface "${V_WAN10_BR}" \
  --namespace-interface "${V_WAN10_NS}" \
  --output "${EVIDENCE_DIR}/internet-down-link-up.json"'''
old_recover = 'sudo ip link set "${V_WAN10_BR}" up'
new_recover = r'''sudo ip netns exec "${NS_WAN10}" tc qdisc del dev "${V_WAN10_NS}" root'''

for needle, label in ((old_fail, "failure injection"), (old_recover, "recovery injection")):
    if text.count(needle) != 1:
        raise SystemExit(f"expected exactly one {label} line, found {text.count(needle)}")

old_verifier = 'verify_packet_flow_behavior.py'
if text.count(old_verifier) != 5:
    raise SystemExit(
        f"expected exactly five packet-flow verifier call sites, found {text.count(old_verifier)}"
    )
text = text.replace(old_verifier, 'verify_link_up_recursive_failover.py')

start_marker = 'log "diagnosing RouterOS runtime validity of PCC and routing-mark rules"\n'
end_marker = 'python3 "${ROOT}/lab/chr/verify_link_up_recursive_failover.py" wait-routes \\\n'
start = text.find(start_marker)
end = text.find(end_marker, start + len(start_marker)) if start >= 0 else -1
if start < 0 or end < 0:
    raise SystemExit("could not isolate PCC-only diagnostic block")
text = text[:start] + text[end:]

text = text.replace(old_fail, new_fail, 1).replace(old_recover, new_recover, 1)
text = text.replace('log "measuring normal 10:1 PCC distribution"', 'log "measuring preferred-WAN recursive routing"')
text = text.replace('log "evaluating end-to-end packet-flow acceptance"', 'log "evaluating link-up Internet failure and recursive failover acceptance"')
text = text.replace('log "PASS: real CHR PCC distribution, failover and failback behavior verified"', 'log "PASS: Internet-down/link-up recursive failover and recovery verified"')
text = text.replace(
    'for command in python3 qemu-system-x86_64 unzip ip curl sudo; do',
    'for command in python3 qemu-system-x86_64 unzip ip curl sudo ss; do',
    1,
)

measurement_marker = 'log "measuring preferred-WAN recursive routing"\n'
if text.count(measurement_marker) != 1:
    raise SystemExit("expected exactly one preferred-WAN measurement marker")
readiness_block = r'''log "verifying deterministic dataplane readiness before acceptance measurement"
READINESS_DIR="${EVIDENCE_DIR}/readiness"
mkdir -p "${READINESS_DIR}"
for readiness_ns in "${NS_CORE}" "${NS_WAN10}" "${NS_WAN1}"; do
  sudo ip netns exec "${readiness_ns}" ip -j link show > "${READINESS_DIR}/${readiness_ns}-links.json"
  sudo ip netns exec "${readiness_ns}" ip -j addr show > "${READINESS_DIR}/${readiness_ns}-addresses.json"
  sudo ip netns exec "${readiness_ns}" ip -j route show table all > "${READINESS_DIR}/${readiness_ns}-routes.json"
  sudo ip netns exec "${readiness_ns}" ip -j neigh show > "${READINESS_DIR}/${readiness_ns}-neighbours.json"
done
sudo ip netns exec "${NS_WAN10}" ss -H -lunp > "${READINESS_DIR}/wan10-sockets.txt" || true
sudo ip netns exec "${NS_WAN1}" ss -H -lunp > "${READINESS_DIR}/wan1-sockets.txt" || true
{
  printf 'wan10_pid=%s alive=' "${WAN10_SERVER_PID}"
  if sudo kill -0 "${WAN10_SERVER_PID}" 2>/dev/null; then printf 'true\n'; else printf 'false\n'; fi
  printf 'wan1_pid=%s alive=' "${WAN1_SERVER_PID}"
  if sudo kill -0 "${WAN1_SERVER_PID}" 2>/dev/null; then printf 'true\n'; else printf 'false\n'; fi
} > "${READINESS_DIR}/responder-processes.txt"
curl -fsS --user 'admin:' "${ADMIN_URL}/rest/interface" > "${READINESS_DIR}/routeros-interfaces.json"
curl -fsS --user 'admin:' "${ADMIN_URL}/rest/ip/route" > "${READINESS_DIR}/routeros-ip-routes.json"
curl -fsS --user 'admin:' "${ADMIN_URL}/rest/ip/route?active=true" > "${READINESS_DIR}/routeros-active-ip-routes.json"
curl -fsS --user 'admin:' "${ADMIN_URL}/rest/routing/nexthop" > "${READINESS_DIR}/routeros-nexthops.json"
cp "${EVIDENCE_DIR}/routes-normal.json" "${READINESS_DIR}/managed-routes-normal.json"

readiness_ok=0
readiness_attempts=0
for readiness_attempt in $(seq 1 8); do
  readiness_attempts="${readiness_attempt}"
  if sudo ip netns exec "${NS_CORE}" python3 "${ROOT}/lab/chr/udp_flow_probe.py" \
    --bind 10.10.10.2 \
    --destination "${SERVICE_IP}" \
    --destination-port "${SERVICE_PORT}" \
    --source-port-start "$((19000 + readiness_attempt))" \
    --count 1 \
    --timeout 0.5 \
    --output "${READINESS_DIR}/probe-${readiness_attempt}.json"; then
    cp "${READINESS_DIR}/probe-${readiness_attempt}.json" "${READINESS_DIR}/probe-final.json"
    readiness_ok=1
    break
  fi
done
for readiness_ns in "${NS_CORE}" "${NS_WAN10}" "${NS_WAN1}"; do
  sudo ip netns exec "${readiness_ns}" ip -j neigh show > "${READINESS_DIR}/${readiness_ns}-neighbours-after.json"
done

python3 - "${READINESS_DIR}" "${readiness_ok}" "${readiness_attempts}" <<'PYREADINESS'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
probe_ok = sys.argv[2] == "1"
attempts = int(sys.argv[3])


def load_json(name):
    return json.loads((root / name).read_text(encoding="utf-8"))


def is_true(value):
    return str(value or "").strip().lower() in {"1", "true", "yes"}

errors = []

namespace_expectations = {
    "rc-core": {"interface": "v-core-ns", "addresses": {"10.10.10.2"}},
    "rc-wan10": {"interface": "v-w10-ns", "addresses": {"192.0.2.1", "203.0.113.100"}},
    "rc-wan1": {"interface": "v-w1-ns", "addresses": {"198.51.100.1", "203.0.113.100"}},
}
for namespace, expected in namespace_expectations.items():
    links = load_json(f"{namespace}-links.json")
    link = next((row for row in links if str(row.get("ifname") or "") == expected["interface"]), None)
    if not link or "UP" not in set(link.get("flags", [])):
        errors.append(f"{namespace} interface {expected['interface']} is not UP")
    addresses = load_json(f"{namespace}-addresses.json")
    observed_addresses = {
        str(info.get("local") or "")
        for row in addresses if isinstance(row, dict)
        for info in row.get("addr_info", []) if isinstance(info, dict)
    }
    missing_addresses = sorted(expected["addresses"] - observed_addresses)
    if missing_addresses:
        errors.append(f"{namespace} missing addresses: {missing_addresses}")
    routes = load_json(f"{namespace}-routes.json")
    if namespace == "rc-core":
        if not any(str(row.get("dst") or "default") == "default" and str(row.get("gateway") or "") == "10.10.10.1" for row in routes if isinstance(row, dict)):
            errors.append("rc-core default route via 10.10.10.1 is missing")
    else:
        expected_gateway = "192.0.2.2" if namespace == "rc-wan10" else "198.51.100.2"
        if not any(str(row.get("dst") or "") == "10.10.10.0/24" and str(row.get("gateway") or "") == expected_gateway for row in routes if isinstance(row, dict)):
            errors.append(f"{namespace} return route via {expected_gateway} is missing")

process_text = (root / "responder-processes.txt").read_text(encoding="utf-8", errors="replace")
processes = {}
for line in process_text.splitlines():
    parts = line.strip().split()
    if len(parts) != 2 or "_pid=" not in parts[0] or not parts[1].startswith("alive="):
        continue
    label, pid = parts[0].split("_pid=", 1)
    processes[label] = {"pid": pid, "alive": parts[1].split("=", 1)[1] == "true"}
for label in ("wan10", "wan1"):
    state = processes.get(label)
    if not state or not state["pid"]:
        errors.append(f"{label.upper()} responder process evidence is malformed")
    elif not state["alive"]:
        errors.append(f"{label.upper()} responder process is not alive")

for label in ("wan10", "wan1"):
    sockets = (root / f"{label}-sockets.txt").read_text(encoding="utf-8", errors="replace")
    if ":5000" not in sockets:
        errors.append(f"{label.upper()} UDP responder socket is not listening on port 5000")

interfaces = load_json("routeros-interfaces.json")
by_name = {str(row.get("name") or ""): row for row in interfaces if isinstance(row, dict)}
for name in ("ether2", "ether3", "ether4"):
    row = by_name.get(name)
    if not row or not is_true(row.get("running")):
        errors.append(f"RouterOS {name} is not running")

managed = load_json("managed-routes-normal.json")
routes = managed.get("routes", []) if isinstance(managed, dict) else []
wan10 = [r for r in routes if ":lab-wan10g:" in str(r.get("comment") or "")]
wan1 = [r for r in routes if ":lab-wan1g:" in str(r.get("comment") or "")]
if managed.get("ok") is not True or managed.get("expected") != "normal":
    errors.append("managed normal route evidence is not accepted")
if len(wan10) != 2 or not any(bool(r.get("active")) for r in wan10):
    errors.append("preferred WAN10 route is not RouterOS-active")
if len(wan1) != 2 or any(bool(r.get("active")) for r in wan1):
    errors.append("backup WAN1 route is unexpectedly RouterOS-active during normal phase")

final_probe = None
if probe_ok and (root / "probe-final.json").exists():
    final_probe = load_json("probe-final.json")
    tags = final_probe.get("tags", {}) if isinstance(final_probe, dict) else {}
    if int(final_probe.get("successful_flows") or 0) != 1 or int(tags.get("WAN10") or 0) != 1:
        errors.append("readiness probe did not complete exactly one flow through WAN10")
else:
    errors.append("single-flow end-to-end readiness probe never succeeded")

result = {
    "schema_version": "chr-link-up-dataplane-readiness/1",
    "ok": not errors,
    "classification": "READY" if not errors else "LAB_READINESS_FAILED",
    "acceptance": "PASS" if not errors else "FAIL",
    "attempts": attempts,
    "errors": errors,
    "final_probe": final_probe,
    "evidence": {
        "namespace_links": True,
        "namespace_addresses": True,
        "namespace_routes": True,
        "namespace_neighbours": True,
        "responder_processes": True,
        "responder_sockets": True,
        "routeros_interfaces": True,
        "routeros_routes": True,
        "routeros_active_route_query": True,
        "routeros_nexthops": True,
    },
    "production_writer_available": False,
    "write_authorized": False,
}
(root / "readiness.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(result, indent=2, sort_keys=True))
if errors:
    raise SystemExit(18)
PYREADINESS

'''
text = text.replace(measurement_marker, readiness_block + measurement_marker, 1)

target.write_text(text, encoding="utf-8")
target.chmod(0o755)
PY

exec bash "${PATCHED}"
