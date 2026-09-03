#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE="${ROOT}/lab/chr/run_qos_packet_flow_acceptance.sh"
GENERATED="${ROOT}/lab/chr/.run_qos_packet_flow_acceptance_v2.generated.sh"

cleanup() {
  rm -f "${GENERATED}"
}
trap cleanup EXIT

sed 's#verify_qos_packet_flow\.py#verify_qos_packet_flow_v2.py#g' "${SOURCE}" > "${GENERATED}"
chmod +x "${GENERATED}"

set +e
bash "${GENERATED}"
rc=$?
set -e
exit "${rc}"
