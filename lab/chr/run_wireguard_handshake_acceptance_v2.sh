#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE="${ROOT}/lab/chr/run_wireguard_handshake_acceptance.sh"
GENERATED="${ROOT}/lab/chr/.run_wireguard_handshake_acceptance_v2.generated.sh"
trap 'rm -f "${GENERATED}"' EXIT
sed 's#verify_wireguard_handshake.py#verify_wireguard_handshake_v2.py#g' "${SOURCE}" > "${GENERATED}"
chmod +x "${GENERATED}"
bash "${GENERATED}"
