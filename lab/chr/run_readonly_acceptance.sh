#!/usr/bin/env sh
set -eu

: "${ROUTEROS_URL:?Set ROUTEROS_URL, for example https://192.0.2.10}"
: "${ROUTEROS_USERNAME:?Set ROUTEROS_USERNAME to a dedicated read-only REST account}"
: "${ROUTEROS_PASSWORD:?Set ROUTEROS_PASSWORD through your local secret mechanism}"

PROFILE="${1:-examples/rd-10g-1g/deployment-profile.json}"
OUTPUT_DIR="${2:-evidence/chr-readonly-$(date -u +%Y%m%dT%H%M%SZ)}"
EVIDENCE="$OUTPUT_DIR/routeros-discovery.json"
MANIFEST="$OUTPUT_DIR/manifest.json"

mkdir -p "$OUTPUT_DIR"

printf '%s\n' '[1/4] Validate deployment profile'
routerctl profile-check --profile "$PROFILE"

printf '%s\n' '[2/4] Collect sanitized RouterOS REST GET evidence'
if [ "${ROUTEROS_LAB_INSECURE_TLS:-0}" = "1" ]; then
    routerctl routeros-discover \
      --url "$ROUTEROS_URL" \
      --username "$ROUTEROS_USERNAME" \
      --output "$EVIDENCE" \
      --lab \
      --no-verify-tls
else
    routerctl routeros-discover \
      --url "$ROUTEROS_URL" \
      --username "$ROUTEROS_USERNAME" \
      --output "$EVIDENCE"
fi

printf '%s\n' '[3/4] Verify evidence integrity'
routerctl routeros-evidence-check --evidence "$EVIDENCE"

printf '%s\n' '[4/4] Run profile-to-evidence preflight'
routerctl routeros-preflight --profile "$PROFILE" --evidence "$EVIDENCE"

python - "$PROFILE" "$EVIDENCE" "$MANIFEST" <<'PY'
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

profile = Path(sys.argv[1])
evidence = Path(sys.argv[2])
manifest = Path(sys.argv[3])
evidence_payload = json.loads(evidence.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()

payload = {
    "schema_version": "routeros-readonly-acceptance-manifest/1",
    "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "claim_scope": "read_only_candidate_evidence",
    "profile_sha256": sha256(profile),
    "evidence_file_sha256": sha256(evidence),
    "normalized_state_sha256": evidence_payload.get("state_sha256"),
    "platform": evidence_payload.get("platform", {}),
    "note": "This manifest does not by itself prove CHR or physical-device provenance; target evidence must still be reviewed and recorded in ROUTEROS_TARGET_MATRIX.json.",
}
manifest.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

printf '%s\n' "READ_ONLY_PIPELINE_PASS evidence=$EVIDENCE manifest=$MANIFEST"
