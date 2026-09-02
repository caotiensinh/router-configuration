# CHR Packet-Flow Acceptance

This gate validates Router Configuration v1 Multi-WAN behavior on a disposable MikroTik CHR 7.24.1 instance.

## Scope

The lab boots four CHR interfaces:

- `ether1`: user-mode management only, REST forwarded to loopback.
- `ether2`: isolated WAN10 dataplane.
- `ether3`: isolated WAN1 dataplane.
- `ether4`: isolated CORE dataplane.

Linux network namespaces provide two independent WAN peers and one CORE client. Both WAN namespaces expose the same synthetic service IP but return different UDP tags (`WAN10` or `WAN1`). This lets the CORE client observe which WAN actually carried each new connection without relying only on RouterOS counters.

## Acceptance sequence

1. Render and dry-run 17 recursive-failover commands plus 21 state-safe PCC commands.
2. Reconcile every dedicated policy routing table to `fib=yes`; an existing `fib=false` table is repaired rather than accepted as drift.
3. Apply the 38-command fixture to disposable CHR only.
4. Read RouterOS runtime state for every managed PCC mangle rule. Any `invalid=true` rule is an immediate hard failure before traffic measurement.
5. Run a temporary CLI-import diagnostic matrix. It reuses the already valid managed WAN10 connection mark and tests PCC modulus variants `2/1`, `3/1`, `10/1`, `11/1`, and `11/10`, then separately tests new mark creation and routing-mark dependency. Diagnostic rules and files are removed before traffic measurement.
6. Confirm normal recursive routes are active.
7. Generate 220 unique UDP connections from CORE and verify an approximately 10:1 WAN10:WAN1 distribution.
8. Disconnect WAN10 reachability at the host-side isolated veth.
9. Wait for RouterOS recursive `check-gateway` state to move WAN10-marked policy traffic to WAN1.
10. Generate a fresh source-port range and require at least 98% WAN1 responses with at least 95% request success.
11. Restore WAN10 reachability and wait for route recovery.
12. Generate another fresh source-port range and require capacity-weighted distribution to return.

The shell harness remains `set -Eeuo pipefail` for the entire run. Cleanup operations are individually best-effort and must never disable `errexit` globally. A failed evaluator or runtime-validity check therefore fails the GitHub Actions job.

## Safety boundary

The gate uses only a QEMU `-snapshot` CHR image and loopback management forwarding. It contains no production router address, credential, secret resolver, or product write transport. The WAN and CORE networks exist only as temporary Linux namespaces, bridges, taps and veth pairs on the CI runner.

Evidence is uploaded as a GitHub Actions artifact and includes flow counts, route states, RouterOS mangle snapshots, CLI-import PCC runtime diagnostics, CHR resource/interface metadata and serial logs.
