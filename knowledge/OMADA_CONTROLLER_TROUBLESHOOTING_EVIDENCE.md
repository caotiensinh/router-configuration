# Omada Controller Troubleshooting — Evidence Note

Task: `7.15 Controller troubleshooting`
Micro-task: `7.15.A official-source evidence normalization`
Status: `EVIDENCE_ONLY_CANDIDATE`

## Official sources

1. Controller V6 adoption troubleshooting, 2026-05-11: https://support.omadanetworks.com/en/document/122955/
2. Controller network tools guide, Controller v6.0+, 2026-01-06: https://support.omadanetworks.com/en/document/113838/
3. Omada Controller User Guide V6.0: https://support.omadanetworks.com/en/document/111217/
4. Gateway adoption troubleshooting, Controller v6.0+, 2026-08-25: https://support.omadanetworks.com/us/document/13204/

## Evidence-first fault classes

- credential/authentication issue;
- controller-to-device connectivity or required-port issue;
- device lifecycle/state issue such as Pending, Adopting, Configuring, Heartbeat Missed, Disconnected or Adopt Failed;
- controller/device firmware compatibility issue;
- controller/UI stale-state issue;
- site/topology/configuration conflict;
- controller resource/logging issue;
- downstream client/network issue that requires Controller logs or Network Tools evidence.

## Diagnostic ordering

1. Record current controller version, site, device model/firmware and current controller-visible device state.
2. Collect read-only reachability, status, log/event/alert, and built-in Network Tools evidence where applicable.
3. Classify the failure plane before proposing mutation.
4. Check compatibility and configuration prerequisites before reset/upgrade/reprovision actions.
5. Preserve management reachability and collect before/after evidence if a bounded remediation is later authorized.

## Safety boundary

- Factory reset, firmware upgrade, Force Provision, Forget, broad firewall disable, or destructive log deletion are not generic first-line diagnostics.
- A recommendation to reset or reprovision must be symptom- and source-scoped, and must not be treated as evidence that root cause was proven.
- Unknown tool support or behavior is `NOT_SUPPORTED_UNVERIFIED`.
- This artifact contains no credentials, no device secrets, no write transport, and no authorization to mutate a controller or device.

## Next micro-tasks

- `7.15.B` machine-readable troubleshooting schema.
- `7.15.C` evidence-to-fault classification contract.
- `7.15.D` bounded remediation and fail-closed rules.
- `7.15.E` tests and CI discovery.
