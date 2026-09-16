# Omada Controller Backup / Restore / Upgrade Contract — Task 4.19

## Scope

This contract is fail-closed. It does not treat “Omada” as one uniform upgrade domain. Every write path is gated by controller platform and exact controller version/build, and every device firmware action is further gated by model, hardware revision, region, firmware and management mode.

## Official behavior normalized

The current Omada SDN Controller user guide documents **Settings > Maintenance > Backup & Restore**. Backup can include configuration plus retained historical data, while **Settings Only** stores configuration without historical data. Restore consumes a backup file. The same guide separates **Site Migration** and **Controller Migration** and requires the target controller/device handoff to be verified rather than inferred.

Auto Backup is a separate state plane and is platform-scoped. The current guide documents different behavior for OC200, Software Controller and Cloud-Based Controller, so the automation must not synthesize one common storage rule.

The current managed-device guide documents custom firmware upgrade as a separate device operation. Upgrade can reboot a device and cause controller readoption. Therefore a successful upload or accepted command is never PASS.

## Safety contract

Before any restore, migration or firmware upgrade, capture a compatible pre-change backup and the exact current controller/device tuple. Do not assume cross-version restore or downgrade support. Do not infer firmware suitability from a filename or from “latest”; use an official TP-Link firmware source and exact product applicability.

`EXECUTED_UNVERIFIED` is the highest state immediately after a write. PASS requires exact version/configuration read-back, controller reachability, expected adoption/connection state, intended configuration and representative service health. Recovery from a failed change must use a prevalidated compatible backup or a model/version-specific rollback procedure and must re-verify management reachability.

## Sources

- TP-Link, Omada SDN Controller User Guide, Chapter 5 — Controller maintenance, Backup & Restore, Migration, Auto Backup.
- TP-Link, Omada SDN Controller User Guide, Chapter 6 — managed-device custom firmware upgrade and readoption behavior.
