# Omada SNMP / Monitoring / Logging

**Task:** 4.18  
**Status:** COMPLETE candidate for current official evidence scope  
**Observed:** 2026-09-16

The current Omada Controller guide exposes SNMP at **Settings > Services > SNMP** and documents SNMPv1, SNMPv2c and SNMPv3. For devices managed by the controller, the official guide states that an external NMS can **read but not write** SNMP objects. That is the default safety boundary for this work unit.

Controller logging is a separate evidence plane: logs cover controller/site activities and are organized into Alerts and Events, with Error/Warning/Info severities and Operation/System/Device/Client content classes. Export Data can export device/client/log/running-log information.

TP-Link's standalone switch logging guide documents local buffer/file logs and remote syslog, eight severity levels (0–7, lower value = higher severity), up to four log servers, and UDP/514. That evidence is model-scoped and must not be generalized to every Omada-managed switch.

PASS requires exact read-back, an intended read-only SNMP poll, no plaintext monitoring secrets in evidence, expected controller log visibility, remote syslog receipt where supported/configured, and healthy management reachability. Apply/acceptance alone is `EXECUTED_UNVERIFIED`.
