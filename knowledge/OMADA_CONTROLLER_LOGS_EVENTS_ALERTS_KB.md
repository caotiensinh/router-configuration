# Omada Controller Logs / Events / Alerts — Task 7.11

Current Controller V6.2 documentation separates Alerts, Events and Audit Logs, and separately documents Alert/Event Notifications, Audit Log Notifications and Remote Logging. These are different state/evidence planes and must not be collapsed into one generic `log enabled` flag.

TP-Link's support-export guidance also distinguishes controller configuration data, runtime logs and the log list. It documents masked support export for Controller 5.6.3+ and version/access-mode caveats for how artifacts can be retrieved. Exported evidence must therefore retain controller version and access-mode provenance and must be sanitized before persistence or sharing.

Configuration acceptance is not proof of observability. PASS requires a representative generated condition in the expected alert/event plane, representative administrative action in audit logs where applicable, independent notification delivery checks, remote-sink receipt when configured, and secret-safe retained evidence.
