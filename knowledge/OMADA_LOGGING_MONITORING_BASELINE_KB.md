# Omada Logging / Monitoring Security Baseline — Task 10.8

## Reuse boundary

This baseline consumes the verified observability planes from 7.11 and device-level monitoring/logging principles from 4.18. It does not create duplicate collectors, log categories, or remote-delivery mechanisms.

## Official-source facts

The Omada Controller monitoring guide distinguishes **Alerts** from **Events**, supports notification classification, and records system/device/user/administrator activity. Controller settings also document alert email and Remote Logging/Syslog options. A configured notification or syslog destination is therefore not sufficient evidence of delivery.

## Project security policy

- retain security-relevant administrative, system, device, and abnormal-behavior evidence according to an explicit retention policy;
- preserve Alert/Event semantics rather than flattening them;
- independently verify email/notification receipt when enabled;
- independently verify remote-sink receipt when Remote Logging is enabled;
- record controller/site clock and timezone context for correlation;
- expose logs under least privilege;
- sanitize exports and never persist passwords, tokens, private keys, or equivalent secret payloads.

Unknown retention semantics or transport-security properties fail closed as `NOT_SUPPORTED_UNVERIFIED` rather than being inferred.
