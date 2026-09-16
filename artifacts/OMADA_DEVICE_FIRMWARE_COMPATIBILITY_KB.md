# Omada Device Firmware Compatibility — Task 7.05

Firmware compatibility is a tuple, not a version-string comparison. The minimum authorization key is **device model + hardware revision + region + current firmware + target firmware + controller platform/version + management mode**.

TP-Link's 2026 EAP772(JP) V1 1.1.2 release note is a concrete example of why this is mandatory: it specifies a minimum firmware version for update, states that the upgrade is irreversible, directs downgrade requests to Omada technical support, and recommends Omada Controller 5.14 or above. Those values are valid only for that cited model/region/hardware revision and must never become global defaults.

The compiler must require an official firmware source and release note, honor minimum source firmware or upgrade-hop requirements, and carry downgrade/reversibility as explicit state. “Latest” is not compatibility evidence. Region mismatch is not authorized. Missing evidence yields `NOT_SUPPORTED_UNVERIFIED`.

After a firmware write, state is `EXECUTED_UNVERIFIED`. PASS requires exact firmware read-back, controller adoption/connection health, management reachability, required-feature behavior and representative network/client checks.
