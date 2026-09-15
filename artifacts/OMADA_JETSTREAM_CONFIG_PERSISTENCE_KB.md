# Omada JetStream Configuration Persistence

**Task:** 4.02 — Save/running/startup configuration behavior  
**Observed:** 2026-09-15  
**Status:** COMPLETE for the official managed-switch guide scope

## Official state model

The current multi-model **Managed Switch CLI Reference Guide REV2.0.0** distinguishes two configuration states:

- `running-config`: the current operating configuration.
- `startup-config`: the configuration saved in the switch; the guide states that these saved settings are not lost on the next reboot.

The official JetStream CLI example guide additionally warns that configurations which are not saved are lost if the switch is powered off or rebooted.

Therefore the automation model must treat running and startup configuration as **potentially divergent states** until persistence has been explicitly performed and verified.

## Canonical save/read commands

| Operation | Command | Mode | Documented privilege | Risk |
|---|---|---|---|---|
| Save current settings | `copy running-config startup-config` | Privileged EXEC | Admin, Operator | Persistent write |
| Read current operating config | `show running-config` | Privileged EXEC or any configuration mode | Admin | Read-only |
| Read saved config | `show startup-config` | Privileged EXEC or any configuration mode | Admin | Read-only |

The example guide also publishes the abbreviation `copy run start` and a local Web GUI **Save** action. These are retained only within their official guide scope and do not establish controller/cloud persistence semantics.

## Privilege asymmetry

The 2026 guide documents **Admin or Operator** access for the save command, but **Admin-only** access for both canonical `show` commands. This means an Operator-role transaction can potentially execute a save without being authorized to perform the canonical CLI read-back.

For this project, that case is **not PASS**. It is recorded as `EXECUTED_UNVERIFIED` until an authorized read-back or another exact, official verification path confirms the intended startup state.

## Safe automation contract

1. Resolve exact model, hardware revision, region, firmware and management mode.
2. Reject unmanaged/inventory-only devices and unresolved CLI applicability.
3. Confirm authenticated role and command support.
4. Pre-read running/startup state when the role allows it.
5. Calculate the intended delta and obtain required production-write approval.
6. Execute `copy running-config startup-config`.
7. Read back `show startup-config` using an authorized role.
8. Verify intended configuration objects semantically. Do **not** require byte-for-byte equality unless exact-device output canonicalization has been separately verified.

## Persistence boundary

- Unsaved configuration is treated as volatile with respect to reboot/power-off where the official JetStream example guide applies.
- Saved startup configuration is treated as retained across the next reboot where the current Managed Switch CLI guide applies.
- This task does not claim that every runtime subsystem state is part of the configuration file.
- This task does not infer local CLI/Web GUI behavior into Omada Controller or cloud-managed persistence behavior.
- A virtual lab can validate workflow, permissions/state-machine logic and fail-closed behavior, but cannot certify real switch power-loss persistence.

## Applicability boundary

The 2026 reference is explicitly a **multi-model Managed Switch** guide. Some sections in that guide are explicitly marked “Only for Certain Devices”; the save and canonical show commands above are not labeled that way in their own sections. Even so, the project does **not** promote them to every TP-Link switch SKU or firmware. Exact-device support remains an execution-time gate, and unmanaged switches remain excluded.

## Sources

1. TP-Link / Omada, **Managed Switch_CLI Guide**, REV2.0.0, May 2026; Omada support portal publication 2026-07-24.  
   `https://support.omadanetworks.com/us/document/4943/`
2. TP-Link / Omada, **Typical CLI Configuration Examples for TP-Link JetStream Switch**.  
   `https://support.omadanetworks.com/hk/document/13117/`

## Closure

**4.02 = COMPLETE** for official managed-switch-guide persistence semantics with exact-device applicability and privilege read-back gates retained.

**Next:** 4.03 — Physical port status / speed / duplex.
