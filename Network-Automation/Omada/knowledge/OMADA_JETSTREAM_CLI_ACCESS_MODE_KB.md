# Omada JetStream CLI Access & Command Modes

**Task:** 4.01 — CLI access and command modes  
**Observed:** 2026-09-15  
**Status:** COMPLETE for the official generic JetStream CLI guide scope

## Access methods

The official JetStream CLI guide lists three CLI access paths:

1. Console Port
2. Telnet
3. SSH

These are **not** promoted into universal per-model capabilities. Console requires the exact device to expose an applicable console interface; Telnet/SSH require exact model/firmware support and runtime enablement verification.

## Command modes

| Mode | Prompt | Entry | Return / exit |
|---|---|---|---|
| User EXEC | `Switch>` | Initial mode | `exit` disconnects; `enable` -> Privileged EXEC |
| Privileged EXEC | `Switch#` | `enable` | `disable`/`exit` -> User EXEC; `configure` -> Global Config |
| Global Configuration | `Switch(config)#` | `configure` | `exit`/`end`/Ctrl+Z -> Privileged EXEC |
| Interface Configuration | `Switch(config-if)#` / `Switch(config-if-range)#` | `interface ...` | `end`/Ctrl+Z -> Privileged EXEC; `exit` -> Global Config |
| VLAN Configuration | `Switch(config-vlan)#` | `vlan ...` | `end`/Ctrl+Z -> Privileged EXEC; `exit` -> Global Config |

The guide also prints `#` as a return mechanism from Interface/VLAN configuration to Global Configuration. This is retained as raw vendor wording but is marked **REVALIDATE_BEFORE_AUTOMATION** rather than treated as a preferred deterministic command.

## Safety boundary

- Family-level guide != exact model CLI support.
- Do not synthesize CLI support for unmanaged/inventory-only switches.
- Exact hardware/firmware applicability must be resolved before execution.
- 4.01 does not promote save, VLAN, port, IGMP, or other feature commands into their later tasks.

## Next

**4.02 — Save/running/startup configuration behavior.**
