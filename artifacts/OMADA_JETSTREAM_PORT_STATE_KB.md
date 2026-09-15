# Omada JetStream Physical Port Status / Speed / Duplex

**Task:** 4.03 — Physical port status / speed / duplex  
**Observed:** 2026-09-15  
**Status:** COMPLETE for the official Managed Switch CLI guide scope

## Official interface classes

The current **Managed Switch CLI Reference Guide REV2.0.0** publishes these Chapter-12 interface identifiers:

| CLI token | Normalized class | Guide meaning |
|---|---|---|
| `fastEthernet` | `FAST_ETHERNET` | 100M Ethernet port |
| `gigabitEthernet` | `GIGABIT_ETHERNET` | Gigabit Ethernet port |
| `two-gigabitEthernet` | `TWO_GIGABIT_ETHERNET` | 2.5-Gigabit Ethernet port |
| `ten-gigabitEthernet` | `TEN_GIGABIT_ETHERNET` | 10-Gigabit Ethernet port |
| `port-channel` | `PORT_CHANNEL` | Ethernet channel where explicitly accepted |

This is a command-language mapping, not a complete physical product capability table. A 5-Gigabit speed keyword does **not** establish a `five-gigabitEthernet` CLI class, and the project will not invent 25G or other interface tokens that are absent from applicable official syntax.

## Three state planes must remain separate

| Plane | Canonical read | Meaning |
|---|---|---|
| Configured state | `show interface configuration` | Port-status, Flow Control, Negotiation Mode, Port-description |
| Operational connection state | `show interface status` | Current connection status of Ethernet ports / port channels |
| Statistics state | `show interface counters` | Traffic/statistics evidence |

All three commands are documented for Privileged EXEC or any configuration mode with no privilege requirement published in their respective command entries. A configuration value is **not** proof of a live link, and counters are not configuration state.

## Speed

Canonical syntax:

`speed { 10 | 100 | 1000 | 2500 | 5000 | 10000 | auto }`

Reset syntax:

`no speed`

The guide states that `no speed` returns to the default configuration and describes Auto negotiation as the default speed mode. The speed command is documented in Fast/Gigabit/2.5-Gigabit/10-Gigabit interface contexts and port-channel contexts, with Admin or Operator privilege.

**Critical capability rule:** the grammar's list of speed keywords is a command-wide vocabulary. It is not evidence that every exact physical port supports all seven choices. Exact port/media capability must be positively resolved before a write.

## Duplex

Canonical syntax:

`duplex { auto | full | half }`

Reset syntax:

`no duplex`

The current guide documents Admin or Operator access and explicitly states that a **Gigabit Ethernet** port defaults to auto-negotiation. Its listed command contexts are Gigabit Ethernet/interface-range and port-channel contexts. The project therefore does not extend that default or duplex applicability to Fast Ethernet, 2.5G, 10G or other classes without exact evidence.

## Interface-range safety

The guide states that commands in Interface Range GigabitEthernet mode are executed independently on the member ports and that an error on one port does not stop execution on the others.

For automation, this means an interface-range write is **not atomic**. A range transaction requires per-port outcome collection; a partial failure may never be collapsed into one PASS result.

## Safe automation contract

1. Resolve exact model + hardware revision + region + firmware + management mode.
2. Resolve the exact physical port, media, and applicable CLI interface class.
3. Positively verify the requested speed/duplex capability for that exact port.
4. Read configured negotiation state and current connection state before mutation.
5. Identify whether the target carries the active management path and preserve an authorized recovery path.
6. Obtain production-write approval.
7. Apply only the intended speed/duplex delta.
8. Read back `show interface configuration`.
9. Re-read `show interface status`; use counters if diagnostics are needed.
10. PASS only when the intended configured value is verified and the required operational link outcome is acceptable.

A command that is merely accepted is `EXECUTED_UNVERIFIED`, not PASS.

## Rollback and persistence boundary

`no speed` / `no duplex` restore vendor defaults; they are **not** a substitute for restoring a previously observed non-default value. Safe rollback must use the exact pre-change state when available.

A successful interface write/read-back verifies the running state only. Reboot durability still requires the **4.02 running → startup save contract**.

## Scope boundaries

- Family membership never proves exact-model command support.
- Unmanaged/inventory-only switches are not promoted to CLI targets.
- Controller/cloud behavior is not inferred from local CLI behavior.
- The generic CLI interface vocabulary is not expanded to port types absent from the applicable guide.
- Virtual tests may validate orchestration and fail-closed logic, but not PHY negotiation, actual link establishment, cabling, optics, electrical behavior, or line-rate performance.

## Source

TP-Link / Omada, **Managed Switch_CLI Guide**, REV2.0.0, May 2026; official Omada support publication 2026-07-24.  
`https://support.omadanetworks.com/us/document/4943/`

## Closure

**4.03 = COMPLETE** for official managed-switch CLI physical port status / speed / duplex semantics with exact port/media capability gates retained.

**Next:** 4.04 — VLAN 802.1Q fundamentals.
