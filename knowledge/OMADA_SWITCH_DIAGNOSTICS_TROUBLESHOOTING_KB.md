# Omada Switch Diagnostics / Troubleshooting — Task 4.20

## Operating rule

Troubleshooting is evidence-first. The automation must not jump from a symptom to a configuration write. It first fixes the scope of the failure (endpoints, direction, time and management mode), captures current device/controller state, and then walks the lowest-cost read-only evidence path before proposing any mutation.

## Vendor-supported diagnostic planes

TP-Link's managed-switch diagnostics guidance documents cable diagnostics plus ping and tracert for explicitly scoped switch families. Current Omada Controller guidance also uses a switch-side ping test to validate device-to-controller or internet reachability before adoption. Those are separate capability planes: availability in standalone mode does **not** prove availability through a particular Controller version.

Controller support exports are another evidence plane. TP-Link documents configuration-data, runtime-log and event/log-list exports for troubleshooting. These artifacts may contain operational topology/configuration information and therefore must be sanitized before persistence or external sharing.

## RCA sequence

1. Define the exact failing flow or management symptom.
2. Capture link state, counters and current management/adoption state.
3. Test physical media only if cable diagnostics are verified for the exact model/mode.
4. Test the relevant L3 path with ping/traceroute only where supported.
5. Inspect the feature state that actually lies on the path: VLAN/PVID, LAG/STP, MAC/ARP, routing, ACL/security and controller provisioning as applicable.
6. Export logs/configuration evidence when the prior steps do not isolate the fault.
7. Change only the failing layer, then obtain a fresh read-back and rerun the representative failing path.

Factory reset, broad security disable and speculative firmware upgrade are not generic troubleshooting steps. If evidence is still insufficient, the correct state is `ROOT_CAUSE_UNRESOLVED`, not a guessed fix.
