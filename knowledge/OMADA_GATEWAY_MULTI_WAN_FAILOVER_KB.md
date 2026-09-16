# Omada Gateway Multi-WAN / Load Balancing / Failover — Task 5.06

## Scope

This task normalizes Omada gateway Multi-WAN behavior without collapsing WAN interface state, Online Detection, Load Balancing, Link Backup, or Policy Routing into one feature.

## Official-source facts

The current Omada Controller network guide documents multiple WAN operation together with **Online Detection**, **Load Balancing**, and **Link Backup**. Online Detection is therefore a health input to automatic path decisions; physical link-up alone is not sufficient evidence that upstream Internet service is healthy.

Policy Routing remains task 5.05. A policy that selects a preferred WAN is not evidence that generic load balancing or backup failover is configured correctly.

## Normalized contract

- `wan_interfaces`: configured WAN identities and current state.
- `online_detection`: explicit health method/targets and current healthy/unhealthy result.
- `load_balancing`: enablement and documented weight/ratio semantics where supported.
- `link_backup`: explicit primary/backup role and failover condition.
- `failover_observation`: evidence from controlled failure and recovery.

## Safety and verification

Before any change, calculate management-path, VPN, inbound-service, and remote-site impact. Never infer exact capability from product-family marketing; exact gateway model/hardware revision/region/firmware/controller version remains mandatory.

PASS is not command acceptance. PASS requires fresh read-back, expected steady-state path, controlled failover, controlled recovery, management reachability, and a negative control proving an unhealthy WAN is not selected. Existing sessions are not claimed to survive merely because new sessions fail over.
