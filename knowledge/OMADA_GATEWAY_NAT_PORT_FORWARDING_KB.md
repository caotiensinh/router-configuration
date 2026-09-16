# Omada Gateway NAT / Port Forwarding Knowledge Baseline — Task 5.07

## Authority
- Omada Controller User Guide V6.0: https://support.omadanetworks.com/en/document/111217/
- Omada guide for limiting public source IPs to an internal server: https://support.omadanetworks.com/us/document/126427/

## Normalized capability planes
Port Forwarding, One-to-One NAT, ALG, NAT-disable state, and observed inbound reachability are separate planes. A Port Forwarding rule does not prove that a One-to-One NAT or ALG behavior exists, and a configured rule does not prove that traffic is actually reachable.

## Vendor facts retained
The Controller guide documents Port Forwarding as a mechanism that permits Internet hosts to reach selected LAN hosts/services through specified gateway ports. Rules expose source scope, WAN/interface binding, external/source port, internal/destination port and destination IP, and protocol. The current support guide also demonstrates restricting exposure to specific public source IPs rather than permitting every Internet source.

## Project security policy
Use the narrowest source scope that satisfies the requirement. `Any` is not the default when a known bounded source can be expressed. Treat DMZ or broad inbound exposure as a separate high-risk design choice, not a generic Port Forwarding shortcut. Management-plane exposure requires an independent security review. Check collisions with management, VPN, controller and other inbound-service ports before proposing a change.

## Verification
Configuration acceptance remains `EXECUTED_UNVERIFIED` until fresh read-back and traffic evidence exist. PASS requires a positive allowed-source test and, when source restriction is part of the rule, a negative disallowed-source control. Existing management and unrelated inbound services must remain healthy.

Unknown model/firmware/controller behavior is `NOT_SUPPORTED_UNVERIFIED`; do not infer capability from another Omada gateway or another management mode.
