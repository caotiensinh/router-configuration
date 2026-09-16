# Omada Gateway Firewall / ACL / Stateful Policy — Task 5.08

## Authority
Primary source: Omada Controller User Guide V6.0:
https://support.omadanetworks.com/en/document/111217/

## Vendor facts
- ACL is not one generic plane: Gateway ACL, Switch ACL, and EAP ACL apply at different forwarding surfaces.
- ACL rules are evaluated sequentially and the first matching rule determines the action.
- When no ACL rule matches, the documented controller behavior includes an implicit Permit All clause.
- Gateway ACL exposes LAN->LAN and LAN->WAN directions and can separately control access to the gateway management page.
- Gateway ACL supports state matching; the documented Auto mode covers New/Established/Related states.
- Gateway Firewall Options are a separate surface from ACL rules and include session timers and options such as SYN Cookies.

## Automation contract
1. Bind every claim to exact model, hardware revision, region, firmware, controller platform/version/build, and management mode.
2. Normalize Gateway/Switch/EAP ACL, Firewall Options, state matching, and effective ordered policy separately.
3. Never assume a rule applies to a packet path until the actual ACL plane and direction are proven.
4. For restricted zones, require an explicit terminal/default policy rather than relying on implicit Permit All.
5. Treat rule ordering as configuration state. A correct rule in the wrong order is drift.
6. Broad Any/Any permits and management-page exposure require an explicit exception and separate security review.
7. A vendor-accepted write is only `EXECUTED_UNVERIFIED`.

## PASS evidence
PASS requires fresh ordered read-back plus positive allowed-flow, negative denied-flow, stateful return-flow where applicable, management-survival, and unrelated-flow controls.

Unknown model/version support is `NOT_SUPPORTED_UNVERIFIED`.
