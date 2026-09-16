# Omada Gateway Static Routing — Task 5.04

Current Omada Controller guidance exposes gateway/site static routes under `Settings > Transmission > Routing > Static Route`. The route object separates identity/status, one or more destination prefixes, route type, forwarding target and metric. `Next Hop` and `Interface` are distinct forwarding modes and must not be normalized as the same operation.

Gateway/site routing is a different management plane from per-switch L3 static routing. A switch route configured in a device management window is not evidence that the same object is a gateway route. Effective routing-table state is operational evidence and must be checked after a write.

A default-route or management-path change is critical. Before change, analyze overlaps and more-specific prefixes and prove the selected next hop or interface is usable. Apply remains `EXECUTED_UNVERIFIED` until exact route read-back, effective routing-table state, positive destination flow, negative/control traffic and controller/management health all pass.

The 2026 V6.2 switch PDF was text-parsed, but visual screenshot verification was attempted and returned a cache miss. No visual-verification claim is made from that PDF.
