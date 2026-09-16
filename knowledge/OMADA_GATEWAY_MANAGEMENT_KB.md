# Omada Gateway Management — Task 7.07

The Controller device view separates configuration from monitoring. Current guidance documents one router per site and states that gateway configuration is synchronized with current site settings by default. Available gateway functions vary by model and device status.

Gateway properties can include general settings, SNMP/services, IPTV where supported, and advanced functions such as Hardware Offload, LLDP and Echo Server. The automation keeps site settings, device overrides and operational telemetry as separate state planes.

A management operation is not complete when the controller accepts it. PASS requires the gateway to remain Connected, exact managed-state read-back, unchanged site ownership unless intentionally changed, healthy controller reachability and representative routed/client traffic. Unknown model/version/status support fails closed.
