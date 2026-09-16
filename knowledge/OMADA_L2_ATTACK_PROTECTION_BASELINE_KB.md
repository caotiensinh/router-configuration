# Omada L2 Attack-Protection Baseline — Task 10.5

This baseline treats IP-MAC binding, DHCP Snooping, ARP Inspection, IP Source Guard, port security, storm control, port isolation and DoS defense as separate capabilities. Exact support is model, hardware, firmware and management-plane dependent; a standalone switch guide is not proof that the same control exists through every Controller version.

The dependency chain matters. DHCP Snooping can learn binding state; ARP Inspection and IP Source Guard can consume binding state on supported platforms. Static-IP hosts therefore need an explicit binding strategy rather than invented DHCP leases. Trust topology must identify legitimate DHCP/uplink paths before enforcement; blindly marking ports trusted or untrusted can either defeat protection or break service.

Project policy is to enable only proven-supported protections, preserve management/infrastructure paths, and tune rate/storm controls to actual service requirements. PASS requires configuration and binding read-back, legitimate traffic success and representative negative/spoof evidence where safely testable.
