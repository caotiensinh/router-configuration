# Omada Switch Management — Task 7.08

The Controller supports individual and batch switch configuration. A batch operation applies only to selected switches and unaltered settings keep their current values. Port and LAG state, device Config state and monitoring telemetry are distinct planes, and feature availability varies by model and device status.

The switch management surface includes port profiles/overrides, mirroring, LAGs, VLAN interfaces and Management VLAN, static routes, services, and device-management actions. TP-Link explicitly warns that an incorrect Management VLAN can cause the controller to lose management of the device.

Firmware upgrade can reboot/readopt a switch, Force Provision can temporarily disconnect/readopt it, Move to Site changes ownership scope, and Forget removes controller-related configuration/history. These are not generic troubleshooting actions. PASS requires selected-device identity, Connected status, exact configuration read-back, healthy management path and representative traffic, with no unintended batch drift.
