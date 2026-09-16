# Omada Administrator / RBAC Baseline — Task 10.3

Current Omada guidance documents master administrator, administrator and viewer roles, with local and cloud identities as distinct principal types. The master administrator has all features and cannot be deleted. Administrators can be scoped to sites and can receive Adopt Devices and Device Manage permissions. Viewers are read-only for network status/settings.

The security baseline applies least privilege across role, site privileges and device permissions. Read-only monitoring accounts should use viewer scope; operational administrators receive only required sites and device permissions; master credentials are not shared or stored in evidence. Local and cloud identities are not treated as interchangeable.

RBAC changes are security-sensitive writes. PASS requires fresh principal/role/site/device-permission read-back and, where safe, a negative permission check proving restricted users cannot perform unauthorized changes. Unknown permission semantics fail closed rather than being inferred from role names.
