# Omada Controller User / RBAC / Administrator Roles — Task 7.10

Current Omada Controller guidance defines three administrator levels: master administrator, administrator and viewer. Local users and cloud users are separate principal types and must remain distinct in normalized state.

The master administrator has full controller access and cannot be deleted. Administrators are scoped by site privileges and may receive `Adopt Devices` and `Device Manage` permissions separately. Administrators can manage viewer accounts within their privileged sites but cannot edit/delete the master administrator or peer administrators. Viewers are read-only for their privileged sites. `All` site privilege includes future sites, which makes it broader than an explicit site list.

Project policy is least privilege and secret-safe evidence. Passwords, tokens and reset secrets are never persisted in verification artifacts. PASS requires role/site/device-permission read-back plus both a permitted-action check and a representative denied-action check. Unknown permission effects fail closed as `DENY_UNVERIFIED`.
