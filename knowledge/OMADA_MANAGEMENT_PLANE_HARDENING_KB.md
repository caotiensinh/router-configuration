# Omada Management-Plane Hardening — Task 10.2

This baseline separates **vendor-documented capability** from the project's **security policy**. The automation may recommend a hardening control only when the exact controller/device/topology can support it; it must not convert a general security preference into a fabricated Omada capability.

TP-Link documents HTTPS certificate import and Access Config for Software and Hardware Controllers, and explicitly separates controller-management ports from portal ports. TP-Link also documents management-VLAN designs for supported Omada deployments and warns that incorrect Management VLAN configuration can break controller management. Cloud access is an optional path for on-prem controller setup rather than a prerequisite for local administration.

The project security policy is therefore: isolate management where verified-supported, prefer encrypted management protocols, avoid unnecessary/insecure management services, keep portal/client paths separate from administration, and never persist credentials/private keys in evidence. These are policy controls; exact implementation still requires model/controller/firmware evidence.

Any management-plane change is critical because a syntactically valid change can still lock out the controller or devices. Before mutation, capture the current path and backup, calculate the reachability impact and identify recovery options. After the write, remain `EXECUTED_UNVERIFIED` until a fresh management endpoint read-back proves controller login, device adoption/connection and intended isolation are healthy.
