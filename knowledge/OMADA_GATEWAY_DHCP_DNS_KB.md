# Omada Gateway DHCP / DNS — Task 5.03

Current Omada Controller guidance models DHCP as part of an Interface network, but DHCP server state, relay state, address pools, DNS assignment, default gateway, lease time and DHCP options remain separate state planes. When an external DHCP server already exists for a network, the Controller-managed gateway DHCP server must not be enabled accidentally.

DHCP Server and DHCP Relay are different operating modes. A relay forwards client requests toward a server on another subnet; it is not equivalent to a local address pool. DHCP Option 138 may advertise the Controller address to supported Omada clients/devices and is therefore controller-path state, not a generic DNS setting.

DNS assignment can be automatic or manual. In the documented automatic behavior, the gateway address can be handed to clients as DNS. A successful DHCP lease does not prove DNS health, so verification must separately confirm lease source, gateway assignment, DNS assignment and actual name resolution. Apply remains `EXECUTED_UNVERIFIED` until fresh read-back and client-path tests pass.
