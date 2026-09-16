# Omada Gateway Interfaces / WAN / LAN — Task 5.01

Current Omada Controller guidance separates wired networking into Internet and LAN. WAN state includes WAN mode/port count, IPv4/IPv6 connection state and, when multiple WAN ports exist, load-balancing/link-backup behavior. Online detection is an input to multi-WAN behavior and must therefore be modeled separately from configured link state.

For IPv4 the documented connection families include Dynamic IP, Static IP, PPPoE, L2TP and PPTP; IPv6 includes Dynamic IP (SLAAC/DHCPv6), Static IP, PPPoE, 6to4 and Pass-Through/Bridge. Secrets such as PPP credentials are references only and are never persisted in evidence.

LAN networks have two distinct purposes: `Interface` creates an L3 VLAN interface for routing, while `VLAN` is L2-only. The default LAN uses VLAN 1 and is editable but not deletable. Port-profile binding is a separate activation plane.

WAN Settings Override and WAN-port-count changes can disrupt connectivity or trigger reboot after adoption, so a successful Apply remains `EXECUTED_UNVERIFIED`. PASS requires fresh read-back plus upstream, management and representative LAN-path checks.
