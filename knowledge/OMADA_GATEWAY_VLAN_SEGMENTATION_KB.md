# Omada Gateway VLAN / Network Segmentation — Task 5.02

Current Omada Controller guidance models wired segmentation with 802.1Q LAN networks. `Interface` creates an L3 VLAN interface used for inter-VLAN routing, while `VLAN` is L2-only. Wired membership is activated through port profiles bound to switch ports; wireless VLAN tagging is a separate plane.

Segmentation policy is not equivalent to creating VLAN IDs. Where communication must be restricted, ACL state and binding are explicit. Controller ACL rules are ordered and first-match; Switch ACL takes effect only after binding to ports or a VLAN. The default no-match behavior documented by the guide is permit, so policy verification must include representative negative traffic.

Management VLAN, default VLAN 1, user/client VLANs and ACL policy remain separate state planes. Any change that could move or block the management path requires pre-change reachability analysis and fresh post-change read-back. Apply remains `EXECUTED_UNVERIFIED` until both intended reachability and intended isolation are proven.
