# Omada Network Segmentation Security Baseline — Task 10.4

Vendor capability and project security policy remain separate. Omada provides LAN VLAN segmentation, L3 Interface networks, Gateway/Switch/EAP ACL planes and, on supported devices, Management VLAN. The project baseline maps actual trust zones onto those verified capabilities without assuming every model supports every control.

Segmentation is flow-based, not merely VLAN-count based. Before introducing deny rules, enumerate required infrastructure and management flows such as controller reachability, DHCP, DNS, NTP, authentication/RADIUS and approved server/application dependencies. ACL order and binding are part of the security state; a syntactically correct rule that is unbound or shadowed is not enforcement.

Broad deny rules without a flow inventory are forbidden. PASS requires positive tests for required flows, negative tests for intended isolation, exact ACL/network read-back and uninterrupted management/recovery reachability.
