# Omada Gateway Policy Routing — Task 5.05

Current Omada Controller guidance defines Policy Routing as a gateway/site routing object that selects a WAN based on traffic source, destination and protocol. `Network`, `IP Group`, and `IP-Port Group` are distinct selector types. A rule can explicitly enable use of another WAN when its selected WAN is down.

Policy Routing is not normalized as Static Route or as generic Multi-WAN/load balancing. Before any write, the automation must analyze rule overlap and management/controller traffic impact and must not invent precedence between routing planes without exact controller-version evidence.

A successful controller write remains `EXECUTED_UNVERIFIED`. PASS requires exact rule read-back, representative matching-flow WAN behavior, a non-matching control flow, fallback behavior when configured and safely testable, and healthy controller/management reachability.
