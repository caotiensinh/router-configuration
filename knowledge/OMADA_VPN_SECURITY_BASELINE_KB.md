# Omada VPN Security Baseline — Task 10.7

Current Omada Controller V6.2 documentation exposes separate VPN server, VPN client and site-to-site workflows, with documented protocol families including WireGuard, OpenVPN, IPsec, SSL VPN, L2TP and PPTP. VPN status is a separate operational read-back plane. Exact availability remains gateway/model/firmware/region/controller-version dependent.

Vendor capability is separate from project security policy. The project prefers modern proven-compatible protocols, does not authorize PPTP for new sensitive deployments, applies least privilege to routes/allowed networks, and never persists private keys, PSKs, passwords or tokens in evidence.

Creating a tunnel is only `EXECUTED_UNVERIFIED`. PASS requires secret-free profile/tunnel binding read-back, operational tunnel/SA state where applicable, expected routes/allowed networks, a positive authorized flow, a negative non-allowed flow, and healthy management plus unaffected tunnels.
