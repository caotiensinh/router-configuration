# Third-Party Research and Clean-Room Policy

## Purpose

Router Configuration may study public projects, standards, vendor documentation, and technical articles to understand networking problems and general engineering patterns. The project does not use third-party repositories as a code source unless a future contribution explicitly documents and accepts the applicable license obligations.

## Default rule

**Research concepts; implement independently.**

For the current project phase:

- do not copy source code;
- do not copy router command blocks or configuration templates;
- do not translate code line-by-line into another language;
- do not preserve distinctive function/variable names, comments, directory layouts, tests, or documentation text from a reference project;
- do not import third-party source files into this repository;
- do not use a repository with no stated license as an implementation source.

## Allowed research outputs

Research may produce neutral engineering statements such as:

- desired state should be compared with actual state;
- a WAN health decision should use more than physical link state;
- load distribution should consider asymmetric link capacity;
- network writes should support dry-run, verification, and rollback;
- secret values should be kept outside Git;
- vendor-specific configuration should be isolated behind adapters.

These are problem-solving principles, not copied implementations.

## Research references for the initial ten modules

The following projects informed problem selection and architectural questions only. Their code is not incorporated into Router Configuration.

1. Ansible `community.routeros` — device automation abstraction and facts/config lifecycle.
2. Terraform RouterOS provider — desired-state and drift-management concepts.
3. `n3tuk/scripts-mikrotik` — separation of configuration data, rendering, and secret management concepts.
4. `routerOS-failoverLB` — treating load balance, failover, and traffic management as one coordinated system.
5. Public RouterOS Dual-WAN recursive failover/PCC examples — end-to-end path-health problem statement only; sources without a clear license are idea-only references.
6. `eworm-de/routeros-scripts` — operational lifecycle, monitoring, backup, and maintained security-list concepts.
7. Public MikroTik homelab policy repositories — segmentation, PBR, VPN path, and QoS problem statements.
8. Yamaha official Ansible collection — running-config/read/diff/apply/save lifecycle concepts.
9. `omada-mcp` — bounded capabilities, dry-run, and verification concepts for safe automation.
10. Omada API research toolkits — API coverage/version-compatibility problem statement; undocumented interfaces remain research-only.

## License handling

A permissive license does not automatically mean code should be copied. A copyleft license does not prevent learning general engineering concepts, but incorporating protected source may impose redistribution obligations. Sources with no license grant no general permission to copy their code.

Therefore the initial implementation is intentionally clean-room and original.

## Contribution rule

Any future contribution containing third-party code must:

1. identify the exact source and version/commit;
2. identify the license;
3. explain why incorporation is necessary;
4. preserve required notices/attribution;
5. pass repository license review before merge.

If those conditions are not met, reimplement the required behavior from a neutral specification instead.