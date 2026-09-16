# Omada Security / Compliance Technical Mapping — Task 10.10

## Public authority anchors
- NIST Cybersecurity Framework 2.0: https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20
- CIS Controls v8.1: https://www.cisecurity.org/controls
- CIS Control 12 Network Infrastructure Management: https://www.cisecurity.org/controls/network-infrastructure-management
- PCI SSC FAQ describing PCI DSS Requirement 1 network security controls: https://www.pcisecuritystandards.org/faqs/1076/
- ISO/IEC 27001:2022 public standard overview: https://www.iso.org/standard/27001

## Mapping rule
A technical mapping is evidence organization, not a certification, audit result, attestation, or guarantee of compliance.

- NIST CSF 2.0 provides cybersecurity-risk outcomes and does not prescribe a single implementation.
- CIS Controls v8.1 is prescriptive guidance; Omada evidence can support relevant safeguards such as vulnerability management, network infrastructure management, and network monitoring/defense.
- PCI DSS Requirement 1 is relevant only when a cardholder-data environment or applicable payment scope is explicitly established. Network security controls such as firewalls are only one part of PCI DSS.
- ISO/IEC 27001:2022 defines ISMS requirements. Exact clause/control mappings must use authoritative licensed text or an organization-provided approved mapping; this project must not invent non-public control wording.

## Automation contract
Every row binds: framework/version, applicability, project control domain, exact configuration/evidence references, verification freshness, deviations, and claim level. Vendor capability does not equal organization policy, and policy does not equal verified implementation.

Unknown version, applicability, or evidence => `MAPPING_UNVERIFIED`.
Any attempt to turn a technical mapping into an automatic compliance/certification claim => `REJECTED`.
