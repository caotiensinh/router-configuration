# Omada Central / Cloud Differences — Task 7.14

## Official sources
- Controller comparison, updated 2026-08-21: https://support.omadanetworks.com/ec/document/13150/
- Omada Cloud-Based Controller / networking module of Omada Central: https://support.omadanetworks.com/en/product/omada-cloud-based-controller/
- Japan Omada Central: https://support.omadanetworks.com/jp/product/omada-central/
- Japan Omada Central Essentials: https://support.omadanetworks.com/jp/product/omada-central-essentials/

## Required distinctions
- `Cloud Access` is remote access to a customer-side on-premises or integrated controller. It is not the same architecture as a Cloud-Based Controller.
- On-premises Hardware/Software Controllers keep the controller service, configuration, logs, backup responsibility, availability, updates, and host security on customer-managed infrastructure.
- Omada Cloud-Based Controller is vendor-hosted; managed devices communicate to the cloud platform and management depends on internet connectivity.
- Omada Cloud Standard and Omada Cloud Essentials share cloud-hosted architecture but are different service tiers.
- The official comparison describes Cloud Standard as the more comprehensive tier with MSP Mode and device licensing.
- Cloud Essentials is free/simplified and does not support MSP Mode.
- Integrated Gateways keep the controller service local while optionally supporting Cloud Access; they are not equivalent to the Cloud-Based Controller.

## Automation contract
Normalize architecture, service location, ownership boundary, connectivity dependency, licensing, MSP support, backup/update responsibility, feature surface, device compatibility, and region separately. Never infer feature parity across tiers or controller families from a shared UI label.

Unknown current feature parity is `NOT_SUPPORTED_UNVERIFIED`. Migration is not PASS until target-side device/state reconciliation is fresh and complete.
