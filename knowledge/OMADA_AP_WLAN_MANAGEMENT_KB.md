# Omada AP / WLAN Management — Task 7.09

Omada Controller separates site WLAN groups from per-AP WLAN overrides. Adopted APs receive WLAN configuration from their site/group, while a single AP can override SSID-related settings where supported. The effective WLAN state therefore cannot be inferred from the site object alone.

Radio state is per band: status, wireless mode, channel width, channel and transmit power are separate operational parameters. Actual available values depend on model, band, region and regulatory limits. Disabling a band removes service on that radio and is treated as an impact-bearing write.

Mesh is another operational plane. It applies only to supported APs and same-site topology, and wireless uplink state must not be conflated with normal wired adoption. PASS requires effective WLAN and override read-back, radio state, AP Connected status, management health, expected SSID visibility, representative client association/data access, and mesh/uplink health where applicable.
