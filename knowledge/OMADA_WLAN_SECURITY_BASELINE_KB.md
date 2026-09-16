# Omada WLAN Security Baseline — Task 10.6

Current Omada documentation exposes `None`, OWE, WPA-Personal, WPA-Enterprise, PPSK without RADIUS and PPSK with RADIUS as distinct security strategies, subject to controller/AP/band support. Vendor capability and project security policy are separate: a mode appearing in the UI does not mean the project should use it.

For 6 GHz, TP-Link documents modern-security restrictions: PPSK and legacy WPA/WPA2 modes are not supported; WPA3-SAE and WPA3-Enterprise force PMF to Mandatory. Exact availability still depends on device model, firmware, region and controller version.

Project policy forbids unauthenticated `None` for sensitive networks, forbids storing PSKs/PPSKs/RADIUS shared secrets in evidence, and requires an explicit client-compatibility/reassociation plan before changing SSID security. The system may prefer the strongest proven-compatible mode but must not silently guess compatibility. PASS requires effective security read-back, band/security compatibility, PMF where applicable, secret-free profile bindings, positive authorized-client evidence, negative unauthorized-client evidence, and management/unaffected-WLAN health.

The V6.2 PDF result was available through search extraction, but direct PDF open failed because the document exceeded the fetch size limit; no visual screenshot verification is claimed.
