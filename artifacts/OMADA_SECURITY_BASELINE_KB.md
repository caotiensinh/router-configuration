# TP-Link / Omada Official Security Guidance Baseline — Task 10.1

The security baseline is evidence-driven, not a static list of “secure defaults.” TP-Link maintains official security-advisory indexes and currently lists Omada-specific controller, gateway and device advisories. The automation must continuously match those advisories to the exact managed inventory rather than infer safety from a product family name or a generic “latest firmware” label.

## State model

- `APPLICABLE_UNREMEDIATED`: exact affected identity/version evidence matches and the vendor remediation condition is not yet satisfied.
- `NOT_APPLICABLE_VERIFIED`: authoritative scope evidence excludes the exact product/version.
- `REMEDIATED_VERIFIED`: the vendor fixed-version/workaround condition is satisfied and exact post-change state is verified.
- `UNKNOWN_APPLICABILITY`: evidence is incomplete or ambiguous; fail closed.

The current TP-Link SMB advisory index includes, among others, advisory 5287 for CVE-2026-81531 affecting multiple Omada Controllers and advisory 5256 for multiple Omada Gateway vulnerabilities. These examples prove that controller and gateway security state must be version-scoped; they do not establish that every Omada product is affected.

## Management-plane baseline

Where the exact controller type supports it, use a valid HTTPS certificate and keep controller-management access distinct from portal access. Do not export credentials, private keys or secret material to logs or reports. Reduce management exposure according to the deployment's supported access controls rather than inventing unsupported firewall behavior.

Any remediation upgrade must first pass the firmware/controller compatibility gate and have a pre-change backup. A write is only `EXECUTED_UNVERIFIED`; PASS requires exact fixed-state read-back and healthy management/network behavior.
