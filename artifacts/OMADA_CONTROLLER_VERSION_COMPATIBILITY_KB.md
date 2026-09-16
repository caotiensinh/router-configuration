# Omada Controller Version Compatibility

**Task:** 7.04  
**Status:** COMPLETE candidate for current official evidence scope  
**Observed:** 2026-09-16

Compatibility is evaluated on a full tuple: **controller platform + exact controller version/build + device model + hardware revision + region + device firmware + required feature**. The 6.1.0 release notes explicitly warn that controllers on different platforms may differ in features even when the first three version digits match. They also state that the controller can manage only certain devices running supported firmware.

The same release notes demonstrate why feature compatibility is a separate gate: multiple 6.1 features (including RF optimization, switch diagnostic tools, VRF, global LLDP and DHCP Snooping) require device firmware upgrades. Therefore a compiler must never infer feature support from controller version alone.

The release note's Omada App 5.0.x compatibility statement is kept separate from controller-device compatibility. Unknown tuples fail closed rather than being treated as supported.

For upgrades, preserve a controller backup and recovery path, resolve the exact target platform/build, verify the compatibility list and device-firmware prerequisites, and verify the migration path. The cited 6.1.0 software release notes also state that since controller 5.14.32, upgrading from Controller v4 is no longer supported.

The release-note PDF was parsed successfully. Screenshot attempts were required and made, but the web cache returned a cache miss, so visual verification remains false.
