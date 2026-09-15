# Omada Phase-3 Official Source-Class Cross-Check

**Task:** 3.13 — Cross-check against datasheet + hardware guide + compatibility source  
**Observed:** 2026-09-15  
**Status:** PASS with explicit source-class gaps retained

## Coverage

- Exact IDs evaluated: **230/230**.
- Datasheet/specification or exact product-spec evidence already present in persisted Phase-3 artifacts: **230/230**.
- Compatibility/support applicability evidence already reviewed in Phase 3.8: **230/230**.
- Exact/example model matches observed in the current official Hardware Installation Guide portal during this cross-check: **14**.
- Remaining IDs without an exhaustively persisted exact HIG link: **216**. This is a source-class evidence gap, **not** an unsupported-device result.

## Mandatory semantics

- Datasheet/specification, Hardware Installation Guide, and Compatibility/Support are independent source classes; one cannot silently substitute for another.
- Missing HIG linkage does not block facts already proven by the appropriate specification/compatibility source class, but it blocks installation-only facts that require HIG evidence.
- Existing revision/region/firmware/controller conflicts remain fail-closed; 3.13 does not resolve them by majority vote.
- A family/example guide applies only to models/revisions actually named or explicitly covered.
- Current catalog/support presence is not lifecycle evidence.

## Current official HIG portal observations

- `EAP787` — EAP787(US)_V2.6_Installation Guide.
- `Sector Bridge 5` — Sector Bridge 5_V1/V1.6_Installation Guide.
- `Beam Bridge 7 KIT` — Beam Bridge 7 KIT_V1/V1.6_Installation Guide.
- `Omada 5MP Bullet` — Omada Bullet PoE Security Camera_Installation Guide (5MP Bullet used for example).
- `Omada 5MP Turret` — Omada Turret PoE Security Camera_Installation Guide (5MP Turret used for example).
- `Omada 8MP Bullet` — Omada Bullet PoE Security Camera_Installation Guide (8MP Bullet used for example).
- `Omada 8MP Turret` — Omada Turret PoE Security Camera_Installation Guide (8MP Turret used for example).
- `EAP772-Outdoor` — Indoor/Outdoor Access Point_Quick Installation Guide (EAP772-Outdoor used for example).
- `EAP650 D120-Outdoor` — Indoor/Outdoor Access Point_Quick Installation Guide (EAP650 D120-Outdoor used for example).
- `EAP225-Outdoor` — Indoor/Outdoor Access Point_Quick Installation Guide (EAP225-Outdoor used for example).
- `EAP610-Outdoor` — Indoor/Outdoor Access Point_Quick Installation Guide (EAP610-Outdoor used for example).
- `EAP625-Outdoor HD` — Indoor/Outdoor Access Point_Quick Installation Guide (EAP625-Outdoor used for example).
- `EAP775-Outdoor` — EAP775-Outdoor_V1/V1.6_Dual-Antenna Modes (classified Hardware Installation Guide).
- `EAP725-Wall` — Wall Plate Access Point_Quick Installation Guide (EAP725-Wall used for example).

## Closure

**Task result:** 3.13 = COMPLETE for the registered Phase-3 source-cross-check scope, with exact HIG linkage gaps retained explicitly.  
**Next:** 3.14 — Mark VERIFIED only when mandatory fields are sourced.
