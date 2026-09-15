# Omada Lifecycle / EOL-EOM-EOS Status Matrix

**Task:** 3.11 — EOL/EOM/EOS status  
**Observed:** 2026-09-15  
**Status:** COMPLETE for the registered **US Business EOL List V8** source scope

## Lifecycle semantics

- Lifecycle evidence is bound to exact model + hardware/revision + region when TP-Link publishes a revision-scoped row.
- A revision-specific EOS notice does **not** make every revision of that model EOS.
- No exact row in the reviewed EOL list means **UNKNOWN**, not CURRENT.
- Current catalog/support/download presence is independent evidence and never overrides an exact lifecycle notice.
- Legacy aliases are not inherited across identifiers.

## Official source scope

- TP-Link EOL bulletin: `https://support.omadanetworks.com/us/bulletin/14106/?app=omada`
- Business list: `https://static.tp-link.com/upload/manual/2026/202606/20260624/US%20EOL%20List_Business_V8.pdf`
- TP-Link states the EOL list is continually updated and may change without notice.
- The reviewed Business list uses `Models`, `Regional Specifications`, `Version`, `EOS Notification Date`, and `EOS Date` fields.
- This task closes the registered US-source scope; it does not claim exhaustive worldwide lifecycle coverage.

## Coverage

- Registered exact identifiers reviewed: **230/230**.
- Exact model IDs with one or more exact EOL-list rows: **21**.
- Exact revision-level EOS rows retained: **44**.
- Exact model IDs with no exact row in the reviewed US Business list: **209** — retained as lifecycle `UNKNOWN`, not CURRENT.

## Exact registered IDs with revision-scoped EOS evidence

- `ER7212PC` — UN V1.6 → EOS 2026-03-05.
- `ER605` — UN V2.20 → EOS 2026-02-26; UN V2.26 → EOS 2026-02-26.
- `DS105X` — UN V2.6 → EOS 2026-03-05.
- `DS108G-M2` — UN V1.0 → EOS 2026-03-27; UN V1.6 → EOS 2026-03-27.
- `SG2210MP` — UN V5.6 → EOS 2026-03-27.
- `SG3428MP` — UN V6.20 → EOS 2026-03-27; UN V6.26 → EOS 2026-03-27.
- `SG3452` — UN V1.20 → EOS 2026-03-27; UN V1.26 → EOS 2026-03-27.
- `EAP225-Outdoor` — US V3.0 → EOS 2026-02-26; US V3.6 → EOS 2026-02-26; US V3.8 → EOS 2026-02-26.
- `EAP235-Wall` — US V1.0 → EOS 2026-01-05; US V1.6 → EOS 2026-01-05.
- `EAP772-Outdoor` — US V1.0 → EOS 2026-03-27; US V1.6 → EOS 2026-03-27.
- `OC200` — UN V2.0 → EOS 2026-02-26; UN V2.6 → EOS 2026-02-26.
- `OC300` — UN V1.0 → EOS 2026-03-27; UN V1.6 → EOS 2026-03-27.
- `POE160S` — UN V3.0 → EOS 2026-03-27; UN V3.6 → EOS 2026-03-27.
- `POE260S` — UN V2.0 → EOS 2026-03-27; UN V2.6 → EOS 2026-03-27.
- `POE4824G` — UN V2.20 → EOS 2026-01-28; UN V2.26 → EOS 2026-01-28.
- `MC420L` — UN V1.6 → EOS 2026-01-05.
- `MC1400` — UN V4.20 → EOS 2026-02-26.
- `POE150S` — UN V6.20 → EOS 2026-01-28; UN V6.26 → EOS 2026-01-28.
- `SM321A` — UN V3.30 → EOS 2026-01-28.
- `TL-SG3210` — UN V3.6 → EOS 2026-01-05; UN V3.0 → EOS 2025-02-05.
- `EAP225` — US V1.0 → EOS Before 2018; US V2.0 → EOS Before 2018; US V3.0 → EOS 2023-12-16; US V3.8 → EOS 2023-08-25; US V4.0 → EOS 2025-07-01; US V4.6 → EOS 2025-07-01; US V4.8 → EOS 2025-07-01; US V5.0 → EOS 2026-03-27; US V5.6 → EOS 2026-03-27.

## High-value reconciliation

- `ER7212PC`: EOS row is **UN V1.6** only. Later V2.x tracks are not marked EOS by inheritance.
- `POE260S`: EOS rows are **UN V2.0/V2.6** only; no sibling-revision inference.
- `TL-SG3210` lifecycle rows belong to that exact legacy identifier; they are not copied to `SG3210`.
- EOL rows for `TL-SG2008`, `TL-SG2008P`, `TL-SG3428`, `TL-SG3428MP`, `TL-SG3210XHP-M2`, etc. are not silently mapped to newer/non-TL exact IDs.
- Current product/support/firmware visibility is not used to manufacture a `CURRENT` lifecycle status.

## Closure

**Task result:** PHASE 3.11 — EOL/EOM/EOS STATUS = COMPLETE for the registered US Business EOL V8 source scope.  
**Next:** 3.12 — Normalize into database schema.
