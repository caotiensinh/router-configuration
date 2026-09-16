# Omada Controller Backup / Restore / Migration — Task 7.12

## Reuse boundary

Task 7.12 specializes the already verified 4.19 controller backup/restore/migration contract. It does **not** create a second backup engine and does not include device firmware-upgrade semantics.

## Official-source facts

Current Omada documentation separates **Site Migration** from **Controller Migration**. Site migration exports/imports one site and then migrates its devices; controller migration moves the whole controller scope. Current guidance requires validating the target controller and verifying migrated devices are visible and `Connected` before finishing source-side cleanup. The guide also warns that Internet connectivity can be interrupted for several minutes during migration.

Version compatibility is an admission gate, not an assumption. The currently published guide describes same-version constraints for migration workflows; older controller guidance additionally documents major/minor compatibility rules for certain versions. Automation therefore records exact source and target version/build and fails closed when compatibility is unverified.

## Safety

A migration window, source backup, exact target Controller IP/Inform URL, and recovery path are mandatory. `Forget Devices` or equivalent source cleanup is always after target-side connected-state verification.

PASS requires backup provenance, source/target version evidence, successful import/restore, target controller health, intended configuration, connected managed devices, and representative client/service health.
