# Execution Policy

`MASTER_RULES.md` is authoritative.

No production write may occur until current state, desired state, diff, dependencies, conflicts, management path, rollback, verification criteria, backup, and changeset-specific human approval are established.

Preferred execution is STEP -> APPLY -> READ BACK -> VERIFY -> NEXT STEP. Important failures stop further changes. Rollback success must itself be verified.

A successful command response is not deployment success. Completion requires actual-state verification against desired state and vendor-expected behavior, post-change backup, evidence, and handover artifacts.