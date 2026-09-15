from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


class GovernanceError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass(frozen=True)
class GovernanceSnapshot:
    root: Path
    master_rules_sha256: str
    agents_sha256: str
    scoped_rule_sha256: tuple[tuple[str, str], ...]
    vendor_rule_sha256: tuple[tuple[str, str], ...]

    @property
    def all_rule_hashes(self) -> tuple[str, ...]:
        return (
            self.master_rules_sha256,
            self.agents_sha256,
            *(digest for _, digest in self.scoped_rule_sha256),
            *(digest for _, digest in self.vendor_rule_sha256),
        )


@dataclass(frozen=True)
class GovernanceAcknowledgement:
    master_rules_sha256: str
    agents_sha256: str
    scoped_rule_sha256: tuple[tuple[str, str], ...]
    vendor_rule_sha256: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class GovernanceAuthorization:
    authorized_for_project_work: bool
    authorized_for_repository_write: bool
    authorized_for_production_execution: bool
    blockers: tuple[str, ...]
    snapshot: GovernanceSnapshot


def load_governance_snapshot(
    root: str | Path,
    *,
    vendors: Iterable[str] = (),
) -> GovernanceSnapshot:
    base = Path(root).resolve()
    master = base / "MASTER_RULES.md"
    agents = base / "AGENTS.md"
    if not master.is_file():
        raise GovernanceError("MASTER_RULES_MISSING")
    if not agents.is_file():
        raise GovernanceError("AGENTS_RULE_MISSING")

    policies = tuple(
        sorted(
            path
            for path in (base / "governance").glob("*.md")
            if path.is_file()
        )
    )
    if not policies:
        raise GovernanceError("SCOPED_RULES_MISSING")

    vendor_entries: list[tuple[str, str]] = []
    for vendor in sorted({str(item).strip().lower() for item in vendors if str(item).strip()}):
        path = base / "vendors" / vendor / "VENDOR_RULES.md"
        if not path.is_file():
            raise GovernanceError(f"VENDOR_RULES_MISSING:{vendor}")
        vendor_entries.append((str(path.relative_to(base)), _sha256(path)))

    return GovernanceSnapshot(
        root=base,
        master_rules_sha256=_sha256(master),
        agents_sha256=_sha256(agents),
        scoped_rule_sha256=tuple((str(path.relative_to(base)), _sha256(path)) for path in policies),
        vendor_rule_sha256=tuple(vendor_entries),
    )


def acknowledge(snapshot: GovernanceSnapshot) -> GovernanceAcknowledgement:
    """Bind an acknowledgement to the exact repository rule bytes.

    The caller must only invoke this after actually reviewing the referenced rules.
    This function cannot prove comprehension; it prevents a stale acknowledgement
    from remaining valid after governance files change.
    """

    return GovernanceAcknowledgement(
        master_rules_sha256=snapshot.master_rules_sha256,
        agents_sha256=snapshot.agents_sha256,
        scoped_rule_sha256=snapshot.scoped_rule_sha256,
        vendor_rule_sha256=snapshot.vendor_rule_sha256,
    )


def authorize(
    snapshot: GovernanceSnapshot,
    acknowledgement: GovernanceAcknowledgement | None,
    *,
    execution_policy_passed: bool = False,
    approval_received: bool = False,
) -> GovernanceAuthorization:
    blockers: list[str] = []
    if acknowledgement is None:
        blockers.append("MASTER_RULES_NOT_ACKNOWLEDGED")
    elif acknowledgement != acknowledge(snapshot):
        blockers.append("STALE_OR_MISMATCHED_GOVERNANCE_ACKNOWLEDGEMENT")

    project_ok = not blockers
    repository_write = project_ok
    production = project_ok and execution_policy_passed and approval_received
    if project_ok and not execution_policy_passed:
        blockers.append("EXECUTION_POLICY_NOT_PASSED")
    if project_ok and not approval_received:
        blockers.append("PRODUCTION_APPROVAL_NOT_RECEIVED")

    return GovernanceAuthorization(
        authorized_for_project_work=project_ok,
        authorized_for_repository_write=repository_write,
        authorized_for_production_execution=production,
        blockers=tuple(blockers),
        snapshot=snapshot,
    )


def require_repository_write(auth: GovernanceAuthorization) -> None:
    if not auth.authorized_for_repository_write:
        raise GovernanceError("WORK_NOT_AUTHORIZED:" + ",".join(auth.blockers))


def require_production_execution(auth: GovernanceAuthorization) -> None:
    if not auth.authorized_for_production_execution:
        raise GovernanceError("PRODUCTION_EXECUTION_NOT_AUTHORIZED:" + ",".join(auth.blockers))
