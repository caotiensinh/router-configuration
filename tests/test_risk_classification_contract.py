from router_configuration.m02_state_engine import default_risk_classifier
from router_configuration.types import OperationKind, RiskLevel


def test_risk_classification_precedence_and_expanded_network_planes() -> None:
    cases = [
        ("management.vlan", OperationKind.UPDATE, RiskLevel.CRITICAL_CHANGE),
        ("controller_access.acl", OperationKind.UPDATE, RiskLevel.CRITICAL_CHANGE),
        ("security.acl.rule", OperationKind.CREATE, RiskLevel.NETWORK_CHANGE),
        ("site.radius.primary", OperationKind.UPDATE, RiskLevel.NETWORK_CHANGE),
        ("monitoring.snmp", OperationKind.UPDATE, RiskLevel.BOUNDED_CHANGE),
        ("power.poe", OperationKind.UPDATE, RiskLevel.BOUNDED_CHANGE),
    ]
    for path, kind, expected in cases:
        assert default_risk_classifier(path, kind, None, None) is expected


def test_unknown_mutation_is_never_classified_as_read_only() -> None:
    assert default_risk_classifier("unknown.foo", OperationKind.UPDATE, 1, 2) is RiskLevel.BOUNDED_CHANGE
    assert default_risk_classifier("unknown.foo", OperationKind.DELETE, 1, None) is RiskLevel.NETWORK_CHANGE
