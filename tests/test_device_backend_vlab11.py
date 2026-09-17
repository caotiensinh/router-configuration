import unittest

from router_configuration.device_backend import (
    BackendCapabilities,
    BackendContractError,
    BackendIdentity,
    EvidenceClass,
    assert_evidence_claim_allowed,
    expected_evidence_ceiling,
    validate_backend_contract,
)


class ReadOnlyBackend:
    def __init__(self, identity, ceiling, capabilities=None):
        self._identity = identity
        self._ceiling = ceiling
        self._capabilities = capabilities or BackendCapabilities()

    @property
    def identity(self):
        return self._identity

    @property
    def capabilities(self):
        return self._capabilities

    @property
    def evidence_ceiling(self):
        return self._ceiling

    def discover(self): return {"ok": True}
    def snapshot(self): return {"state": {}}
    def plan(self, desired_state): return {"desired": dict(desired_state)}
    def read_back(self): return {"state": {}}
    def verify(self, desired_state, observed_state): return {"verified": True}


class DeviceBackendVlab11Tests(unittest.TestCase):
    def test_virtual_backend_cannot_claim_hardware_verified(self):
        backend = ReadOnlyBackend(
            BackendIdentity("VirtualBackend", "virtual", "simulated-omada"),
            EvidenceClass.VIRTUAL_VERIFIED,
        )
        validate_backend_contract(backend)
        assert_evidence_claim_allowed(backend, EvidenceClass.VIRTUAL_VERIFIED)
        with self.assertRaises(BackendContractError):
            assert_evidence_claim_allowed(backend, EvidenceClass.HARDWARE_VERIFIED)

    def test_physical_backend_requires_hardware_present(self):
        identity = BackendIdentity("PhysicalDeviceBackend", "TP-Link", "ER-series", hardware_present=False)
        with self.assertRaises(BackendContractError):
            expected_evidence_ceiling(identity)

        present = BackendIdentity("PhysicalDeviceBackend", "TP-Link", "ER-series", hardware_present=True)
        self.assertEqual(expected_evidence_ceiling(present), EvidenceClass.HARDWARE_VERIFIED)

    def test_unknown_backend_kind_fails_closed(self):
        identity = BackendIdentity("MagicBackend", "unknown", "unknown")
        with self.assertRaises(BackendContractError):
            expected_evidence_ceiling(identity)

    def test_write_authority_requires_mutating_protocol(self):
        backend = ReadOnlyBackend(
            BackendIdentity("VirtualBackend", "virtual", "simulated-omada"),
            EvidenceClass.VIRTUAL_VERIFIED,
            BackendCapabilities(apply=True, rollback=True, write_authorized=True),
        )
        with self.assertRaises(BackendContractError):
            validate_backend_contract(backend)

    def test_evidence_ceiling_mismatch_is_rejected(self):
        backend = ReadOnlyBackend(
            BackendIdentity("VirtualBackend", "virtual", "simulated-omada"),
            EvidenceClass.PROTOCOL_VERIFIED,
        )
        with self.assertRaises(BackendContractError):
            validate_backend_contract(backend)


if __name__ == "__main__":
    unittest.main()
