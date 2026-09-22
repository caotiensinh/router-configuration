import copy
import unittest

from router_configuration.device_backend import EvidenceClass
from router_configuration.network_sandbox_acceptance import (
    NetworkSandboxAcceptanceError,
    build_network_sandbox_acceptance,
    validate_network_sandbox_acceptance,
)


ROUTER_CONFIGURATION_SHA = "503933d2cb100e05b8a181b7614c9f42d5d59e15"
NETWORK_SANDBOX_SHA = "a9658656efa3b20ae233b1be92d99fda70de4fcc"
SCENARIO_SHA256 = "1" * 64
RESULT_SHA256 = "2" * 64


class NetworkSandboxAcceptanceTests(unittest.TestCase):
    def build(self, **overrides):
        params = {
            "router_configuration_sha": ROUTER_CONFIGURATION_SHA,
            "network_sandbox_sha": NETWORK_SANDBOX_SHA,
            "network_sandbox_release": "0.6.0",
            "fidelity_level": "L2",
            "scenario_id": "dual-wan-failure-recovery",
            "scenario_sha256": SCENARIO_SHA256,
            "result_sha256": RESULT_SHA256,
            "tested_logic": ["routing", "failover", "recovery"],
            "evidence_refs": [
                "github:caotiensinh/Network_Sandbox_Runtime@a9658656efa3b20ae233b1be92d99fda70de4fcc",
                "scenario:dual-wan-failure-recovery",
            ],
            "eligible_claims": [
                "virtual_routing_behavior",
                "virtual_failover_behavior",
                "virtual_recovery_behavior",
            ],
        }
        params.update(overrides)
        return build_network_sandbox_acceptance(**params).as_dict()

    def test_l2_maps_to_virtual_verified_and_never_hardware(self):
        record = self.build()
        self.assertEqual(
            validate_network_sandbox_acceptance(record),
            EvidenceClass.VIRTUAL_VERIFIED,
        )
        self.assertEqual(record["evidence_class"], "VIRTUAL_VERIFIED")
        self.assertFalse(record["hardware_present"])
        self.assertFalse(record["hardware_verified"])
        self.assertFalse(record["physical_device_verified"])
        self.assertFalse(record["production_write_authorized"])
        self.assertFalse(record["production_writer_available"])

    def test_l3_maps_to_protocol_verified_without_hardware_promotion(self):
        record = self.build(
            fidelity_level="L3",
            eligible_claims=["protocol_packet_behavior", "protocol_recovery_behavior"],
        )
        self.assertEqual(
            validate_network_sandbox_acceptance(record),
            EvidenceClass.PROTOCOL_VERIFIED,
        )
        self.assertEqual(record["evidence_class"], "PROTOCOL_VERIFIED")
        self.assertFalse(record["hardware_verified"])

    def test_l4_vendor_golden_is_not_accepted_by_hardware_free_contract(self):
        with self.assertRaises(NetworkSandboxAcceptanceError):
            self.build(fidelity_level="L4")

    def test_hardware_or_production_claim_is_rejected(self):
        with self.assertRaises(NetworkSandboxAcceptanceError):
            self.build(eligible_claims=["hardware_verified"])

        with self.assertRaises(NetworkSandboxAcceptanceError):
            self.build(eligible_claims=["production_write_authorized"])

    def test_tampered_hardware_flag_is_rejected_before_digest_acceptance(self):
        record = self.build()
        tampered = copy.deepcopy(record)
        tampered["hardware_verified"] = True
        with self.assertRaises(NetworkSandboxAcceptanceError):
            validate_network_sandbox_acceptance(tampered)

    def test_digest_binds_cross_repo_evidence(self):
        record = self.build()
        tampered = copy.deepcopy(record)
        tampered["network_sandbox_sha"] = "f" * 40
        with self.assertRaises(NetworkSandboxAcceptanceError):
            validate_network_sandbox_acceptance(tampered)


if __name__ == "__main__":
    unittest.main()
