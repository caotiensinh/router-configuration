import unittest

from router_configuration.vendors.cisco.c05_acceptance_decision import (
    CiscoC05AcceptanceDecisionError,
    bind_c05_repository_decision,
)
from router_configuration.vendors.cisco.c05_live_state_ingest import ingest_c05_live_state_candidate
from router_configuration.vendors.cisco.router_state import normalize_router_state

MODULES = {"Cisco-IOS-XE-interfaces-oper", "ietf-routing"}
SCHEMA_DIGEST = "a" * 64


def normalized_state():
    return normalize_router_state(
        model="C8000V",
        iosxe_version="17.18.1a",
        schema_inventory_digest_sha256=SCHEMA_DIGEST,
        observed_modules=MODULES,
        interface_records=[
            {
                "name": "GigabitEthernet1",
                "vrf": "default",
                "admin-status": "if-state-up",
                "oper-status": "if-oper-state-ready",
                "ipv4": "192.0.2.10",
                "ipv4-subnet-mask": "255.255.255.0",
                "ipv6-addrs": ["2001:db8::10"],
            }
        ],
        route_records=[
            {
                "destination-prefix": "0.0.0.0/0",
                "source-protocol": "static",
                "route-preference": 1,
                "metric": 10,
                "next-hop": {
                    "outgoing-interface": "GigabitEthernet1",
                    "next-hop-address": "192.0.2.1",
                },
                "active": True,
            }
        ],
    )


def candidate():
    return ingest_c05_live_state_candidate(
        normalized_state(),
        source_sha="1" * 40,
        run_id="gha:12345",
        transport="NETCONF_READONLY",
        raw_live_artifact_sha256="2" * 64,
        collector_attestation_sha256="3" * 64,
        live_target_observed=True,
    )


class CiscoC05AcceptanceDecisionTests(unittest.TestCase):
    def test_accept_binds_exact_candidate_without_crossing_safety_boundaries(self):
        result = bind_c05_repository_decision(
            candidate(),
            decision_id="C05-DECISION-001",
            authority_ref="reviewer:network-acceptance",
            authority_attestation_sha256="4" * 64,
            decision="accept",
        )
        self.assertTrue(result["repository_live_evidence_accepted"])
        self.assertTrue(result["repository_c05_complete"])
        self.assertFalse(result["physical_device_verified"])
        self.assertFalse(result["production_write_authorized"])
        self.assertEqual(result["source_sha"], "1" * 40)
        self.assertEqual(result["raw_live_artifact_sha256"], "2" * 64)
        self.assertEqual(result["collector_attestation_sha256"], "3" * 64)
        self.assertEqual(len(result["decision_record_sha256"]), 64)

    def test_reject_is_recorded_without_completing_c05(self):
        result = bind_c05_repository_decision(
            candidate(),
            decision_id="C05-DECISION-002",
            authority_ref="reviewer:network-acceptance",
            authority_attestation_sha256="4" * 64,
            decision="reject",
        )
        self.assertFalse(result["repository_live_evidence_accepted"])
        self.assertFalse(result["repository_c05_complete"])
        self.assertFalse(result["production_write_authorized"])

    def test_tampered_candidate_fails_closed(self):
        item = candidate()
        item["model"] = "C8300"
        with self.assertRaisesRegex(CiscoC05AcceptanceDecisionError, "digest mismatch"):
            bind_c05_repository_decision(
                item,
                decision_id="C05-DECISION-003",
                authority_ref="reviewer:network-acceptance",
                authority_attestation_sha256="4" * 64,
                decision="accept",
            )

    def test_self_promoted_candidate_fails_closed_even_with_recomputed_digest_absent(self):
        item = candidate()
        item["repository_c05_complete"] = True
        with self.assertRaises(CiscoC05AcceptanceDecisionError):
            bind_c05_repository_decision(
                item,
                decision_id="C05-DECISION-004",
                authority_ref="reviewer:network-acceptance",
                authority_attestation_sha256="4" * 64,
                decision="accept",
            )

    def test_invalid_decision_or_attestation_fails_closed(self):
        with self.assertRaisesRegex(CiscoC05AcceptanceDecisionError, "unsupported C05 decision"):
            bind_c05_repository_decision(
                candidate(),
                decision_id="C05-DECISION-005",
                authority_ref="reviewer:network-acceptance",
                authority_attestation_sha256="4" * 64,
                decision="approve",
            )
        with self.assertRaisesRegex(CiscoC05AcceptanceDecisionError, "lowercase SHA-256"):
            bind_c05_repository_decision(
                candidate(),
                decision_id="C05-DECISION-006",
                authority_ref="reviewer:network-acceptance",
                authority_attestation_sha256="bad",
                decision="accept",
            )


if __name__ == "__main__":
    unittest.main()
