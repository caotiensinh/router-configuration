import unittest

from router_configuration.vendors.cisco.c05_live_state_ingest import (
    CiscoC05LiveStateIngestError,
    ingest_c05_live_state_candidate,
)
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


class CiscoC05LiveStateIngestTests(unittest.TestCase):
    def test_live_candidate_binds_state_raw_artifact_and_collector(self):
        result = ingest_c05_live_state_candidate(
            normalized_state(),
            source_sha="1" * 40,
            run_id="gha:12345",
            transport="NETCONF_READONLY",
            raw_live_artifact_sha256="2" * 64,
            collector_attestation_sha256="3" * 64,
            live_target_observed=True,
        )
        self.assertTrue(result["candidate_claims_live_state"])
        self.assertTrue(result["eligible_for_repository_review"])
        self.assertFalse(result["repository_c05_complete"])
        self.assertFalse(result["physical_device_verified"])
        self.assertFalse(result["production_write_authorized"])
        self.assertEqual(len(result["ingest_record_sha256"]), 64)

    def test_non_live_or_non_readonly_transport_fails_closed(self):
        with self.assertRaisesRegex(CiscoC05LiveStateIngestError, "observed live target"):
            ingest_c05_live_state_candidate(
                normalized_state(),
                source_sha="1" * 40,
                run_id="gha:12345",
                transport="NETCONF_READONLY",
                raw_live_artifact_sha256="2" * 64,
                collector_attestation_sha256="3" * 64,
                live_target_observed=False,
            )
        with self.assertRaisesRegex(CiscoC05LiveStateIngestError, "unsupported"):
            ingest_c05_live_state_candidate(
                normalized_state(),
                source_sha="1" * 40,
                run_id="gha:12345",
                transport="SSH_CLI_WRITE",
                raw_live_artifact_sha256="2" * 64,
                collector_attestation_sha256="3" * 64,
                live_target_observed=True,
            )


if __name__ == "__main__":
    unittest.main()
