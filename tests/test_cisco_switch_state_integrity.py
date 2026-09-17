import unittest
from dataclasses import replace

from router_configuration.vendors.cisco.switch_state import normalize_switch_state
from router_configuration.vendors.cisco.switch_state_integrity import (
    CiscoSwitchStateIntegrityError,
    verify_switch_state_integrity,
)

MODULES = {
    "Cisco-IOS-XE-interfaces-oper",
    "Cisco-IOS-XE-vlan-oper",
    "Cisco-IOS-XE-matm-oper",
    "Cisco-IOS-XE-spanning-tree-oper",
    "openconfig-interfaces",
    "openconfig-if-ethernet",
    "openconfig-vlan",
    "openconfig-vlan-types",
}
SCHEMA_DIGEST = "a" * 64


def normalized_state():
    return normalize_switch_state(
        model="C9300-24T",
        iosxe_version="17.18.1a",
        schema_inventory_digest_sha256=SCHEMA_DIGEST,
        observed_modules=MODULES,
        interface_records=[
            {"name": "GigabitEthernet1/0/1", "admin-status": "if-state-up", "oper-status": "if-oper-state-ready"}
        ],
        vlan_records=[
            {"id": 10, "name": "users", "status": "active", "ports": [{"interface": "GigabitEthernet1/0/1"}], "vlan-interfaces": []}
        ],
        mac_records=[
            {"table-type": "mat-vlan", "vlan-id-number": 10, "mac": "00:11:22:33:44:55", "mat-addr-type": "dynamic", "port": "GigabitEthernet1/0/1", "vlan-all": False}
        ],
        stp_records=[
            {
                "instance": "10",
                "bridge-priority": 32768,
                "bridge-address": "00:11:22:33:44:55",
                "designated-root-priority": 32768,
                "designated-root-address": "00:11:22:33:44:55",
                "root-port": 1,
                "root-cost": 0,
                "topology-changes": 1,
                "interfaces": [
                    {"name": "GigabitEthernet1/0/1", "role": "stp-designated", "state": "stp-forwarding", "cost": 4, "port-priority": 128, "port-num": 1}
                ],
            }
        ],
        trunk_records=[
            {"interface": "GigabitEthernet1/0/1", "interface-mode": "TRUNK", "native-vlan": 1, "trunk-vlans": [10, "20..22"]}
        ],
    )


class CiscoSwitchStateIntegrityTests(unittest.TestCase):
    def test_normalized_switch_state_integrity_is_non_promoting(self):
        record = verify_switch_state_integrity(normalized_state())
        self.assertTrue(record["normalized_state_integrity_valid"])
        self.assertTrue(record["trunk_state_verified"])
        self.assertEqual(record["switched_vlan_count"], 1)
        self.assertFalse(record["live_state_observed"])
        self.assertFalse(record["repository_c06_complete"])
        self.assertEqual(len(record["integrity_record_sha256"]), 64)

    def test_tampered_state_digest_is_rejected(self):
        with self.assertRaisesRegex(CiscoSwitchStateIntegrityError, "digest mismatch"):
            verify_switch_state_integrity(replace(normalized_state(), state_digest_sha256="9" * 64))

    def test_inconsistent_trunk_flags_are_rejected(self):
        with self.assertRaisesRegex(CiscoSwitchStateIntegrityError, "trunk contract flags"):
            verify_switch_state_integrity(replace(normalized_state(), c06_contract_complete=False))

    def test_self_completion_or_physical_claim_is_rejected(self):
        with self.assertRaisesRegex(CiscoSwitchStateIntegrityError, "self-assert"):
            verify_switch_state_integrity(replace(normalized_state(), c06_complete=True))
        with self.assertRaisesRegex(CiscoSwitchStateIntegrityError, "safety boundary"):
            verify_switch_state_integrity(replace(normalized_state(), physical_device_verified=True))


if __name__ == "__main__":
    unittest.main()
