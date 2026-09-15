import unittest

from router_configuration.vendors.cisco.switch_state import (
    CiscoSwitchStateError,
    load_switch_state_catalog,
    normalize_switch_state,
    switch_state_catalog_digest,
)


MODULES = {
    "Cisco-IOS-XE-interfaces-oper",
    "Cisco-IOS-XE-vlan-oper",
    "Cisco-IOS-XE-matm-oper",
    "Cisco-IOS-XE-spanning-tree-oper",
}
SCHEMA_DIGEST = "b" * 64


class CiscoSwitchNormalizedStateTests(unittest.TestCase):
    def _interfaces(self):
        return [
            {"name": "GigabitEthernet1/0/1", "admin-status": "if-state-up", "oper-status": "if-oper-state-ready"},
            {"name": "GigabitEthernet1/0/2", "admin-status": "if-state-up", "oper-status": "if-oper-state-ready"},
        ]

    def _vlans(self):
        return [
            {
                "id": 10,
                "name": "USERS",
                "status": "active",
                "ports": [{"interface": "GigabitEthernet1/0/1", "subinterface": 0}],
                "vlan-interfaces": [{"interface": "Vlan10", "subinterface": 0}],
            },
            {"id": 20, "name": "CAMERA", "status": "active", "ports": [], "vlan-interfaces": []},
        ]

    def _mac(self):
        return [
            {"table-type": "mat-vlan", "vlan-id-number": 10, "mac": "00:11:22:33:44:55", "mat-addr-type": "dynamic", "port": "GigabitEthernet1/0/1"},
            {"table-type": "mat-vlan", "vlan-id-number": 20, "mac": "AA:BB:CC:DD:EE:FF", "mat-addr-type": "static", "port": "GigabitEthernet1/0/2"},
        ]

    def _stp(self):
        return [
            {
                "instance": "VLAN0010",
                "bridge-priority": 32768,
                "bridge-address": "00:11:22:33:44:00",
                "designated-root-priority": 24576,
                "designated-root-address": "00:11:22:33:44:01",
                "root-port": 1,
                "root-cost": 4,
                "topology-changes": 2,
                "interfaces": [
                    {"name": "GigabitEthernet1/0/1", "role": "stp-root", "state": "stp-forwarding", "cost": 4, "port-priority": 128, "port-num": 1},
                    {"name": "GigabitEthernet1/0/2", "role": "stp-designated", "state": "stp-forwarding", "cost": 4, "port-priority": 128, "port-num": 2},
                ],
            }
        ]

    def _normalize(self, **overrides):
        values = dict(
            model="C9300-24T",
            iosxe_version="17.18.1a",
            schema_inventory_digest_sha256=SCHEMA_DIGEST,
            observed_modules=MODULES,
            interface_records=self._interfaces(),
            vlan_records=self._vlans(),
            mac_records=self._mac(),
            stp_records=self._stp(),
        )
        values.update(overrides)
        return normalize_switch_state(**values)

    def test_catalog_is_pinned_read_only_live_gated_and_trunk_unverified(self):
        catalog = load_switch_state_catalog()
        self.assertEqual(catalog["role"], "switch")
        self.assertFalse(catalog["write_authorized"])
        self.assertFalse(catalog["physical_device_verified"])
        self.assertFalse(catalog["synthetic_fixture_can_complete_c06"])
        self.assertTrue(catalog["live_state_evidence_required_for_c06"])
        self.assertFalse(catalog["trunk_state_verified"])
        self.assertEqual(set(catalog["documentation_trains"]), {"17.18", "26"})
        self.assertEqual(len(switch_state_catalog_digest()), 64)

    def test_switch_state_normalizes_deterministically(self):
        first = self._normalize()
        second = self._normalize(
            observed_modules=reversed(sorted(MODULES)),
            interface_records=list(reversed(self._interfaces())),
            vlan_records=list(reversed(self._vlans())),
            mac_records=list(reversed(self._mac())),
            stp_records=list(reversed(self._stp())),
        )
        self.assertEqual(first.state_digest_sha256, second.state_digest_sha256)
        self.assertEqual(first.platform_family, "Catalyst 9300")
        self.assertEqual(first.documentation_train, "17.18")
        self.assertEqual(first.vlans[0].vlan_id, 10)
        self.assertEqual(first.mac_entries[1].mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(first.stp_instances[0].interfaces[0].role, "stp-root")
        self.assertFalse(first.trunk_state_verified)
        self.assertFalse(first.c06_complete)
        self.assertFalse(first.production_write_authorized)
        self.assertFalse(first.physical_device_verified)

    def test_iosxe_26_switch_is_source_bound(self):
        state = self._normalize(model="C9500-24Y4C", iosxe_version="26.1.1")
        self.assertEqual(state.documentation_train, "26")
        self.assertEqual(state.platform_family, "Catalyst 9500")

    def test_router_model_is_rejected_from_switch_lane(self):
        with self.assertRaises(CiscoSwitchStateError):
            self._normalize(model="C8300-2N2S-6T")

    def test_missing_module_or_inventory_digest_fails_closed(self):
        with self.assertRaisesRegex(CiscoSwitchStateError, "required YANG modules"):
            self._normalize(observed_modules=MODULES - {"Cisco-IOS-XE-matm-oper"})
        with self.assertRaisesRegex(CiscoSwitchStateError, "inventory digest"):
            self._normalize(schema_inventory_digest_sha256="bad")

    def test_vlan_schema_keys_and_status_are_enforced(self):
        duplicate = self._vlans() + [dict(self._vlans()[0])]
        with self.assertRaisesRegex(CiscoSwitchStateError, "duplicate VLAN id"):
            self._normalize(vlan_records=duplicate)
        broken = self._vlans()
        broken[0]["status"] = "mostly-active"
        with self.assertRaisesRegex(CiscoSwitchStateError, "VLAN status"):
            self._normalize(vlan_records=broken)
        broken = self._vlans()
        broken[0]["id"] = 70000
        with self.assertRaisesRegex(CiscoSwitchStateError, "unsigned integer"):
            self._normalize(vlan_records=broken)

    def test_vlan_port_duplicate_fails_closed(self):
        broken = self._vlans()
        broken[0]["ports"].append(dict(broken[0]["ports"][0]))
        with self.assertRaisesRegex(CiscoSwitchStateError, "duplicate vlan.ports"):
            self._normalize(vlan_records=broken)

    def test_matm_vlan_key_type_and_mac_are_enforced(self):
        duplicate = self._mac() + [dict(self._mac()[0])]
        with self.assertRaisesRegex(CiscoSwitchStateError, "duplicate MATM"):
            self._normalize(mac_records=duplicate)
        broken = self._mac()
        broken[0]["table-type"] = "mat-vlan-independent"
        with self.assertRaisesRegex(CiscoSwitchStateError, "mat-vlan"):
            self._normalize(mac_records=broken)
        broken = self._mac()
        broken[0]["mac"] = "not-a-mac"
        with self.assertRaisesRegex(CiscoSwitchStateError, "invalid MAC"):
            self._normalize(mac_records=broken)

    def test_stp_instance_interface_keys_and_enums_are_enforced(self):
        duplicate = self._stp() + [dict(self._stp()[0])]
        with self.assertRaisesRegex(CiscoSwitchStateError, "duplicate STP instance"):
            self._normalize(stp_records=duplicate)
        broken = self._stp()
        broken[0]["interfaces"][0]["role"] = "root-ish"
        with self.assertRaisesRegex(CiscoSwitchStateError, "STP port role"):
            self._normalize(stp_records=broken)
        broken = self._stp()
        broken[0]["interfaces"].append(dict(broken[0]["interfaces"][0]))
        with self.assertRaisesRegex(CiscoSwitchStateError, "duplicate STP interface"):
            self._normalize(stp_records=broken)

    def test_sensitive_fields_are_rejected_before_normalization(self):
        broken = self._vlans()
        broken[0]["secret"] = "must-never-enter-normalized-state"
        with self.assertRaisesRegex(CiscoSwitchStateError, "sensitive field"):
            self._normalize(vlan_records=broken)


if __name__ == "__main__":
    unittest.main()
