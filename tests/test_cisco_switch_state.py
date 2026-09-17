import unittest

from router_configuration.vendors.cisco.switch_state import (
    CiscoSwitchStateError,
    load_switch_state_catalog,
    normalize_switch_state,
    switch_state_catalog_digest,
)


BASE_MODULES = {
    "Cisco-IOS-XE-interfaces-oper",
    "Cisco-IOS-XE-vlan-oper",
    "Cisco-IOS-XE-matm-oper",
    "Cisco-IOS-XE-spanning-tree-oper",
}
TRUNK_MODULES = {
    "openconfig-interfaces",
    "openconfig-if-ethernet",
    "openconfig-vlan",
    "openconfig-vlan-types",
}
MODULES = BASE_MODULES | TRUNK_MODULES
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

    def _trunks(self):
        return [
            {
                "interface": "GigabitEthernet1/0/1",
                "interface-mode": "TRUNK",
                "native-vlan": 10,
                "trunk-vlans": [10, "20..22", 30],
            },
            {
                "interface": "GigabitEthernet1/0/2",
                "interface-mode": "ACCESS",
                "access-vlan": 20,
            },
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
            trunk_records=self._trunks(),
        )
        values.update(overrides)
        return normalize_switch_state(**values)

    def test_catalog_is_pinned_read_only_live_gated_and_trunk_source_bound(self):
        catalog = load_switch_state_catalog()
        self.assertEqual(catalog["role"], "switch")
        self.assertFalse(catalog["write_authorized"])
        self.assertFalse(catalog["physical_device_verified"])
        self.assertFalse(catalog["synthetic_fixture_can_complete_c06"])
        self.assertTrue(catalog["live_state_evidence_required_for_c06"])
        self.assertTrue(catalog["trunk_state_verified"])
        self.assertEqual(set(catalog["documentation_trains"]), {"17.18", "26"})
        trunk = next(item for item in catalog["observations"] if item["id"] == "switch-trunk-operational-state")
        self.assertEqual(
            trunk["schema_path"],
            "/oc-if:interfaces/oc-if:interface/oc-eth:ethernet/oc-vlan:switched-vlan/oc-vlan:state",
        )
        self.assertEqual(trunk["list_key"], "oc-if:name")
        self.assertEqual(set(trunk["required_modules"]), TRUNK_MODULES)
        self.assertEqual(trunk["interface_mode_enum"], ["ACCESS", "TRUNK"])
        self.assertEqual(trunk["vlan_id_range"], "1..4094")
        self.assertEqual(len(switch_state_catalog_digest()), 64)

    def test_switch_state_normalizes_deterministically_with_trunk_state(self):
        first = self._normalize()
        second = self._normalize(
            observed_modules=reversed(sorted(MODULES)),
            interface_records=list(reversed(self._interfaces())),
            vlan_records=list(reversed(self._vlans())),
            mac_records=list(reversed(self._mac())),
            stp_records=list(reversed(self._stp())),
            trunk_records=list(reversed(self._trunks())),
        )
        self.assertEqual(first.state_digest_sha256, second.state_digest_sha256)
        self.assertEqual(first.platform_family, "Catalyst 9300")
        self.assertEqual(first.documentation_train, "17.18")
        self.assertEqual(first.vlans[0].vlan_id, 10)
        self.assertEqual(first.mac_entries[1].mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(first.stp_instances[0].interfaces[0].role, "stp-root")
        self.assertTrue(first.trunk_state_verified)
        self.assertTrue(first.c06_contract_complete)
        self.assertFalse(first.c06_complete)
        self.assertFalse(first.production_write_authorized)
        self.assertFalse(first.physical_device_verified)
        trunk = first.switched_vlans[0]
        self.assertEqual(trunk.interface_mode, "TRUNK")
        self.assertEqual(trunk.native_vlan, 10)
        self.assertEqual(trunk.trunk_vlans, (10, 20, 21, 22, 30))
        self.assertFalse(trunk.all_vlans_allowed)
        access = first.switched_vlans[1]
        self.assertEqual(access.interface_mode, "ACCESS")
        self.assertEqual(access.access_vlan, 20)

    def test_trunk_absence_semantics_are_source_bound_and_canonical(self):
        state = self._normalize(
            trunk_records=[{"interface": "GigabitEthernet1/0/1", "interface-mode": "TRUNK"}]
        )
        self.assertEqual(state.switched_vlans[0].trunk_vlans, ())
        self.assertTrue(state.switched_vlans[0].all_vlans_allowed)

    def test_partial_contract_without_trunk_observation_stays_unverified(self):
        state = self._normalize(observed_modules=BASE_MODULES, trunk_records=None)
        self.assertFalse(state.trunk_state_verified)
        self.assertFalse(state.c06_contract_complete)
        self.assertFalse(state.c06_complete)
        self.assertEqual(state.switched_vlans, ())

    def test_iosxe_26_switch_is_source_bound(self):
        state = self._normalize(model="C9500-24Y4C", iosxe_version="26.1.1")
        self.assertEqual(state.documentation_train, "26")
        self.assertEqual(state.platform_family, "Catalyst 9500")
        self.assertTrue(state.trunk_state_verified)

    def test_router_model_is_rejected_from_switch_lane(self):
        with self.assertRaises(CiscoSwitchStateError):
            self._normalize(model="C8300-2N2S-6T")

    def test_missing_module_or_inventory_digest_fails_closed(self):
        with self.assertRaisesRegex(CiscoSwitchStateError, "required YANG modules"):
            self._normalize(observed_modules=MODULES - {"Cisco-IOS-XE-matm-oper"})
        with self.assertRaisesRegex(CiscoSwitchStateError, "required trunk YANG modules"):
            self._normalize(observed_modules=MODULES - {"openconfig-vlan-types"})
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

    def test_openconfig_trunk_enums_ranges_and_mode_constraints_fail_closed(self):
        broken = self._trunks()
        broken[0]["interface-mode"] = "DESIRABLE"
        with self.assertRaisesRegex(CiscoSwitchStateError, "interface-mode"):
            self._normalize(trunk_records=broken)

        broken = self._trunks()
        broken[0]["native-vlan"] = 0
        with self.assertRaisesRegex(CiscoSwitchStateError, "OpenConfig VLAN id"):
            self._normalize(trunk_records=broken)

        broken = self._trunks()
        broken[0]["trunk-vlans"] = ["22..20"]
        with self.assertRaisesRegex(CiscoSwitchStateError, "low < high"):
            self._normalize(trunk_records=broken)

        broken = self._trunks()
        broken[1]["native-vlan"] = 10
        with self.assertRaisesRegex(CiscoSwitchStateError, "ACCESS"):
            self._normalize(trunk_records=broken)

        broken = self._trunks()
        broken[0]["access-vlan"] = 20
        with self.assertRaisesRegex(CiscoSwitchStateError, "TRUNK"):
            self._normalize(trunk_records=broken)

    def test_openconfig_trunk_interface_key_and_cross_reference_fail_closed(self):
        duplicate = self._trunks() + [dict(self._trunks()[0])]
        with self.assertRaisesRegex(CiscoSwitchStateError, "duplicate switched-VLAN"):
            self._normalize(trunk_records=duplicate)

        broken = self._trunks()
        broken[0]["interface"] = "GigabitEthernet9/9/9"
        with self.assertRaisesRegex(CiscoSwitchStateError, "unknown interface"):
            self._normalize(trunk_records=broken)

    def test_sensitive_fields_are_rejected_before_normalization(self):
        broken = self._trunks()
        broken[0]["secret"] = "must-never-enter-normalized-state"
        with self.assertRaisesRegex(CiscoSwitchStateError, "sensitive field"):
            self._normalize(trunk_records=broken)


if __name__ == "__main__":
    unittest.main()
