import unittest
import xml.etree.ElementTree as ET

from router_configuration.vendors.cisco.c07_access_vlan_renderer import (
    CiscoC07AccessVlanRendererError,
    render_access_vlan_fragment,
)

NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"


class CiscoC07AccessVlanRendererTests(unittest.TestCase):
    def test_access_vlan_fragment_is_deterministic_and_bounded(self):
        first = render_access_vlan_fragment(interface_name="GigabitEthernet1/0/1", vlan_id=100)
        second = render_access_vlan_fragment(interface_name="GigabitEthernet1/0/1", vlan_id=100)
        self.assertEqual(first, second)
        self.assertEqual(first.feature_id, "switch.vlan.set")
        self.assertEqual(first.documentation_trains, ("17.18", "26"))
        self.assertTrue(first.requires_existing_switchport)
        self.assertFalse(first.apply_authorized)
        self.assertFalse(first.production_write_authorized)
        root = ET.fromstring(first.payload_xml)
        vlan = root.find(
            f"./{{{NS}}}interface/{{{NS}}}GigabitEthernet/"
            f"{{{NS}}}switchport-wrapper/{{{NS}}}switchport/{{{NS}}}access/{{{NS}}}vlan"
        )
        self.assertIsNotNone(vlan)
        self.assertEqual(vlan.text, "100")

    def test_vlan_range_and_interface_subset_fail_closed(self):
        for vlan_id in (0, 4095, -1, True):
            with self.subTest(vlan_id=vlan_id):
                with self.assertRaises(CiscoC07AccessVlanRendererError):
                    render_access_vlan_fragment(interface_name="GigabitEthernet1/0/1", vlan_id=vlan_id)
        with self.assertRaises(CiscoC07AccessVlanRendererError):
            render_access_vlan_fragment(interface_name="bad interface", vlan_id=100)


if __name__ == "__main__":
    unittest.main()
