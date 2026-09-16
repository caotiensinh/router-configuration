import unittest
import xml.etree.ElementTree as ET

from router_configuration.vendors.cisco.c07_ipv4_renderer import (
    CiscoC07Ipv4RendererError,
    render_ipv4_primary_fragment,
)

NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"


class CiscoC07Ipv4RendererTests(unittest.TestCase):
    def test_ipv4_primary_fragment_is_deterministic_and_non_authorizing(self):
        first = render_ipv4_primary_fragment(
            interface_name="GigabitEthernet1",
            address="192.0.2.10",
            mask="255.255.255.0",
        )
        second = render_ipv4_primary_fragment(
            interface_name="GigabitEthernet1",
            address="192.0.2.10",
            mask="255.255.255.0",
        )
        self.assertEqual(first, second)
        self.assertEqual(first.feature_id, "interface.ipv4.set")
        self.assertEqual(first.documentation_trains, ("17.18", "26"))
        self.assertFalse(first.apply_authorized)
        self.assertFalse(first.production_write_authorized)
        root = ET.fromstring(first.payload_xml)
        primary = root.find(
            f"./{{{NS}}}interface/{{{NS}}}GigabitEthernet/{{{NS}}}ip/"
            f"{{{NS}}}address/{{{NS}}}primary"
        )
        self.assertIsNotNone(primary)
        self.assertEqual(primary.find(f"{{{NS}}}address").text, "192.0.2.10")
        self.assertEqual(primary.find(f"{{{NS}}}mask").text, "255.255.255.0")

    def test_invalid_address_mask_or_interface_fails_closed(self):
        cases = (
            {"interface_name": "GigabitEthernet1", "address": "999.1.1.1", "mask": "255.255.255.0"},
            {"interface_name": "GigabitEthernet1", "address": "192.0.2.10", "mask": "255.0.255.0"},
            {"interface_name": "bad interface", "address": "192.0.2.10", "mask": "255.255.255.0"},
        )
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(CiscoC07Ipv4RendererError):
                    render_ipv4_primary_fragment(**kwargs)


if __name__ == "__main__":
    unittest.main()
