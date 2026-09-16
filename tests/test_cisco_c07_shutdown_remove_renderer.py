import unittest
import xml.etree.ElementTree as ET

from router_configuration.vendors.cisco.c07_shutdown_remove_renderer import (
    CiscoC07ShutdownRemoveRendererError,
    render_shutdown_remove_fragment,
)

NATIVE_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"
NETCONF_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"


class CiscoC07ShutdownRemoveRendererTests(unittest.TestCase):
    def test_shutdown_remove_is_deterministic_idempotent_fragment(self):
        first = render_shutdown_remove_fragment(interface_name="GigabitEthernet1")
        second = render_shutdown_remove_fragment(interface_name="GigabitEthernet1")
        self.assertEqual(first, second)
        self.assertEqual(first.feature_id, "interface.shutdown.remove")
        self.assertEqual(first.netconf_operation, "remove")
        self.assertEqual(first.documentation_trains, ("17.18", "26"))
        self.assertFalse(first.apply_authorized)
        self.assertFalse(first.production_write_authorized)
        root = ET.fromstring(first.payload_xml)
        shutdown = root.find(
            f"./{{{NATIVE_NS}}}interface/{{{NATIVE_NS}}}GigabitEthernet/{{{NATIVE_NS}}}shutdown"
        )
        self.assertIsNotNone(shutdown)
        self.assertEqual(shutdown.attrib[f"{{{NETCONF_NS}}}operation"], "remove")
        self.assertIsNone(shutdown.text)

    def test_interface_subset_fails_closed(self):
        for name in ("", "bad interface", "x" * 65):
            with self.subTest(name=name):
                with self.assertRaises(CiscoC07ShutdownRemoveRendererError):
                    render_shutdown_remove_fragment(interface_name=name)


if __name__ == "__main__":
    unittest.main()
