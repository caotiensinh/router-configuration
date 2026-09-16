import unittest
import xml.etree.ElementTree as ET

from router_configuration.vendors.cisco.desired_state import (
    CiscoDesiredStateError,
    render_interface_ipv4,
    render_interface_shutdown_remove,
    render_switch_access_vlan,
)

MODULES = {"Cisco-IOS-XE-native"}
CAPABILITIES = {"urn:ietf:params:netconf:capability:candidate:1.0"}
SCHEMA = "b" * 64
IOS = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"
NC = "urn:ietf:params:xml:ns:netconf:base:1.0"


class CiscoC07ExtendedIntegrationTests(unittest.TestCase):
    def _base(self, *, model, version="17.18.1a"):
        return {
            "model": model,
            "iosxe_version": version,
            "schema_inventory_digest_sha256": SCHEMA,
            "observed_modules": MODULES,
            "netconf_capabilities": CAPABILITIES,
            "interface_name": "1/0/1",
        }

    def test_router_ipv4_is_admitted_through_main_api(self):
        first = render_interface_ipv4(
            **self._base(model="C8000V"), address="192.0.2.10", mask="255.255.255.0"
        )
        second = render_interface_ipv4(
            **self._base(model="C8000V"), address="192.0.2.10", mask="255.255.255.0"
        )
        self.assertEqual(first, second)
        self.assertEqual(first.feature_id, "interface.ipv4.set")
        self.assertEqual(first.role, "router")
        root = ET.fromstring(first.payload_xml)
        primary = root.find(
            f"./{{{IOS}}}interface/{{{IOS}}}GigabitEthernet/{{{IOS}}}ip/"
            f"{{{IOS}}}address/{{{IOS}}}primary"
        )
        self.assertEqual(primary.find(f"{{{IOS}}}address").text, "192.0.2.10")
        self.assertEqual(primary.find(f"{{{IOS}}}mask").text, "255.255.255.0")
        self.assertFalse(first.apply_authorized)
        self.assertFalse(first.production_write_authorized)

    def test_ipv4_fails_closed_on_switch_role(self):
        with self.assertRaisesRegex(CiscoDesiredStateError, "router-role"):
            render_interface_ipv4(
                **self._base(model="C9300-24T"), address="192.0.2.10", mask="255.255.255.0"
            )

    def test_access_vlan_requires_switch_role_and_explicit_switchport(self):
        rendered = render_switch_access_vlan(
            **self._base(model="C9300-24T"), vlan_id=100, existing_switchport=True
        )
        self.assertEqual(rendered.feature_id, "switch.vlan.set")
        self.assertEqual(rendered.role, "switch")
        root = ET.fromstring(rendered.payload_xml)
        vlan = root.find(
            f"./{{{IOS}}}interface/{{{IOS}}}GigabitEthernet/"
            f"{{{IOS}}}switchport-wrapper/{{{IOS}}}switchport/{{{IOS}}}access/{{{IOS}}}vlan"
        )
        self.assertEqual(vlan.text, "100")
        with self.assertRaisesRegex(CiscoDesiredStateError, "already established switchport"):
            render_switch_access_vlan(
                **self._base(model="C9300-24T"), vlan_id=100, existing_switchport=False
            )
        with self.assertRaisesRegex(CiscoDesiredStateError, "switch-role"):
            render_switch_access_vlan(
                **self._base(model="C8000V"), vlan_id=100, existing_switchport=True
            )

    def test_shutdown_remove_is_exact_rfc6241_remove_fragment(self):
        rendered = render_interface_shutdown_remove(**self._base(model="C8000V", version="26.1.1"))
        self.assertEqual(rendered.feature_id, "interface.shutdown.remove")
        self.assertEqual(rendered.documentation_train, "26")
        root = ET.fromstring(rendered.payload_xml)
        shutdown = root.find(
            f"./{{{IOS}}}interface/{{{IOS}}}GigabitEthernet/{{{IOS}}}shutdown"
        )
        self.assertEqual(shutdown.attrib[f"{{{NC}}}operation"], "remove")
        self.assertFalse(rendered.apply_authorized)
        self.assertFalse(rendered.production_write_authorized)

    def test_extended_renderers_still_require_module_candidate_and_schema(self):
        with self.assertRaisesRegex(CiscoDesiredStateError, "module was not advertised"):
            render_interface_shutdown_remove(
                **{**self._base(model="C8000V"), "observed_modules": set()}
            )
        with self.assertRaisesRegex(CiscoDesiredStateError, "candidate capability"):
            render_interface_ipv4(
                **{**self._base(model="C8000V"), "netconf_capabilities": set()},
                address="192.0.2.10",
                mask="255.255.255.0",
            )
        with self.assertRaisesRegex(CiscoDesiredStateError, "inventory digest"):
            render_switch_access_vlan(
                **{**self._base(model="C9300-24T"), "schema_inventory_digest_sha256": "bad"},
                vlan_id=100,
                existing_switchport=True,
            )


if __name__ == "__main__":
    unittest.main()
