import unittest
import xml.etree.ElementTree as ET

from router_configuration.vendors.cisco.desired_state import (
    CiscoDesiredStateError,
    desired_state_catalog_digest,
    load_desired_state_catalog,
    render_interface_description,
)


MODULES = {"Cisco-IOS-XE-native"}
CAPABILITIES = {"urn:ietf:params:netconf:capability:candidate:1.0"}
SCHEMA_DIGEST = "b" * 64
NS = {"ios": "http://cisco.com/ns/yang/Cisco-IOS-XE-native"}


class CiscoDesiredStateTests(unittest.TestCase):
    def _render(self, **overrides):
        params = {
            "model": "C9300-24T",
            "iosxe_version": "17.18.1a",
            "schema_inventory_digest_sha256": SCHEMA_DIGEST,
            "observed_modules": MODULES,
            "netconf_capabilities": CAPABILITIES,
            "interface_name": "1/0/1",
            "description": "uplink-core-01",
        }
        params.update(overrides)
        return render_interface_description(**params)

    def test_catalog_is_source_pinned_and_fail_closed(self) -> None:
        catalog = load_desired_state_catalog()
        self.assertEqual(catalog["schema_provenance"]["yangmodels_commit"], "a4ea86b06aa63512e280f1665db6eaf8116bf059")
        self.assertEqual(set(catalog["documentation_trains"]), {"17.18", "26"})
        self.assertFalse(catalog["runtime_ai_rendering"])
        self.assertFalse(catalog["write_authorized"])
        self.assertFalse(catalog["production_write_authorized"])
        self.assertFalse(catalog["c07_complete"])
        self.assertEqual(len(desired_state_catalog_digest()), 64)

    def test_switch_1718_render_is_deterministic_and_never_authorized(self) -> None:
        first = self._render()
        second = self._render(
            observed_modules=reversed(sorted(MODULES)),
            netconf_capabilities=reversed(sorted(CAPABILITIES)),
        )
        self.assertEqual(first.payload_xml, second.payload_xml)
        self.assertEqual(first.payload_digest_sha256, second.payload_digest_sha256)
        self.assertEqual(first.platform_family, "Catalyst 9300")
        self.assertEqual(first.role, "switch")
        self.assertEqual(first.documentation_train, "17.18")
        self.assertEqual(first.target_datastore, "candidate")
        self.assertFalse(first.c07_complete)
        self.assertFalse(first.approval_bound)
        self.assertFalse(first.apply_authorized)
        self.assertFalse(first.production_write_authorized)
        self.assertNotIn("edit-config", first.payload_xml)

    def test_router_26_uses_same_bounded_renderer(self) -> None:
        rendered = self._render(model="C8000V", iosxe_version="26.1.1")
        self.assertEqual(rendered.platform_family, "Catalyst 8000V")
        self.assertEqual(rendered.role, "router")
        self.assertEqual(rendered.documentation_train, "26")

    def test_xml_escaping_is_structural_not_string_interpolation(self) -> None:
        rendered = self._render(description="Core & <edge>")
        self.assertIn("&amp;", rendered.payload_xml)
        self.assertIn("&lt;edge&gt;", rendered.payload_xml)
        root = ET.fromstring(rendered.payload_xml)
        text = root.find(".//ios:description", NS)
        self.assertIsNotNone(text)
        self.assertEqual(text.text, "Core & <edge>")

    def test_missing_native_module_fails_closed(self) -> None:
        with self.assertRaisesRegex(CiscoDesiredStateError, "module was not advertised"):
            self._render(observed_modules=set())

    def test_missing_candidate_capability_fails_closed(self) -> None:
        with self.assertRaisesRegex(CiscoDesiredStateError, "candidate capability"):
            self._render(netconf_capabilities=set())

    def test_unknown_model_or_train_fails_closed(self) -> None:
        with self.assertRaises(CiscoDesiredStateError):
            self._render(model="ISR-UNKNOWN")
        with self.assertRaises(CiscoDesiredStateError):
            self._render(iosxe_version="17.17.1")

    def test_invalid_schema_digest_fails_closed(self) -> None:
        with self.assertRaisesRegex(CiscoDesiredStateError, "inventory digest"):
            self._render(schema_inventory_digest_sha256="not-a-digest")

    def test_description_source_bound_length_is_enforced(self) -> None:
        rendered = self._render(description="x" * 200)
        self.assertEqual(len(ET.fromstring(rendered.payload_xml).find(".//ios:description", NS).text), 200)
        with self.assertRaisesRegex(CiscoDesiredStateError, "source-bound length"):
            self._render(description="x" * 201)

    def test_empty_or_control_character_description_is_rejected(self) -> None:
        with self.assertRaises(CiscoDesiredStateError):
            self._render(description="")
        with self.assertRaisesRegex(CiscoDesiredStateError, "control character"):
            self._render(description="line1\nline2")

    def test_interface_name_uses_conservative_renderer_subset(self) -> None:
        with self.assertRaisesRegex(CiscoDesiredStateError, "conservative renderer subset"):
            self._render(interface_name="1/0/1 $(unsafe)")
        with self.assertRaisesRegex(CiscoDesiredStateError, "source-bound length"):
            self._render(interface_name="1" * 65)

    def test_payload_digest_changes_when_intent_changes(self) -> None:
        first = self._render(description="uplink-a")
        second = self._render(description="uplink-b")
        self.assertNotEqual(first.payload_digest_sha256, second.payload_digest_sha256)


if __name__ == "__main__":
    unittest.main()
