import unittest
import xml.etree.ElementTree as ET

from router_configuration.vendors.cisco.desired_state import (
    CiscoDesiredStateError,
    desired_state_catalog_digest,
    load_desired_state_catalog,
    render_interface_description,
    render_interface_mtu,
)


MODULES = {"Cisco-IOS-XE-native"}
CAPABILITIES = {"urn:ietf:params:netconf:capability:candidate:1.0"}
SCHEMA_DIGEST = "b" * 64
NS = {"ios": "http://cisco.com/ns/yang/Cisco-IOS-XE-native"}


class CiscoDesiredStateTests(unittest.TestCase):
    def _render_description(self, **overrides):
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

    def _render_mtu(self, **overrides):
        params = {
            "model": "C9300-24T",
            "iosxe_version": "17.18.1a",
            "schema_inventory_digest_sha256": SCHEMA_DIGEST,
            "observed_modules": MODULES,
            "netconf_capabilities": CAPABILITIES,
            "interface_name": "1/0/1",
            "mtu": 1500,
        }
        params.update(overrides)
        return render_interface_mtu(**params)

    def test_catalog_is_source_pinned_and_fail_closed(self) -> None:
        catalog = load_desired_state_catalog()
        self.assertEqual(catalog["schema_provenance"]["yangmodels_commit"], "a4ea86b06aa63512e280f1665db6eaf8116bf059")
        self.assertEqual(set(catalog["documentation_trains"]), {"17.18", "26"})
        self.assertEqual({feature["id"] for feature in catalog["features"]}, {"interface.description.set", "interface.mtu.set"})
        mtu_feature = next(feature for feature in catalog["features"] if feature["id"] == "interface.mtu.set")
        self.assertEqual(mtu_feature["yang_constraints"]["mtu_range"], [64, 18000])
        self.assertFalse(catalog["runtime_ai_rendering"])
        self.assertFalse(catalog["write_authorized"])
        self.assertFalse(catalog["production_write_authorized"])
        self.assertFalse(catalog["c07_complete"])
        self.assertEqual(len(desired_state_catalog_digest()), 64)

    def test_switch_1718_description_render_is_deterministic_and_never_authorized(self) -> None:
        first = self._render_description()
        second = self._render_description(
            observed_modules=reversed(sorted(MODULES)),
            netconf_capabilities=reversed(sorted(CAPABILITIES)),
        )
        self.assertEqual(first.payload_xml, second.payload_xml)
        self.assertEqual(first.payload_digest_sha256, second.payload_digest_sha256)
        self.assertEqual(first.feature_id, "interface.description.set")
        self.assertEqual(first.platform_family, "Catalyst 9300")
        self.assertEqual(first.role, "switch")
        self.assertEqual(first.documentation_train, "17.18")
        self.assertEqual(first.target_datastore, "candidate")
        self.assertFalse(first.c07_complete)
        self.assertFalse(first.approval_bound)
        self.assertFalse(first.apply_authorized)
        self.assertFalse(first.production_write_authorized)
        self.assertNotIn("edit-config", first.payload_xml)

    def test_router_26_uses_same_bounded_description_renderer(self) -> None:
        rendered = self._render_description(model="C8000V", iosxe_version="26.1.1")
        self.assertEqual(rendered.platform_family, "Catalyst 8000V")
        self.assertEqual(rendered.role, "router")
        self.assertEqual(rendered.documentation_train, "26")

    def test_description_xml_escaping_is_structural_not_string_interpolation(self) -> None:
        rendered = self._render_description(description="Core & <edge>")
        self.assertIn("&amp;", rendered.payload_xml)
        self.assertIn("&lt;edge&gt;", rendered.payload_xml)
        root = ET.fromstring(rendered.payload_xml)
        text = root.find(".//ios:description", NS)
        self.assertIsNotNone(text)
        self.assertEqual(text.text, "Core & <edge>")

    def test_mtu_render_is_deterministic_source_bound_and_never_authorized(self) -> None:
        first = self._render_mtu(mtu=9216)
        second = self._render_mtu(
            mtu=9216,
            observed_modules=reversed(sorted(MODULES)),
            netconf_capabilities=reversed(sorted(CAPABILITIES)),
        )
        self.assertEqual(first.payload_xml, second.payload_xml)
        self.assertEqual(first.payload_digest_sha256, second.payload_digest_sha256)
        self.assertEqual(first.feature_id, "interface.mtu.set")
        self.assertFalse(first.c07_complete)
        self.assertFalse(first.approval_bound)
        self.assertFalse(first.apply_authorized)
        self.assertFalse(first.production_write_authorized)
        root = ET.fromstring(first.payload_xml)
        mtu = root.find(".//ios:mtu", NS)
        self.assertIsNotNone(mtu)
        self.assertEqual(mtu.text, "9216")

    def test_mtu_boundaries_match_both_pinned_yang_trains(self) -> None:
        self.assertIn(">64<", self._render_mtu(mtu=64).payload_xml)
        self.assertIn(">18000<", self._render_mtu(mtu=18000, model="C8000V", iosxe_version="26.1.1").payload_xml)
        for invalid in (63, 18001, 1500.0, True, "1500"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(CiscoDesiredStateError, "source-bound range"):
                    self._render_mtu(mtu=invalid)

    def test_description_and_mtu_have_distinct_payload_digests(self) -> None:
        description = self._render_description(description="1500")
        mtu = self._render_mtu(mtu=1500)
        self.assertNotEqual(description.payload_digest_sha256, mtu.payload_digest_sha256)
        self.assertNotEqual(description.feature_id, mtu.feature_id)

    def test_missing_native_module_fails_closed_for_both_renderers(self) -> None:
        with self.assertRaisesRegex(CiscoDesiredStateError, "module was not advertised"):
            self._render_description(observed_modules=set())
        with self.assertRaisesRegex(CiscoDesiredStateError, "module was not advertised"):
            self._render_mtu(observed_modules=set())

    def test_missing_candidate_capability_fails_closed_for_both_renderers(self) -> None:
        with self.assertRaisesRegex(CiscoDesiredStateError, "candidate capability"):
            self._render_description(netconf_capabilities=set())
        with self.assertRaisesRegex(CiscoDesiredStateError, "candidate capability"):
            self._render_mtu(netconf_capabilities=set())

    def test_unknown_model_or_train_fails_closed(self) -> None:
        with self.assertRaises(CiscoDesiredStateError):
            self._render_description(model="ISR-UNKNOWN")
        with self.assertRaises(CiscoDesiredStateError):
            self._render_mtu(iosxe_version="17.17.1")

    def test_invalid_schema_digest_fails_closed(self) -> None:
        with self.assertRaisesRegex(CiscoDesiredStateError, "inventory digest"):
            self._render_description(schema_inventory_digest_sha256="not-a-digest")
        with self.assertRaisesRegex(CiscoDesiredStateError, "inventory digest"):
            self._render_mtu(schema_inventory_digest_sha256="not-a-digest")

    def test_description_source_bound_length_is_enforced(self) -> None:
        rendered = self._render_description(description="x" * 200)
        self.assertEqual(len(ET.fromstring(rendered.payload_xml).find(".//ios:description", NS).text), 200)
        with self.assertRaisesRegex(CiscoDesiredStateError, "source-bound length"):
            self._render_description(description="x" * 201)

    def test_empty_or_control_character_description_is_rejected(self) -> None:
        with self.assertRaises(CiscoDesiredStateError):
            self._render_description(description="")
        with self.assertRaisesRegex(CiscoDesiredStateError, "control character"):
            self._render_description(description="line1\nline2")

    def test_interface_name_uses_conservative_renderer_subset_for_both_features(self) -> None:
        with self.assertRaisesRegex(CiscoDesiredStateError, "conservative renderer subset"):
            self._render_description(interface_name="1/0/1 $(unsafe)")
        with self.assertRaisesRegex(CiscoDesiredStateError, "source-bound length"):
            self._render_mtu(interface_name="1" * 65)

    def test_payload_digest_changes_when_intent_changes(self) -> None:
        first = self._render_description(description="uplink-a")
        second = self._render_description(description="uplink-b")
        self.assertNotEqual(first.payload_digest_sha256, second.payload_digest_sha256)
        mtu_a = self._render_mtu(mtu=1500)
        mtu_b = self._render_mtu(mtu=9000)
        self.assertNotEqual(mtu_a.payload_digest_sha256, mtu_b.payload_digest_sha256)


if __name__ == "__main__":
    unittest.main()
