import unittest
import xml.etree.ElementTree as ET

from router_configuration.vendors.cisco.desired_state import (
    CiscoDesiredStateError,
    desired_state_catalog_digest,
    load_desired_state_catalog,
    render_interface_description,
    render_interface_mtu,
    render_interface_shutdown,
)

MODULES = {"Cisco-IOS-XE-native"}
CAPABILITIES = {"urn:ietf:params:netconf:capability:candidate:1.0"}
SCHEMA_DIGEST = "b" * 64
NS = {"ios": "http://cisco.com/ns/yang/Cisco-IOS-XE-native"}


class CiscoDesiredStateTests(unittest.TestCase):
    def _common(self, **overrides):
        params = {
            "model": "C9300-24T",
            "iosxe_version": "17.18.1a",
            "schema_inventory_digest_sha256": SCHEMA_DIGEST,
            "observed_modules": MODULES,
            "netconf_capabilities": CAPABILITIES,
            "interface_name": "1/0/1",
        }
        params.update(overrides)
        return params

    def _render_description(self, **overrides):
        description = overrides.pop("description", "uplink-core-01")
        return render_interface_description(**self._common(**overrides), description=description)

    def _render_mtu(self, **overrides):
        mtu = overrides.pop("mtu", 1500)
        return render_interface_mtu(**self._common(**overrides), mtu=mtu)

    def _render_shutdown(self, **overrides):
        return render_interface_shutdown(**self._common(**overrides))

    def test_catalog_is_source_pinned_and_fail_closed(self) -> None:
        catalog = load_desired_state_catalog()
        self.assertEqual(catalog["schema_provenance"]["yangmodels_commit"], "a4ea86b06aa63512e280f1665db6eaf8116bf059")
        self.assertEqual(set(catalog["documentation_trains"]), {"17.18", "26"})
        self.assertEqual(
            {feature["id"] for feature in catalog["features"]},
            {
                "interface.description.set",
                "interface.mtu.set",
                "interface.shutdown.set",
                "interface.ipv4.set",
                "switch.vlan.set",
                "interface.shutdown.remove",
            },
        )
        mtu_feature = next(feature for feature in catalog["features"] if feature["id"] == "interface.mtu.set")
        self.assertEqual(mtu_feature["yang_constraints"]["mtu_range"], [64, 18000])
        shutdown = next(feature for feature in catalog["features"] if feature["id"] == "interface.shutdown.set")
        self.assertEqual(shutdown["yang_constraints"]["yang_type"], "empty")
        self.assertFalse(shutdown["yang_constraints"]["delete_semantics_admitted"])
        ipv4 = next(feature for feature in catalog["features"] if feature["id"] == "interface.ipv4.set")
        self.assertEqual(ipv4["roles"], ["router"])
        vlan = next(feature for feature in catalog["features"] if feature["id"] == "switch.vlan.set")
        self.assertEqual(vlan["yang_constraints"]["vlan_range"], [1, 4094])
        shutdown_remove = next(feature for feature in catalog["features"] if feature["id"] == "interface.shutdown.remove")
        self.assertEqual(shutdown_remove["yang_constraints"]["netconf_operation"], "remove")
        self.assertFalse(catalog["runtime_ai_rendering"])
        self.assertFalse(catalog["write_authorized"])
        self.assertFalse(catalog["production_write_authorized"])
        self.assertFalse(catalog["c07_complete"])
        self.assertEqual(len(desired_state_catalog_digest()), 64)

    def test_description_render_is_deterministic_and_never_authorized(self) -> None:
        first = self._render_description()
        second = self._render_description(observed_modules=reversed(sorted(MODULES)), netconf_capabilities=reversed(sorted(CAPABILITIES)))
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

    def test_description_xml_escaping_is_structural(self) -> None:
        rendered = self._render_description(description="Core & <edge>")
        self.assertIn("&amp;", rendered.payload_xml)
        self.assertIn("&lt;edge&gt;", rendered.payload_xml)
        root = ET.fromstring(rendered.payload_xml)
        text = root.find(".//ios:description", NS)
        self.assertIsNotNone(text)
        self.assertEqual(text.text, "Core & <edge>")

    def test_mtu_render_is_deterministic_source_bound_and_never_authorized(self) -> None:
        first = self._render_mtu(mtu=9216)
        second = self._render_mtu(mtu=9216, observed_modules=reversed(sorted(MODULES)), netconf_capabilities=reversed(sorted(CAPABILITIES)))
        self.assertEqual(first.payload_xml, second.payload_xml)
        self.assertEqual(first.payload_digest_sha256, second.payload_digest_sha256)
        self.assertEqual(first.feature_id, "interface.mtu.set")
        root = ET.fromstring(first.payload_xml)
        mtu = root.find(".//ios:mtu", NS)
        self.assertIsNotNone(mtu)
        self.assertEqual(mtu.text, "9216")
        self.assertFalse(first.apply_authorized)
        self.assertFalse(first.production_write_authorized)

    def test_mtu_boundaries_match_both_pinned_yang_trains(self) -> None:
        self.assertIn(">64<", self._render_mtu(mtu=64).payload_xml)
        self.assertIn(">18000<", self._render_mtu(mtu=18000, model="C8000V", iosxe_version="26.1.1").payload_xml)
        for invalid in (63, 18001, 1500.0, True, "1500"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(CiscoDesiredStateError, "source-bound range"):
                    self._render_mtu(mtu=invalid)

    def test_shutdown_renders_exact_empty_leaf_on_1718(self) -> None:
        rendered = self._render_shutdown()
        self.assertEqual(rendered.feature_id, "interface.shutdown.set")
        root = ET.fromstring(rendered.payload_xml)
        leaf = root.find(".//ios:shutdown", NS)
        self.assertIsNotNone(leaf)
        self.assertIsNone(leaf.text)
        self.assertFalse(rendered.c07_complete)
        self.assertFalse(rendered.approval_bound)
        self.assertFalse(rendered.apply_authorized)
        self.assertFalse(rendered.production_write_authorized)

    def test_shutdown_has_same_source_bound_shape_on_26(self) -> None:
        rendered = self._render_shutdown(model="C8000V", iosxe_version="26.1.1")
        self.assertEqual(rendered.documentation_train, "26")
        self.assertEqual(rendered.role, "router")
        self.assertIn("<shutdown", rendered.payload_xml)

    def test_shutdown_is_deterministic_and_distinct(self) -> None:
        first = self._render_shutdown()
        second = self._render_shutdown(observed_modules=reversed(sorted(MODULES)), netconf_capabilities=reversed(sorted(CAPABILITIES)))
        self.assertEqual(first.payload_digest_sha256, second.payload_digest_sha256)
        self.assertNotEqual(first.payload_digest_sha256, self._render_description(description="shutdown").payload_digest_sha256)
        self.assertNotEqual(first.payload_digest_sha256, self._render_mtu(mtu=1500).payload_digest_sha256)

    def test_missing_native_module_fails_closed_for_all_renderers(self) -> None:
        for renderer in (self._render_description, self._render_mtu, self._render_shutdown):
            with self.subTest(renderer=renderer.__name__):
                with self.assertRaisesRegex(CiscoDesiredStateError, "module was not advertised"):
                    renderer(observed_modules=set())

    def test_missing_candidate_capability_fails_closed_for_all_renderers(self) -> None:
        for renderer in (self._render_description, self._render_mtu, self._render_shutdown):
            with self.subTest(renderer=renderer.__name__):
                with self.assertRaisesRegex(CiscoDesiredStateError, "candidate capability"):
                    renderer(netconf_capabilities=set())

    def test_unknown_model_or_train_fails_closed(self) -> None:
        with self.assertRaises(CiscoDesiredStateError):
            self._render_description(model="ISR-UNKNOWN")
        with self.assertRaises(CiscoDesiredStateError):
            self._render_mtu(iosxe_version="17.17.1")
        with self.assertRaises(CiscoDesiredStateError):
            self._render_shutdown(iosxe_version="17.17.1")

    def test_invalid_schema_digest_fails_closed(self) -> None:
        for renderer in (self._render_description, self._render_mtu, self._render_shutdown):
            with self.subTest(renderer=renderer.__name__):
                with self.assertRaisesRegex(CiscoDesiredStateError, "inventory digest"):
                    renderer(schema_inventory_digest_sha256="not-a-digest")

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

    def test_interface_name_uses_conservative_subset_for_all_features(self) -> None:
        for renderer in (self._render_description, self._render_mtu, self._render_shutdown):
            with self.subTest(renderer=renderer.__name__):
                with self.assertRaises(CiscoDesiredStateError):
                    renderer(interface_name="1/0/1 $(unsafe)")

    def test_payload_digest_changes_when_intent_changes(self) -> None:
        self.assertNotEqual(self._render_description(description="uplink-a").payload_digest_sha256, self._render_description(description="uplink-b").payload_digest_sha256)
        self.assertNotEqual(self._render_mtu(mtu=1500).payload_digest_sha256, self._render_mtu(mtu=9000).payload_digest_sha256)


if __name__ == "__main__":
    unittest.main()
