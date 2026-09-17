import unittest
from unittest.mock import patch

from router_configuration.vendors.cisco.live_netconf_probe import (
    INTERFACES_OPER_NS,
    PLATFORM_OPER_NS,
    CiscoLiveNetconfProbeError,
    parse_interfaces_oper_reply,
    parse_native_identity_reply,
    parse_platform_oper_reply,
    run_from_environment,
    validate_hostkey_b64,
    yang_schema_has_container,
)
from router_configuration.vendors.cisco.netconf_readonly import NETCONF_BASE_NS


IDENTITY_REPLY = f"""
<rpc-reply xmlns="{NETCONF_BASE_NS}" message-id="1">
  <data>
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
      <hostname>edge-c8300-01</hostname>
      <version>17.18.1a</version>
    </native>
  </data>
</rpc-reply>
"""


PLATFORM_REPLY = f"""
<rpc-reply xmlns="{NETCONF_BASE_NS}" message-id="2">
  <data>
    <components xmlns="{PLATFORM_OPER_NS}">
      <component>
        <type>chassis</type>
        <id>Chassis</id>
        <description>Cisco Catalyst C8300 edge platform</description>
        <mfg-name>Cisco</mfg-name>
        <part-no>C8300-2N2S-6T</part-no>
        <serial-no>REDACT-ME-123</serial-no>
        <location>Rack 1</location>
      </component>
      <component>
        <type>fan</type>
        <id>Fan0</id>
        <description>System fan</description>
        <part-no>FAN-MOD</part-no>
      </component>
    </components>
  </data>
</rpc-reply>
"""


INTERFACES_REPLY = f"""
<rpc-reply xmlns="{NETCONF_BASE_NS}" message-id="3">
  <data>
    <interfaces xmlns="{INTERFACES_OPER_NS}">
      <interface>
        <name>GigabitEthernet0/0/0</name>
        <admin-status>if-state-up</admin-status>
        <oper-status>if-oper-state-ready</oper-status>
        <if-index>1</if-index>
        <speed>1000000000</speed>
      </interface>
      <interface>
        <name>GigabitEthernet0/0/1</name>
        <admin-status>if-state-up</admin-status>
        <oper-status>if-oper-state-down</oper-status>
        <if-index>2</if-index>
        <speed>1000000000</speed>
      </interface>
    </interfaces>
  </data>
</rpc-reply>
"""


class CiscoLiveNetconfProbeTests(unittest.TestCase):
    def test_native_identity_is_bounded(self) -> None:
        identity = parse_native_identity_reply(IDENTITY_REPLY)
        self.assertEqual(identity.hostname, "edge-c8300-01")
        self.assertEqual(identity.iosxe_version, "17.18.1a")

    def test_native_identity_rejects_sensitive_response(self) -> None:
        reply = f"""
        <rpc-reply xmlns="{NETCONF_BASE_NS}" message-id="4">
          <data>
            <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
              <hostname>edge-c8300-01</hostname>
              <version>17.18.1a</version>
              <password><secret>never-store</secret></password>
            </native>
          </data>
        </rpc-reply>
        """
        with self.assertRaises(CiscoLiveNetconfProbeError):
            parse_native_identity_reply(reply)

    def test_platform_observation_admits_documented_router(self) -> None:
        observation = parse_platform_oper_reply(PLATFORM_REPLY, "17.18.1a")
        self.assertEqual(observation.component_count, 2)
        self.assertEqual(observation.admitted_model, "C8300-2N2S-6T")
        self.assertIsNotNone(observation.platform_admission)
        self.assertTrue(observation.platform_admission.read_only_candidate)
        self.assertEqual(len(observation.component_digest_sha256), 64)
        self.assertEqual(len(observation.serial_digest_sha256 or ""), 64)
        self.assertNotIn("REDACT-ME-123", observation.component_digest_sha256)

    def test_platform_observation_does_not_admit_undocumented_version(self) -> None:
        observation = parse_platform_oper_reply(PLATFORM_REPLY, "17.12.4")
        self.assertIsNone(observation.admitted_model)
        self.assertIsNotNone(observation.platform_admission)
        self.assertEqual(observation.platform_admission.status, "UNVERIFIED_VERSION")

    def test_interface_observation_is_summary_and_digest(self) -> None:
        observation = parse_interfaces_oper_reply(INTERFACES_REPLY)
        self.assertEqual(observation.interface_count, 2)
        self.assertEqual(dict(observation.admin_status_counts), {"if-state-up": 2})
        self.assertEqual(
            dict(observation.oper_status_counts),
            {"if-oper-state-down": 1, "if-oper-state-ready": 1},
        )
        self.assertEqual(len(observation.interface_digest_sha256), 64)

    def test_yang_container_proof_is_explicit(self) -> None:
        schema = "module sample { namespace 'x'; container components { leaf id { type string; } } }"
        self.assertTrue(yang_schema_has_container(schema, "components"))
        self.assertFalse(yang_schema_has_container(schema, "interfaces"))

    def test_host_key_pin_requires_real_base64_material(self) -> None:
        with self.assertRaises(CiscoLiveNetconfProbeError):
            validate_hostkey_b64("not-base64***")
        with self.assertRaises(CiscoLiveNetconfProbeError):
            validate_hostkey_b64("YWJj")

    def test_missing_runtime_secrets_are_fail_closed_without_network(self) -> None:
        evidence, exit_code = run_from_environment({"SOURCE_SHA": "a" * 40})
        self.assertEqual(exit_code, 0)
        self.assertEqual(evidence["stage"], "credentials_missing")
        self.assertFalse(evidence["live_target_observed"])
        self.assertFalse(evidence["c03_complete"])
        self.assertFalse(evidence["production_write_authorized"])
        self.assertFalse(evidence["physical_device_verified"])
        self.assertNotIn("password", json_text(evidence).lower())

    def test_probe_failure_is_sanitized_and_never_returns_runtime_secret(self) -> None:
        env = {
            "SOURCE_SHA": "b" * 40,
            "CISCO_NETCONF_HOST": "router.example.invalid",
            "CISCO_NETCONF_USERNAME": "operator",
            "CISCO_NETCONF_PASSWORD": "super-secret-password",
            "CISCO_NETCONF_HOSTKEY_B64": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
        }
        with patch(
            "router_configuration.vendors.cisco.live_netconf_probe.run_live_probe",
            side_effect=CiscoLiveNetconfProbeError("authentication failed"),
        ):
            evidence, exit_code = run_from_environment(env)
        self.assertEqual(exit_code, 3)
        self.assertFalse(evidence["c03_complete"])
        rendered = json_text(evidence)
        self.assertNotIn("super-secret-password", rendered)
        self.assertNotIn("operator", rendered)
        self.assertNotIn("router.example.invalid", rendered)


def json_text(value: object) -> str:
    import json

    return json.dumps(value, sort_keys=True)


if __name__ == "__main__":
    unittest.main()
