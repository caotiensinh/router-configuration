import unittest

from router_configuration.vendors.cisco.netconf_readonly import (
    CISCO_NATIVE_NS,
    NETCONF_BASE_NS,
    NETCONF_MONITORING_NS,
    CiscoNetconfEvidenceError,
    parse_iosxe_native_version_reply,
    parse_schema_inventory_reply,
    parse_server_hello,
    validate_read_only_rpc,
)


HELLO = f"""
<hello xmlns="{NETCONF_BASE_NS}">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:writable-running:1.0</capability>
    <capability>http://cisco.com/ns/yang/Cisco-IOS-XE-native?module=Cisco-IOS-XE-native&amp;revision=2025-03-01</capability>
    <capability>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring?module=ietf-netconf-monitoring&amp;revision=2010-10-04</capability>
  </capabilities>
  <session-id>42</session-id>
</hello>
"""


SCHEMA_REPLY = f"""
<rpc-reply xmlns="{NETCONF_BASE_NS}" message-id="101">
  <data>
    <netconf-state xmlns="{NETCONF_MONITORING_NS}">
      <schemas>
        <schema>
          <identifier>Cisco-IOS-XE-native</identifier>
          <version>2025-03-01</version>
          <format>yang</format>
          <namespace>http://cisco.com/ns/yang/Cisco-IOS-XE-native</namespace>
          <location>NETCONF</location>
        </schema>
        <schema>
          <identifier>ietf-netconf-monitoring</identifier>
          <version>2010-10-04</version>
          <format>yang</format>
          <namespace>{NETCONF_MONITORING_NS}</namespace>
          <location>NETCONF</location>
        </schema>
      </schemas>
    </netconf-state>
  </data>
</rpc-reply>
"""


VERSION_REPLY = f"""
<rpc-reply xmlns="{NETCONF_BASE_NS}" message-id="102">
  <data>
    <native xmlns="{CISCO_NATIVE_NS}">
      <version>17.18.1a</version>
    </native>
  </data>
</rpc-reply>
"""


GET_SCHEMA_INVENTORY = f"""
<rpc xmlns="{NETCONF_BASE_NS}" message-id="201">
  <get>
    <filter type="subtree">
      <netconf-state xmlns="{NETCONF_MONITORING_NS}">
        <schemas/>
      </netconf-state>
    </filter>
  </get>
</rpc>
"""


GET_RUNNING_VERSION = f"""
<rpc xmlns="{NETCONF_BASE_NS}" message-id="202">
  <get-config>
    <source><running/></source>
    <filter type="subtree">
      <native xmlns="{CISCO_NATIVE_NS}">
        <version/>
      </native>
    </filter>
  </get-config>
</rpc>
"""


GET_SCHEMA = f"""
<rpc xmlns="{NETCONF_BASE_NS}" message-id="203">
  <get-schema xmlns="{NETCONF_MONITORING_NS}">
    <identifier>Cisco-IOS-XE-native</identifier>
  </get-schema>
</rpc>
"""


class CiscoNetconfReadOnlyTests(unittest.TestCase):
    def test_server_hello_is_normalized_and_hash_bound(self) -> None:
        evidence = parse_server_hello(HELLO)
        self.assertEqual(evidence.session_id, 42)
        self.assertEqual(evidence.base_capabilities, ("urn:ietf:params:netconf:base:1.0",))
        self.assertIn("Cisco-IOS-XE-native", evidence.model_modules)
        self.assertIn("ietf-netconf-monitoring", evidence.model_modules)
        self.assertEqual(len(evidence.digest_sha256), 64)
        self.assertFalse(evidence.write_authorized)
        self.assertFalse(evidence.physical_device_verified)

    def test_server_hello_requires_netconf_base_capability(self) -> None:
        xml = f"""
        <hello xmlns="{NETCONF_BASE_NS}">
          <capabilities>
            <capability>http://example.invalid/model?module=x</capability>
          </capabilities>
          <session-id>5</session-id>
        </hello>
        """
        with self.assertRaises(CiscoNetconfEvidenceError):
            parse_server_hello(xml)

    def test_server_hello_rejects_duplicate_capabilities(self) -> None:
        xml = f"""
        <hello xmlns="{NETCONF_BASE_NS}">
          <capabilities>
            <capability>urn:ietf:params:netconf:base:1.0</capability>
            <capability>urn:ietf:params:netconf:base:1.0</capability>
          </capabilities>
          <session-id>5</session-id>
        </hello>
        """
        with self.assertRaises(CiscoNetconfEvidenceError):
            parse_server_hello(xml)

    def test_read_only_allowlist_accepts_bounded_get_operations(self) -> None:
        for rpc in (GET_SCHEMA_INVENTORY, GET_RUNNING_VERSION, GET_SCHEMA):
            decision = validate_read_only_rpc(rpc)
            self.assertTrue(decision.allowed, decision.reason)

    def test_unfiltered_get_is_rejected(self) -> None:
        rpc = f"""
        <rpc xmlns="{NETCONF_BASE_NS}" message-id="204">
          <get/>
        </rpc>
        """
        decision = validate_read_only_rpc(rpc)
        self.assertFalse(decision.allowed)
        self.assertIn("filter", decision.reason)

    def test_get_config_must_read_running_only(self) -> None:
        rpc = f"""
        <rpc xmlns="{NETCONF_BASE_NS}" message-id="205">
          <get-config>
            <source><startup/></source>
            <filter type="subtree">
              <native xmlns="{CISCO_NATIVE_NS}"><version/></native>
            </filter>
          </get-config>
        </rpc>
        """
        decision = validate_read_only_rpc(rpc)
        self.assertFalse(decision.allowed)
        self.assertIn("running", decision.reason)

    def test_mutating_operations_fail_closed(self) -> None:
        rpc = f"""
        <rpc xmlns="{NETCONF_BASE_NS}" message-id="206">
          <edit-config>
            <target><running/></target>
            <config/>
          </edit-config>
        </rpc>
        """
        decision = validate_read_only_rpc(rpc)
        self.assertFalse(decision.allowed)
        self.assertIn("blocked", decision.reason)

    def test_nc_operation_attribute_is_rejected_even_inside_get(self) -> None:
        rpc = f"""
        <rpc xmlns="{NETCONF_BASE_NS}" message-id="207">
          <get>
            <filter type="subtree">
              <native xmlns="{CISCO_NATIVE_NS}">
                <hostname xmlns:nc="{NETCONF_BASE_NS}" nc:operation="delete"/>
              </native>
            </filter>
          </get>
        </rpc>
        """
        decision = validate_read_only_rpc(rpc)
        self.assertFalse(decision.allowed)
        self.assertIn("operation", decision.reason)

    def test_schema_inventory_is_deterministic(self) -> None:
        inventory = parse_schema_inventory_reply(SCHEMA_REPLY)
        self.assertEqual(len(inventory.schemas), 2)
        self.assertEqual(inventory.schemas[0].identifier, "Cisco-IOS-XE-native")
        self.assertEqual(len(inventory.digest_sha256), 64)
        self.assertFalse(inventory.write_authorized)
        self.assertEqual(
            parse_schema_inventory_reply(SCHEMA_REPLY).digest_sha256,
            inventory.digest_sha256,
        )

    def test_native_version_parser_extracts_only_expected_leaf(self) -> None:
        self.assertEqual(parse_iosxe_native_version_reply(VERSION_REPLY), "17.18.1a")

    def test_native_version_parser_rejects_sensitive_overbroad_reply(self) -> None:
        reply = f"""
        <rpc-reply xmlns="{NETCONF_BASE_NS}" message-id="208">
          <data>
            <native xmlns="{CISCO_NATIVE_NS}">
              <version>17.18.1a</version>
              <line><vty><password><secret>do-not-persist</secret></password></vty></line>
            </native>
          </data>
        </rpc-reply>
        """
        with self.assertRaises(CiscoNetconfEvidenceError):
            parse_iosxe_native_version_reply(reply)

    def test_dtd_and_entity_declarations_are_rejected(self) -> None:
        xml = """<!DOCTYPE hello [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
          <capabilities><capability>&xxe;</capability></capabilities>
          <session-id>1</session-id>
        </hello>"""
        with self.assertRaises(CiscoNetconfEvidenceError):
            parse_server_hello(xml)


if __name__ == "__main__":
    unittest.main()
