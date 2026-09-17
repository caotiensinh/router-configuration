import hashlib
import json
import unittest

from router_configuration.vendors.cisco.live_restconf_probe import (
    RestconfHttpEvidence,
    run_live_probe,
)


SOURCE_SHA = "a" * 40
CERT_SHA = "b" * 64
PLATFORM_EVIDENCE_SHA = "d" * 64
CAP_XML = b"""<capabilities xmlns="urn:ietf:params:xml:ns:yang:ietf-restconf-monitoring">
  <capability>urn:ietf:params:restconf:capability:depth:1.0</capability>
  <capability>urn:ietf:params:restconf:capability:fields:1.0</capability>
</capabilities>"""
ROOT_XML = b"""<XRD xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0">
  <Link rel="restconf" href="/restconf"/>
</XRD>"""
IDENTITY = b'{"Cisco-IOS-XE-native:native":{"hostname":"lab-edge","version":"17.18.1a"}}'


def environment(**overrides: str) -> dict[str, str]:
    values = {
        "SOURCE_SHA": SOURCE_SHA,
        "CISCO_RESTCONF_HOST": "router.example",
        "CISCO_RESTCONF_USERNAME": "cred-user-9f3",
        "CISCO_RESTCONF_PASSWORD": "cred-pass-7a1",
        "CISCO_RESTCONF_PORT": "443",
        "CISCO_RESTCONF_TIMEOUT_SECONDS": "5",
    }
    values.update(overrides)
    return values


def bound_environment(**overrides: str) -> dict[str, str]:
    values = environment(
        CISCO_RESTCONF_PLATFORM_MODEL="C8300-2N2S-6T",
        CISCO_RESTCONF_PLATFORM_TARGET_SHA256=hashlib.sha256(
            b"router.example"
        ).hexdigest(),
        CISCO_RESTCONF_PLATFORM_EVIDENCE_SHA256=PLATFORM_EVIDENCE_SHA,
    )
    values.update(overrides)
    return values


def successful_requester(
    query_id,
    url,
    headers,
    ssl_context,
    host,
    port,
    timeout,
    observed_capabilities,
):
    del url, ssl_context, host, port, timeout
    assert headers["Authorization"].startswith("Basic ")
    if query_id == "restconf-root-discovery":
        return RestconfHttpEvidence(200, "application/xrd+xml", ROOT_XML, CERT_SHA)
    if query_id == "restconf-capabilities":
        return RestconfHttpEvidence(200, "application/yang-data+xml", CAP_XML, CERT_SHA)
    if query_id == "native-identity":
        assert observed_capabilities is not None
        assert observed_capabilities.supports_fields
        return RestconfHttpEvidence(200, "application/yang-data+json", IDENTITY, CERT_SHA)
    raise AssertionError(query_id)


class CiscoLiveRestconfProbeTests(unittest.TestCase):
    def test_missing_credentials_are_sanitized(self) -> None:
        env = environment(CISCO_RESTCONF_PASSWORD="")
        evidence = run_live_probe(env, successful_requester)
        rendered = json.dumps(evidence, sort_keys=True)
        self.assertEqual(evidence["result"], "credentials_missing")
        self.assertEqual(evidence["missing_required_value_count"], 1)
        self.assertNotIn("CISCO_RESTCONF_PASSWORD", rendered)
        self.assertNotIn("cred-pass-7a1", rendered)
        self.assertNotIn("cred-user-9f3", rendered)
        self.assertFalse(evidence["c04_complete"])

    def test_live_restconf_without_independent_platform_binding_stays_incomplete(self) -> None:
        evidence = run_live_probe(environment(), successful_requester)
        rendered = json.dumps(evidence, sort_keys=True)
        self.assertEqual(evidence["result"], "live_restconf_verified_platform_binding_required")
        self.assertTrue(evidence["live_target_observed"])
        self.assertTrue(evidence["fields_capability_observed"])
        self.assertEqual(evidence["documentation_train"], "17.18")
        self.assertEqual(evidence["peer_certificate_sha256"], CERT_SHA)
        self.assertFalse(evidence["platform_evidence_bound"])
        self.assertEqual(evidence["platform_admission_status"], "PLATFORM_EVIDENCE_REQUIRED")
        self.assertFalse(evidence["c04_complete"])
        self.assertNotIn("router.example", rendered)
        self.assertNotIn("lab-edge", rendered)
        self.assertNotIn("cred-user-9f3", rendered)
        self.assertNotIn("cred-pass-7a1", rendered)

    def test_happy_path_requires_bound_admitted_platform_and_is_minimized(self) -> None:
        evidence = run_live_probe(bound_environment(), successful_requester)
        rendered = json.dumps(evidence, sort_keys=True)
        self.assertEqual(evidence["result"], "live_readonly_admitted")
        self.assertTrue(evidence["live_target_observed"])
        self.assertTrue(evidence["c04_complete"])
        self.assertTrue(evidence["platform_evidence_bound"])
        self.assertEqual(evidence["platform_admission_status"], "DOCUMENTED_READ_ONLY_CANDIDATE")
        self.assertEqual(evidence["platform_family"], "Catalyst 8300")
        self.assertEqual(evidence["admitted_model"], "C8300-2N2S-6T")
        self.assertEqual(evidence["platform_evidence_digest_sha256"], PLATFORM_EVIDENCE_SHA)
        self.assertFalse(evidence["production_write_authorized"])
        self.assertFalse(evidence["physical_device_verified"])
        self.assertFalse(evidence["write_operations_performed"])
        self.assertNotIn("router.example", rendered)
        self.assertNotIn("lab-edge", rendered)
        self.assertNotIn("cred-user-9f3", rendered)
        self.assertNotIn("cred-pass-7a1", rendered)
        self.assertNotIn("Authorization", rendered)

    def test_platform_target_binding_mismatch_fails_closed(self) -> None:
        evidence = run_live_probe(
            bound_environment(CISCO_RESTCONF_PLATFORM_TARGET_SHA256="e" * 64),
            successful_requester,
        )
        self.assertFalse(evidence["platform_evidence_bound"])
        self.assertEqual(evidence["platform_admission_status"], "PLATFORM_TARGET_BINDING_MISMATCH")
        self.assertFalse(evidence["c04_complete"])

    def test_unadmitted_platform_fails_closed(self) -> None:
        evidence = run_live_probe(
            bound_environment(CISCO_RESTCONF_PLATFORM_MODEL="N9K-C93180YC-FX"),
            successful_requester,
        )
        self.assertFalse(evidence["platform_evidence_bound"])
        self.assertEqual(evidence["platform_admission_status"], "UNVERIFIED_PLATFORM")
        self.assertFalse(evidence["c04_complete"])

    def test_missing_fields_capability_fails_closed(self) -> None:
        def requester(*args, **kwargs):
            response = successful_requester(*args, **kwargs)
            if args[0] == "restconf-capabilities":
                return RestconfHttpEvidence(
                    200,
                    "application/yang-data+xml",
                    CAP_XML.replace(
                        b"<capability>urn:ietf:params:restconf:capability:fields:1.0</capability>",
                        b"",
                    ),
                    CERT_SHA,
                )
            return response

        evidence = run_live_probe(bound_environment(), requester)
        self.assertEqual(evidence["result"], "required_capability_missing")
        self.assertFalse(evidence["c04_complete"])

    def test_unsupported_iosxe_version_fails_closed(self) -> None:
        def requester(*args, **kwargs):
            response = successful_requester(*args, **kwargs)
            if args[0] == "native-identity":
                return RestconfHttpEvidence(
                    200,
                    "application/yang-data+json",
                    IDENTITY.replace(b"17.18.1a", b"17.12.4"),
                    CERT_SHA,
                )
            return response

        evidence = run_live_probe(bound_environment(), requester)
        self.assertEqual(evidence["result"], "unverified_iosxe_version")
        self.assertFalse(evidence["c04_complete"])

    def test_peer_certificate_change_fails_closed(self) -> None:
        def requester(*args, **kwargs):
            response = successful_requester(*args, **kwargs)
            if args[0] == "native-identity":
                return RestconfHttpEvidence(
                    response.status_code,
                    response.content_type,
                    response.body,
                    "c" * 64,
                )
            return response

        evidence = run_live_probe(bound_environment(), requester)
        self.assertEqual(evidence["result"], "peer_certificate_changed")
        self.assertFalse(evidence["c04_complete"])

    def test_optional_expected_certificate_pin_is_enforced(self) -> None:
        mismatch = run_live_probe(
            bound_environment(CISCO_RESTCONF_CERT_SHA256="f" * 64),
            successful_requester,
        )
        self.assertEqual(mismatch["result"], "peer_certificate_pin_mismatch")
        self.assertFalse(mismatch["c04_complete"])

        admitted = run_live_probe(
            bound_environment(CISCO_RESTCONF_CERT_SHA256=CERT_SHA),
            successful_requester,
        )
        self.assertTrue(admitted["c04_complete"])

    def test_invalid_peer_certificate_digest_fails_closed(self) -> None:
        def requester(*args, **kwargs):
            response = successful_requester(*args, **kwargs)
            return RestconfHttpEvidence(
                response.status_code,
                response.content_type,
                response.body,
                "not-a-digest",
            )

        evidence = run_live_probe(bound_environment(), requester)
        self.assertEqual(evidence["result"], "invalid_peer_certificate_digest")
        self.assertFalse(evidence["c04_complete"])

    def test_invalid_target_or_ca_never_echoes_input(self) -> None:
        target = "https://user:pass@router.example"
        first = run_live_probe(environment(CISCO_RESTCONF_HOST=target), successful_requester)
        self.assertEqual(first["result"], "invalid_target_host")
        self.assertNotIn(target, json.dumps(first))

        bad_ca = "not-base64!"
        second = run_live_probe(environment(CISCO_RESTCONF_CA_PEM_B64=bad_ca), successful_requester)
        self.assertEqual(second["result"], "invalid_ca_bundle")
        self.assertNotIn(bad_ca, json.dumps(second))

    def test_unexpected_exception_is_sanitized(self) -> None:
        def requester(*args, **kwargs):
            del args, kwargs
            raise RuntimeError("router.example cred-user-9f3 cred-pass-7a1")

        evidence = run_live_probe(bound_environment(), requester)
        rendered = json.dumps(evidence)
        self.assertEqual(evidence["result"], "probe_process_failed")
        self.assertEqual(evidence["failure_class"], "RuntimeError")
        self.assertNotIn("router.example", rendered)
        self.assertNotIn("cred-user-9f3", rendered)
        self.assertNotIn("cred-pass-7a1", rendered)
        self.assertFalse(evidence["c04_complete"])

    def test_invalid_source_sha_blocks_probe_before_network(self) -> None:
        calls = []

        def requester(*args, **kwargs):
            calls.append((args, kwargs))
            return successful_requester(*args, **kwargs)

        evidence = run_live_probe(bound_environment(SOURCE_SHA="bad"), requester)
        self.assertEqual(evidence["result"], "source_sha_missing_or_invalid")
        self.assertEqual(calls, [])
        self.assertFalse(evidence["c04_complete"])


if __name__ == "__main__":
    unittest.main()
