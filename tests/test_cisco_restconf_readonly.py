import unittest

from router_configuration.vendors.cisco import CiscoOfflineKnowledge
from router_configuration.vendors.cisco.restconf_readonly import (
    CiscoRestconfEvidenceError,
    parse_native_identity_json,
    parse_restconf_root_discovery,
    parse_yang_json_response,
    query_definition,
    validate_restconf_request,
)


class CiscoRestconfReadOnlyTests(unittest.TestCase):
    def test_catalog_is_get_only_tls_verified_and_live_gated(self) -> None:
        catalog = CiscoOfflineKnowledge().restconf_readonly_catalog
        self.assertEqual([item["name"] for item in catalog["allowed_methods"]], ["GET"])
        self.assertEqual(
            set(catalog["blocked_methods"]),
            {"POST", "PUT", "PATCH", "DELETE"},
        )
        self.assertEqual(catalog["transport"]["scheme"], "https")
        self.assertTrue(catalog["transport"]["tls_certificate_verification_required"])
        self.assertFalse(catalog["transport"]["follow_redirects"])
        boundaries = catalog["admission_boundaries"]
        self.assertTrue(boundaries["live_target_required_for_c04_completion"])
        self.assertFalse(boundaries["synthetic_fixture_can_complete_c04"])
        self.assertFalse(boundaries["production_write_authorized"])
        self.assertFalse(boundaries["physical_device_verified"])

    def test_known_root_discovery_get_is_allowed(self) -> None:
        decision = validate_restconf_request(
            query_id="restconf-root-discovery",
            method="GET",
            url="https://router.example/.well-known/host-meta",
            headers={"Accept": "application/xrd+xml"},
            verify_tls=True,
            allow_redirects=False,
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.status, "READ_ONLY_GET_ALLOWED")

    def test_known_native_identity_get_is_allowed(self) -> None:
        query = query_definition("native-identity")
        self.assertEqual(
            query.relative_uri,
            "/restconf/data/Cisco-IOS-XE-native:native?fields=hostname;version",
        )
        decision = validate_restconf_request(
            query_id=query.query_id,
            method="GET",
            url="https://router.example" + query.relative_uri,
            headers={"accept": "application/yang-data+json; charset=utf-8"},
            verify_tls=True,
            allow_redirects=False,
        )
        self.assertTrue(decision.allowed)

    def test_mutating_methods_fail_closed(self) -> None:
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                decision = validate_restconf_request(
                    query_id="restconf-root-discovery",
                    method=method,
                    url="https://router.example/.well-known/host-meta",
                    headers={"Accept": "application/xrd+xml"},
                    verify_tls=True,
                    allow_redirects=False,
                )
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.status, "WRITE_OR_UNAPPROVED_METHOD")

    def test_tls_redirect_and_uri_uncertainty_fail_closed(self) -> None:
        tls = validate_restconf_request(
            query_id="restconf-root-discovery",
            method="GET",
            url="https://router.example/.well-known/host-meta",
            headers={"Accept": "application/xrd+xml"},
            verify_tls=False,
            allow_redirects=False,
        )
        redirects = validate_restconf_request(
            query_id="restconf-root-discovery",
            method="GET",
            url="https://router.example/.well-known/host-meta",
            headers={"Accept": "application/xrd+xml"},
            verify_tls=True,
            allow_redirects=True,
        )
        http = validate_restconf_request(
            query_id="restconf-root-discovery",
            method="GET",
            url="http://router.example/.well-known/host-meta",
            headers={"Accept": "application/xrd+xml"},
            verify_tls=True,
            allow_redirects=False,
        )
        invented = validate_restconf_request(
            query_id="restconf-root-discovery",
            method="GET",
            url="https://router.example/restconf/data/arbitrary",
            headers={"Accept": "application/xrd+xml"},
            verify_tls=True,
            allow_redirects=False,
        )
        self.assertEqual(tls.status, "TLS_VERIFICATION_REQUIRED")
        self.assertEqual(redirects.status, "REDIRECTS_NOT_ALLOWED")
        self.assertEqual(http.status, "HTTPS_REQUIRED")
        self.assertEqual(invented.status, "UNVERIFIED_URI")

    def test_unknown_query_and_url_credentials_are_rejected(self) -> None:
        unknown = validate_restconf_request(
            query_id="invented-query",
            method="GET",
            url="https://router.example/restconf/data/foo",
            headers={"Accept": "application/yang-data+json"},
            verify_tls=True,
            allow_redirects=False,
        )
        embedded = validate_restconf_request(
            query_id="restconf-root-discovery",
            method="GET",
            url="https://user:password@router.example/.well-known/host-meta",
            headers={"Accept": "application/xrd+xml"},
            verify_tls=True,
            allow_redirects=False,
        )
        self.assertEqual(unknown.status, "UNVERIFIED_QUERY")
        self.assertEqual(embedded.status, "URL_CREDENTIALS_FORBIDDEN")

    def test_root_discovery_parser_requires_exact_restconf_link(self) -> None:
        body = """<XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'>
          <Link rel='restconf' href='/restconf'/>
        </XRD>"""
        first = parse_restconf_root_discovery(
            status_code=200,
            content_type="application/xrd+xml",
            body=body,
        )
        second = parse_restconf_root_discovery(
            status_code=200,
            content_type="application/xrd+xml; charset=UTF-8",
            body=body,
        )
        self.assertEqual(first.root_href, "/restconf")
        self.assertEqual(first.digest_sha256, second.digest_sha256)
        with self.assertRaises(CiscoRestconfEvidenceError):
            parse_restconf_root_discovery(
                status_code=200,
                content_type="application/xrd+xml",
                body=body.replace("/restconf", "/other"),
            )
        with self.assertRaises(CiscoRestconfEvidenceError):
            parse_restconf_root_discovery(
                status_code=200,
                content_type="application/xrd+xml",
                body="<!DOCTYPE XRD><XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'/>",
            )

    def test_native_identity_json_is_minimized_and_deterministic(self) -> None:
        body = (
            '{"Cisco-IOS-XE-native:native":'
            '{"hostname":"edge-1","version":"17.18.1a"}}'
        )
        first = parse_native_identity_json(
            status_code=200,
            content_type="application/yang-data+json",
            body=body,
        )
        second = parse_native_identity_json(
            status_code=200,
            content_type="application/yang-data+json; charset=utf-8",
            body=body,
        )
        self.assertEqual(first.hostname, "edge-1")
        self.assertEqual(first.iosxe_version, "17.18.1a")
        self.assertEqual(first.digest_sha256, second.digest_sha256)
        self.assertEqual(len(first.digest_sha256), 64)

    def test_secret_or_overbroad_json_is_rejected(self) -> None:
        secret = (
            '{"Cisco-IOS-XE-native:native":'
            '{"hostname":"edge-1","version":"17.18.1a","password":"x"}}'
        )
        broad = (
            '{"Cisco-IOS-XE-native:native":'
            '{"hostname":"edge-1","version":"17.18.1a","domain":{"name":"example"}}}'
        )
        with self.assertRaises(CiscoRestconfEvidenceError):
            parse_yang_json_response(
                status_code=200,
                content_type="application/yang-data+json",
                body=secret,
            )
        with self.assertRaises(CiscoRestconfEvidenceError):
            parse_native_identity_json(
                status_code=200,
                content_type="application/yang-data+json",
                body=broad,
            )

    def test_non_200_and_wrong_media_type_are_rejected(self) -> None:
        with self.assertRaises(CiscoRestconfEvidenceError):
            parse_yang_json_response(
                status_code=401,
                content_type="application/yang-data+json",
                body='{"error":"unauthorized"}',
            )
        with self.assertRaises(CiscoRestconfEvidenceError):
            parse_yang_json_response(
                status_code=200,
                content_type="text/html",
                body="<html/>",
            )


if __name__ == "__main__":
    unittest.main()
