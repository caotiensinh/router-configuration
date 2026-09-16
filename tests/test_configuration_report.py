import unittest

from router_configuration.configuration_report import ConfigurationReportError, build_configuration_report


def final_validation():
    return {
        "transaction_id":"a"*64,
        "acceptance":"PASS",
        "desired_matches_actual":True,
        "fresh_read":True,
        "independently_acquired":True,
        "final_validation_sha256":"b"*64,
    }


class ConfigurationReportTests(unittest.TestCase):
    def test_verified_report_is_deterministic_secret_safe_and_non_executable(self):
        kw=dict(
            project_name="Omada",
            main_sha="785c260f39e7ee8431fef60faa037fb12c2f3f30",
            final_validation=final_validation(),
            verified_configuration={"vlans":{"camera":30},"routing":{"default":"wan1"}},
            scope=["gateway","switch"],
            evidence_refs=["final:validation","readback:fresh"],
            deviations=["none"],
        )
        a=build_configuration_report(**kw).as_dict()
        b=build_configuration_report(**kw).as_dict()
        self.assertEqual(a,b)
        self.assertEqual(a["claim"],"verified_configuration_report_only")
        self.assertFalse(a["secret_material_included"])
        self.assertFalse(a["transport_present"])
        self.assertFalse(a["write_authorized"])
        self.assertEqual(len(a["configuration_sha256"]),64)

    def test_nonpassing_or_nonfresh_final_validation_fails_closed(self):
        bad=final_validation(); bad["acceptance"]="FAIL"
        with self.assertRaises(ConfigurationReportError):
            build_configuration_report(project_name="Omada",main_sha="785c260f39e7ee8431fef60faa037fb12c2f3f30",final_validation=bad,verified_configuration={"x":1},scope=["gateway"],evidence_refs=["e1"])
        stale=final_validation(); stale["fresh_read"]=False
        with self.assertRaises(ConfigurationReportError):
            build_configuration_report(project_name="Omada",main_sha="785c260f39e7ee8431fef60faa037fb12c2f3f30",final_validation=stale,verified_configuration={"x":1},scope=["gateway"],evidence_refs=["e1"])

    def test_secret_and_runtime_fields_fail_closed_recursively(self):
        for config in (
            {"vpn":{"private_key":"secret"}},
            {"api":{"client_secret":"secret"}},
            {"device":{"nested":[{"password":"secret"}]}},
            {"runtime":{"commands":["set x"]}},
        ):
            with self.assertRaises(ConfigurationReportError):
                build_configuration_report(project_name="Omada",main_sha="785c260f39e7ee8431fef60faa037fb12c2f3f30",final_validation=final_validation(),verified_configuration=config,scope=["gateway"],evidence_refs=["e1"])

if __name__=="__main__": unittest.main()
