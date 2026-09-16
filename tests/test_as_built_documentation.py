import unittest
from router_configuration.as_built_documentation import AsBuiltDocumentationError, build_as_built_documentation

SHA="a"*40
DIGEST="b"*64

def summary():
    return {"claim":"durable_project_summary_only","current_main":SHA,"candidate_work_counted":False,"write_authorized":False}

def report():
    return {"claim":"verified_configuration_report_only","current_main":SHA,
            "fresh_independent_readback_required":True,"secret_material_included":False,
            "write_authorized":False,"configuration_report_sha256":DIGEST}

class AsBuiltDocumentationTests(unittest.TestCase):
    def test_as_built_is_deterministic_bound_and_non_executable(self):
        kwargs=dict(project_summary=summary(),configuration_report=report(),
                    topology={"sites":[{"name":"lab","links":["gw-sw"]}]},
                    inventory=[{"role":"gateway","model":"ER-x","management_ip":"192.0.2.1"}],
                    management_paths=["admin->controller->gateway"],evidence_refs=["evidence://final-readback"])
        a=build_as_built_documentation(**kwargs).as_dict()
        b=build_as_built_documentation(**kwargs).as_dict()
        self.assertEqual(a,b)
        self.assertEqual(a["current_main"],SHA)
        self.assertEqual(a["source_configuration_report_sha256"],DIGEST)
        self.assertFalse(a["write_authorized"])
        self.assertFalse(a["transport_present"])

    def test_mismatched_or_unverified_upstream_report_fails_closed(self):
        bad=report(); bad["current_main"]="c"*40
        with self.assertRaises(AsBuiltDocumentationError):
            build_as_built_documentation(project_summary=summary(),configuration_report=bad,
                topology={"sites":["lab"]},inventory=[{"role":"gateway"}],
                management_paths=["admin->controller"],evidence_refs=["evidence://x"])
        bad=report(); bad["claim"]="candidate"
        with self.assertRaises(AsBuiltDocumentationError):
            build_as_built_documentation(project_summary=summary(),configuration_report=bad,
                topology={"sites":["lab"]},inventory=[{"role":"gateway"}],
                management_paths=["admin->controller"],evidence_refs=["evidence://x"])

    def test_secret_or_runtime_fields_fail_closed_recursively(self):
        with self.assertRaises(AsBuiltDocumentationError):
            build_as_built_documentation(project_summary=summary(),configuration_report=report(),
                topology={"sites":[{"name":"lab","credential":"nope"}]},
                inventory=[{"role":"gateway"}],management_paths=["admin->controller"],evidence_refs=["evidence://x"])
        with self.assertRaises(AsBuiltDocumentationError):
            build_as_built_documentation(project_summary=summary(),configuration_report=report(),
                topology={"sites":["lab"]},inventory=[{"role":"gateway","commands":["write"]}],
                management_paths=["admin->controller"],evidence_refs=["evidence://x"])

if __name__ == "__main__":
    unittest.main()
