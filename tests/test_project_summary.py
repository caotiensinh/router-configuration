import unittest
from router_configuration.project_summary import ProjectSummaryError, build_project_summary

class ProjectSummaryTests(unittest.TestCase):
    def base(self, **kw):
        p=dict(project_name="Omada Automation",canonical_total=340,completed=229,main_sha="4d65d1d2ef107ad873019c112a2d96b416824254",
               durable_task_ids=["5.04","7.10","10.6","13.10"],next_task_ids=["5.05","7.11","10.7","14.1"],
               boundaries=["candidate work does not count"],evidence_refs=["main:4d65d1d2"])
        p.update(kw); return p

    def test_deterministic_durable_summary(self):
        a=build_project_summary(**self.base()).as_dict()
        b=build_project_summary(**self.base()).as_dict()
        self.assertEqual(a,b)
        self.assertEqual(a["durable_progress"]["remaining"],111)
        self.assertEqual(a["durable_progress"]["completion_percent"],67.35)
        self.assertFalse(a["candidate_work_counted"])
        self.assertFalse(a["write_authorized"])

    def test_invalid_count_and_duplicate_tasks_fail_closed(self):
        with self.assertRaises(ProjectSummaryError):
            build_project_summary(**self.base(completed=341))
        with self.assertRaises(ProjectSummaryError):
            build_project_summary(**self.base(durable_task_ids=["5.04","5.04"]))

    def test_bad_main_sha_fails_closed(self):
        with self.assertRaisesRegex(ProjectSummaryError,"SHA-1"):
            build_project_summary(**self.base(main_sha="main"))

if __name__=="__main__": unittest.main()
