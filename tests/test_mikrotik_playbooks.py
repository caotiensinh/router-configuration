import unittest

from router_configuration.vendors.mikrotik.playbooks import get_playbook, playbook_names


class MikroTikPlaybookTests(unittest.TestCase):
    def test_playbooks_are_named_and_capture_is_not_default(self):
        self.assertIn("client_no_internet", playbook_names())
        playbook = get_playbook("client_no_internet")
        self.assertIn("diagnostic", playbook.features)
        self.assertFalse(playbook.capture_default)

    def test_unknown_playbook_fails_closed(self):
        with self.assertRaises(KeyError):
            get_playbook("guess_a_fix")


if __name__ == "__main__":
    unittest.main()
