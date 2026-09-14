import unittest

from router_configuration.mikrotik_docs import (
    DocumentationAuthority,
    documentation_sources,
    topic_url,
)


class MikroTikDocsTests(unittest.TestCase):
    def test_current_manual_outranks_legacy_help(self):
        sources = documentation_sources()
        current = [s for s in sources if s.authority is DocumentationAuthority.CURRENT_OFFICIAL]
        legacy = [s for s in sources if s.authority is DocumentationAuthority.LEGACY]
        self.assertTrue(current)
        self.assertTrue(legacy)
        self.assertGreater(min(s.authority for s in current), max(s.authority for s in legacy))

    def test_per_page_markdown_endpoint_is_deterministic(self):
        self.assertEqual(
            topic_url("wireguard", markdown=True),
            "https://manual.mikrotik.com/docs/virtual-private-networks/wireguard.md",
        )


if __name__ == "__main__":
    unittest.main()
