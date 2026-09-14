import unittest

from router_configuration.vendors.mikrotik.version_support import (
    VersionConstraint,
    require_supported_version,
)


class MikroTikVersionSupportTests(unittest.TestCase):
    def test_constraint_requires_provenance(self):
        with self.assertRaises(ValueError):
            require_supported_version("7.24.1", VersionConstraint("", "", minimum="7.20"))

    def test_supported_version_accepts_routeros_channel_suffix(self):
        constraint = VersionConstraint(
            "kb-version-rule",
            "https://manual.mikrotik.com/docs/",
            minimum="7.20",
            maximum="7.30",
        )
        require_supported_version("7.24.1 (stable)", constraint)

    def test_out_of_range_fails_closed(self):
        constraint = VersionConstraint(
            "kb-version-rule",
            "https://manual.mikrotik.com/docs/",
            minimum="7.25",
        )
        with self.assertRaisesRegex(ValueError, "UNSUPPORTED_FOR_VERSION"):
            require_supported_version("7.24.1", constraint)


if __name__ == "__main__":
    unittest.main()
