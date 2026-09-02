import unittest

from router_configuration.m01_intent_device import (
    DeviceCapabilities,
    DeviceIdentity,
    NormalizedDevice,
)
from router_configuration.types import Vendor


class IntentDeviceTests(unittest.TestCase):
    def test_normalized_device_and_capabilities(self):
        identity = DeviceIdentity(
            device_id="rd-router-01",
            vendor=Vendor.MIKROTIK,
            model="CCR2116-12G-4S+",
            management_address="192.168.11.1",
        )
        caps = DeviceCapabilities.from_iterable(
            ["dual_wan", "policy_routing", "wireguard", "qos"]
        )
        device = NormalizedDevice(
            identity=identity,
            capabilities=caps,
            interfaces={"wan_primary": "sfp-sfpplus1", "wan_backup": "ether1"},
        )

        self.assertTrue(device.capabilities.supports("WIREGUARD"))
        self.assertEqual(device.interface_for("wan_primary"), "sfp-sfpplus1")

    def test_invalid_management_address_is_rejected(self):
        with self.assertRaises(ValueError):
            DeviceIdentity(
                device_id="router",
                vendor=Vendor.MIKROTIK,
                model="CCR2116",
                management_address="not-an-ip",
            )


if __name__ == "__main__":
    unittest.main()
