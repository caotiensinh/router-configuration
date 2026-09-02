import unittest

from router_configuration.routeros_renderer import RouterOSSafeSubsetRenderer


class RouterOSRoutingTableSyntaxTests(unittest.TestCase):
    def test_routing_table_create_uses_explicit_fib_yes(self):
        command = RouterOSSafeSubsetRenderer()._ensure_routing_table_command(
            command_id="route.00.table.test",
            operation_id="routing.multiwan.capacity_weighted",
            table="to-wan10g",
            comment="routercfg:managed:routing-table:wan10g",
            risk=30,
        ).command
        self.assertIn("/routing/table/add fib=yes ", command)
        self.assertNotIn("/routing/table/add fib ", command)
        self.assertIn("/routing/table/set $rid fib=yes ", command)


if __name__ == "__main__":
    unittest.main()
