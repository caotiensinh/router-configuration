import unittest

from router_configuration.routeros_renderer import RouterOSSafeSubsetRenderer


class RouterOSRoutingTableSyntaxTests(unittest.TestCase):
    def test_routing_table_command_only_creates_missing_fib_table(self):
        command = RouterOSSafeSubsetRenderer()._ensure_routing_table_command(
            command_id="route.00.table.test",
            operation_id="routing.multiwan.capacity_weighted",
            table="to-wan10g",
            risk=30,
        ).command
        self.assertIn('/routing/table/add name="to-wan10g" fib', command)
        self.assertNotIn("/routing/table/set", command)
        self.assertNotIn("comment=", command)
        self.assertNotIn("/routing/table/add fib=yes", command)


if __name__ == "__main__":
    unittest.main()
