import unittest

from router_configuration.routeros_renderer import RouterOSSafeSubsetRenderer


class RouterOSRoutingTableSyntaxTests(unittest.TestCase):
    def test_routing_table_command_reconciles_fib_switch_on_create_and_drift(self):
        command = RouterOSSafeSubsetRenderer()._ensure_routing_table_command(
            command_id="route.00.table.test",
            operation_id="routing.multiwan.capacity_weighted",
            table="to-wan10g",
            risk=30,
        ).command
        self.assertIn(':local rid [/routing/table/find where name="to-wan10g"]', command)
        self.assertIn('/routing/table/add name="to-wan10g" fib', command)
        self.assertIn('/routing/table/set $rid fib', command)
        self.assertNotIn("fib=yes", command)
        self.assertNotIn("comment=", command)


if __name__ == "__main__":
    unittest.main()
