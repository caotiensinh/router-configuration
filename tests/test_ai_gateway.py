import unittest

from router_configuration.ai_gateway import (
    AIGateway,
    AIGatewayPolicy,
    AIRecommendation,
    RecommendationKind,
    TelemetryEnvelope,
    TelemetryTopic,
)


class AIGatewayTests(unittest.TestCase):
    def test_gateway_rejects_direct_write_policy(self):
        with self.assertRaises(ValueError):
            AIGateway(AIGatewayPolicy(allow_direct_device_write=True))

    def test_gateway_accepts_redacted_operational_telemetry(self):
        gateway = AIGateway()
        envelope = TelemetryEnvelope(
            schema_version="1.0",
            device_id="rd-router-01",
            topic=TelemetryTopic.INTERFACE_COUNTERS,
            payload={"wan10g": {"rx_bps": 8000000000, "tx_bps": 1000000000}},
        )
        self.assertTrue(gateway.accept_telemetry(envelope).accepted)

    def test_gateway_rejects_sensitive_fields(self):
        gateway = AIGateway()
        envelope = TelemetryEnvelope(
            schema_version="1.0",
            device_id="rd-router-01",
            topic=TelemetryTopic.DEVICE_STATE,
            payload={"vpn": {"private_key": "must-not-leave-control-plane"}},
        )
        decision = gateway.accept_telemetry(envelope)
        self.assertFalse(decision.accepted)
        self.assertTrue(any("private_key" in reason for reason in decision.reasons))

    def test_raw_packet_payload_is_disabled_by_default(self):
        gateway = AIGateway()
        envelope = TelemetryEnvelope(
            schema_version="1.0",
            device_id="rd-router-01",
            topic=TelemetryTopic.RAW_PACKET,
            payload={"bytes": "001122"},
        )
        self.assertFalse(gateway.accept_telemetry(envelope).accepted)

    def test_ai_change_proposal_must_reenter_harness(self):
        gateway = AIGateway()
        recommendation = AIRecommendation(
            kind=RecommendationKind.PROPOSED_INTENT,
            title="Move backup traffic to WAN1G",
            summary="WAN10G saturation is sustained during backup window.",
            confidence=0.88,
            proposed_intent={"traffic_policy": {"backup": {"wan_preference": "wan1g"}}},
        )
        self.assertTrue(gateway.accept_recommendation(recommendation).accepted)
        self.assertEqual(
            gateway.execution_route_for(recommendation),
            ("intent_review", "plan", "validate", "safety_gate", "approval"),
        )


if __name__ == "__main__":
    unittest.main()
