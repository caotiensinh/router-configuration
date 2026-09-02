# Future AI / Observability Gateway Contract

## Status

Reserved interface only. AI analysis is **not** part of the current implementation phase.

Current engineering priority remains deterministic router configuration and automation.

## Purpose

The gateway reserves one safe integration point for a future internal AI agent that can analyze network behavior without receiving a hidden device-write path.

Future AI use cases may include:
- bandwidth utilization analysis;
- interface error/drop analysis;
- WAN quality and failover trend analysis;
- routing-change analysis;
- firewall event/statistics analysis;
- QoS effectiveness analysis;
- VPN health analysis;
- flow metadata analysis;
- packet metadata analysis;
- syslog/event summarization;
- anomaly detection;
- maintenance recommendations;
- capacity/upgrade recommendations;
- proposed intent changes.

## Trust boundary

```text
Router / Controller
        |
        v
Read-only collectors
        |
        v
Normalization + redaction
        |
        v
Observability / AI Gateway
        |
        +--> internal AI analysis
        |
        +--> advisory
        +--> diagnosis
        +--> maintenance recommendation
        +--> proposed intent
                    |
                    v
             Intent review
                    |
                    v
        Normal configuration harness
```

The AI path does not connect to a vendor adapter write transport.

## Default data policy

Accepted by default:
- normalized device state;
- interface counters;
- WAN health scores;
- route state/change summaries;
- firewall counters and event summaries;
- QoS counters;
- VPN status without keys/secrets;
- harness evidence;
- redacted logs;
- flow metadata;
- packet metadata.

Rejected by default:
- passwords;
- tokens;
- API secrets;
- private keys;
- preshared keys;
- unredacted credentials;
- raw packet payload.

Raw packet payload is intentionally disabled in the foundation gateway. A future local-only packet-analysis feature must have a separate privacy/security specification and explicit operator opt-in.

## Recommendation contract

AI output may be:
- observation;
- diagnosis;
- maintenance recommendation;
- capacity recommendation;
- security recommendation;
- proposed network intent.

A proposed network intent is not an executable command. Its route is always:

`intent review -> plan -> validate -> safety gate -> approval`

Only after that normal path may a future executor consider apply.

## Future telemetry examples

Bandwidth/capacity:
- bytes/sec and bits/sec;
- utilization percentage;
- 95th percentile utilization;
- peak windows;
- congestion duration.

Packet/interface health:
- packet rate;
- drops;
- errors;
- retransmission indicators when available as metadata;
- MTU/fragmentation indicators;
- queue drops.

Traffic/flow statistics:
- source/destination zone;
- protocol;
- service class;
- bytes/packets;
- duration;
- selected WAN;
- policy decision identifier.

Logs/events:
- WAN up/down;
- route changes;
- VPN peer changes;
- firewall denies;
- authentication failures;
- high CPU/memory/temperature;
- configuration changes;
- harness apply/verify/rollback events.

## Future maintenance reasoning

An AI agent may eventually correlate:

`capacity trend + errors + failover history + firmware age + configuration drift + incident history`

and produce a recommendation such as:
- increase WAN capacity;
- move a traffic class;
- review a failing optic/cable;
- schedule firmware validation;
- adjust QoS intent;
- investigate a repeated route flap.

It remains advisory until a human-approved intent enters the normal harness.
