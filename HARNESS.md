# Deployment Harness

## Why the harness exists

Router Configuration is not a script launcher. The harness is the control boundary that makes a complex router change repeatable for a non-expert operator.

A vendor adapter may know how to execute commands, but it may never decide when it is safe to execute them. That decision belongs to the harness and M09 Safety Gate.

## Harness responsibilities

The harness must:
- keep execution in a deterministic stage order;
- tell the operator what is happening and what success means;
- require structured evidence before advancing;
- block missing or failed prerequisites;
- keep writes disabled unless explicitly enabled;
- force production backup and management-path checks;
- route failed post-change verification into rollback handling;
- retain stage history and evidence;
- expose a stable machine-readable event stream for future monitoring/AI.

The harness must never:
- issue vendor commands directly;
- fabricate missing network values;
- downgrade a failed safety check to a warning automatically;
- permit an AI component to bypass the plan/safety path;
- persist a configuration before verification.

## Guided operator experience

`GUIDED` mode changes explanations, not safety.

Each active stage provides four pieces of guidance:
1. **Title** — what is being done.
2. **Purpose** — why an expert performs this step.
3. **Success criteria** — what evidence must exist before continuing.
4. **Failure action** — what the operator should fix instead of forcing progress.

The same safety gates apply in `GUIDED`, `ADMIN` and `EXPERT` modes.

## State machine

```text
CREATED
   |
   v
DISCOVER -- device facts
   |
   v
INSPECT -- normalized running state
   |
   v
PLAN -- immutable diff/change plan
   |
   v
VALIDATE -- schema/capability/policy validation
   |
   v
BACKUP -- recoverable pre-change state
   |
   v
PREFLIGHT -- capability + management + baseline
   |
   v
APPROVAL -- authorization bound to exact plan
   |
   v
APPLY -- approved operations only
   |
   v
VERIFY -- routes/firewall/VPN/DNS/WAN/management
   | \
 PASS  FAIL
   |     \
   v      v
SAVE    ROLLBACK
   |        |
   v        v
COMPLETE <- recovery verification
```

## Production gate policy

Production requires all of the following before apply:
- deployment spec validation;
- current device state;
- deterministic plan;
- validation PASS;
- backup PASS;
- vendor capability PASS;
- management path PASS;
- connectivity baseline PASS;
- explicit write-enabled deployment spec;
- explicit approval record.

There is intentionally no `--force` concept in the foundation harness.

## Evidence model

Every evidence record contains:
- evidence kind;
- PASS/FAIL;
- human-readable summary;
- optional artifact reference.

Future revisions will add run ID, plan digest, device state digest, timestamps and signed evidence without changing the stage contract.

## Basic-user deployment workflow

A basic operator should eventually be able to run:

```text
routerctl init
routerctl discover <device>
routerctl plan <profile>
routerctl check <profile>
routerctl apply <profile>
```

Internally, `apply` is never one blind action. It is an orchestration of the harness stages above.

Before write support is enabled, the CLI should stop after PLAN/PREFLIGHT and print exactly what is missing.

## Separation of concerns

```text
Operator / future UI
        |
        v
Deployment Harness
        |
        +--> M01 discovery/state
        +--> M02 diff/plan
        +--> M03 compile/secrets
        +--> M04-M07 policy intelligence
        +--> M09 safety decision
        |
        v
Vendor Adapter
        |
        v
Router
```

The adapter is an execution driver, not the policy brain.

## Future AI boundary

The future AI subsystem will connect to an observability gateway, not directly to router write transports.

Allowed future inputs:
- normalized state snapshots;
- harness evidence;
- interface counters;
- route changes;
- WAN health;
- QoS counters;
- firewall statistics;
- VPN status;
- syslog/event summaries;
- approved telemetry and packet metadata.

Allowed future outputs:
- diagnosis;
- anomaly score;
- maintenance recommendation;
- capacity recommendation;
- proposed intent change.

A proposed intent change must re-enter the normal `PLAN -> VALIDATE -> ...` path. AI does not receive a hidden apply channel.
