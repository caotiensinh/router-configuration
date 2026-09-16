# Omada Engineering Patterns

Reusable lessons extracted from durable work. These patterns apply to future Omada/network-automation tasks unless a stronger task-specific rule overrides them.

## 1. Capability-plane separation
A capability proven in standalone device mode is not automatically a Controller capability, and one Controller type/version does not imply parity with another. Every capability claim is bound to its exact management plane and applicability tuple.

## 2. Vendor fact vs security policy
Keep documented vendor capabilities separate from project security policy. A desirable hardening control must never be represented as a supported Omada operation unless exact product/controller/firmware/topology evidence proves it.

## 3. Independent read-back verification
Never reuse the apply observation as verification evidence. Acquire a fresh, independent managed-state read-back, normalize it, compare it deterministically to desired state, and preserve drift evidence. A successful write remains EXECUTED_UNVERIFIED until this gate passes.

## 4. Evidence-first RCA
Troubleshooting starts with exact symptom scope and read-only evidence. Inspect logs/state/counters and the relevant dependency path before mutation. If evidence cannot isolate the cause, record ROOT_CAUSE_UNRESOLVED instead of guessing.

## 5. Blocker fallback without lowering assurance
When one execution path is blocked (for example, container DNS prevents git clone), switch to an alternate evidence path such as connector-fetched exact source plus a minimal local test workspace. Preserve the same validation gates; do not trade a blocker for weaker evidence.

## 6. Template/profile operations are broad writes
Bind, reapply, inheritance changes, and auto-bind can affect many managed objects. Require an exact pre-diff, management-path impact analysis, override analysis, fresh read-back, and representative service checks.

## 7. Exact-byte promotion
The durable artifact path is: implement -> validate -> Library persist -> Library read-back -> materialize exact snapshot -> compute/verify Git blob identity -> branch gate -> selective main promotion -> main gate -> canonical update. Similar-looking local files are not sufficient evidence.

## 8. Test-discovery verification
CI green is not test evidence unless the intended tests were actually collected and executed by the runner's real test command. Inspect runner logs for the target test names after adding or changing test layout/framework. Import-only or uncollected tests do not count as PASS.

## 9. Reuse proven architecture before adding parallel logic
Before implementing a new lifecycle or safety feature, inspect the existing transaction/state/harness flow. Extend proven boundaries and invariants rather than building a second, divergent state machine.

## 10. Durable progress accounting
Planning, branch creation, candidate artifacts, waiting CI, and unverified writes add zero canonical progress. Count a task only after persistence, tests, exact promotion, main CI/Governance, and canonical read-back all pass.
