# Cisco Parallel Convergence Guard

The convergence guard is the safety boundary between independently tested feature lanes and a later convergence batch.

A candidate batch must contain at least two lanes, all based on the exact same parent SHA. Every lane must have a unique head SHA, PASS required checks, disjoint file ownership, and no production-write authority. Invalid paths, stale bases, duplicate heads, overlapping ownership, or failed checks are rejected.

The guard only produces a deterministic convergence manifest. It never merges branches and never updates the parent ref. A separate integration step must still verify the live parent ref and run combined CI before fast-forwarding.
