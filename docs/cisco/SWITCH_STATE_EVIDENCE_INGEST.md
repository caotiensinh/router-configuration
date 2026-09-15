# Cisco C06 Switch-State Evidence Ingest

This contract binds an already normalized C06 switch-state artifact to sanitized provenance from a future live IOS XE read-only run. It requires the normalized state to have already satisfied the switch-state contract and to carry the exact current schema/catalog/state digests.

Synthetic fixtures, write attempts, non-live origins, and self-promotion flags are rejected. A successful ingest record still keeps `repository_live_evidence_accepted=false`, `c06_complete=false`, `physical_device_verified=false`, and `production_write_authorized=false`.

The ingest layer does not connect to a device and does not replace the canonical live evidence gate.
