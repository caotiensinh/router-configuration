# Omada Configuration Templates / Profiles — Task 7.06

Omada has several reusable-configuration planes and they must not be collapsed into one object. A Site Template controls supported site modules from Global View; a Device Template targets supported gateway/switch models; a switch port profile is applied to ports and can be locally overridden; feature reference profiles are reusable objects consumed by specific features. A local override is state, not a new template.

The current Site Template guide documents Controller v5.15.20 or above for Software Controller and Cloud-Based Controller. The automation therefore does not infer current Hardware Controller support without separate authoritative evidence. Configurable modules selected when a Site Template is created cannot later be changed, so module selection is part of the immutable template identity.

Binding a site synchronizes the template configuration immediately. Device templates are model-bound; the guide warns that incorrect automatic binding can disconnect the network. Gateway templates can overwrite WAN-related configuration. Re-Apply restores managed settings to the template, while unbinding stops future synchronization but retains the current configuration, including local overrides.

A template operation is therefore treated as a potentially broad write. Before bind/reapply, compute the exact desired-vs-current diff, check the management path and identify overrides that would be removed. A successful click or accepted controller operation remains `EXECUTED_UNVERIFIED`; PASS requires fresh read-back of the binding/inheritance state plus management and representative service health.
