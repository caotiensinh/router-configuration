
PRAGMA foreign_keys = ON;

CREATE TABLE vendor (
    vendor_id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    business_brand TEXT
);

CREATE TABLE product (
    product_id INTEGER PRIMARY KEY,
    vendor_id INTEGER NOT NULL REFERENCES vendor(vendor_id),
    exact_model TEXT NOT NULL UNIQUE,
    product_family TEXT NOT NULL,
    subfamily TEXT,
    automation_class TEXT,
    source_artifact TEXT,
    is_bundle INTEGER NOT NULL DEFAULT 0 CHECK (is_bundle IN (0,1)),
    is_direct_config_target INTEGER CHECK (is_direct_config_target IN (0,1)),
    created_at TEXT NOT NULL
);

CREATE TABLE product_alias (
    alias_id INTEGER PRIMARY KEY,
    product_id INTEGER NOT NULL REFERENCES product(product_id),
    alias_raw TEXT NOT NULL,
    relation_kind TEXT NOT NULL,
    verification_status TEXT NOT NULL DEFAULT 'UNVERIFIED',
    source_id INTEGER,
    UNIQUE(product_id, alias_raw, relation_kind)
);

CREATE TABLE region_scope (
    region_scope_id INTEGER PRIMARY KEY,
    raw_marker TEXT NOT NULL,
    resolved_market TEXT,
    portal_locale TEXT,
    resolution_status TEXT NOT NULL DEFAULT 'UNVERIFIED'
);
CREATE UNIQUE INDEX uq_region_scope
ON region_scope(raw_marker, IFNULL(resolved_market,''), IFNULL(portal_locale,''));

CREATE TABLE hardware_revision (
    hardware_revision_id INTEGER PRIMARY KEY,
    product_id INTEGER NOT NULL REFERENCES product(product_id),
    version_raw TEXT NOT NULL,
    normalized_version TEXT,
    vendor_notation TEXT,
    region_scope_id INTEGER REFERENCES region_scope(region_scope_id),
    evidence_status TEXT NOT NULL,
    source_artifact TEXT
);
CREATE UNIQUE INDEX uq_hardware_revision_scope
ON hardware_revision(product_id, version_raw, IFNULL(region_scope_id, -1));

CREATE TABLE management_mode (
    management_mode_id INTEGER PRIMARY KEY,
    mode_code TEXT NOT NULL UNIQUE,
    management_plane TEXT NOT NULL,
    description TEXT,
    is_direct_device_mode INTEGER NOT NULL CHECK (is_direct_device_mode IN (0,1))
);

CREATE TABLE controller_platform (
    controller_platform_id INTEGER PRIMARY KEY,
    platform_key TEXT NOT NULL UNIQUE,
    product_id INTEGER REFERENCES product(product_id),
    controller_type TEXT NOT NULL,
    product_name TEXT NOT NULL,
    tier TEXT,
    version_raw TEXT,
    management_plane TEXT NOT NULL
);

CREATE TABLE firmware_release (
    firmware_release_id INTEGER PRIMARY KEY,
    product_id INTEGER NOT NULL REFERENCES product(product_id),
    hardware_revision_id INTEGER REFERENCES hardware_revision(hardware_revision_id),
    region_scope_id INTEGER REFERENCES region_scope(region_scope_id),
    version_raw TEXT,
    build_raw TEXT,
    release_date_raw TEXT,
    release_date_iso TEXT,
    track_status TEXT NOT NULL,
    write_policy TEXT NOT NULL,
    source_artifact TEXT
);
CREATE UNIQUE INDEX uq_firmware_release_scope
ON firmware_release(
    product_id,
    IFNULL(hardware_revision_id,-1),
    IFNULL(region_scope_id,-1),
    IFNULL(version_raw,''),
    IFNULL(build_raw,''),
    IFNULL(release_date_raw,'')
);

CREATE TABLE target_scope (
    scope_id INTEGER PRIMARY KEY,
    scope_key TEXT NOT NULL UNIQUE,
    product_id INTEGER NOT NULL REFERENCES product(product_id),
    hardware_revision_id INTEGER REFERENCES hardware_revision(hardware_revision_id),
    region_scope_id INTEGER REFERENCES region_scope(region_scope_id),
    firmware_release_id INTEGER REFERENCES firmware_release(firmware_release_id),
    management_mode_id INTEGER REFERENCES management_mode(management_mode_id),
    controller_platform_id INTEGER REFERENCES controller_platform(controller_platform_id),
    controller_version_raw TEXT,
    scope_status TEXT NOT NULL
);

CREATE TABLE source (
    source_id INTEGER PRIMARY KEY,
    authority TEXT NOT NULL DEFAULT 'TP_LINK_OMADA_OFFICIAL',
    source_type TEXT NOT NULL,
    title TEXT,
    canonical_url TEXT NOT NULL,
    locale TEXT,
    publication_date_raw TEXT,
    publication_date_iso TEXT,
    retrieved_at TEXT,
    document_version TEXT,
    archive_path TEXT,
    sha256 TEXT,
    supersedes_source_id INTEGER REFERENCES source(source_id)
);
CREATE UNIQUE INDEX uq_source_identity
ON source(canonical_url, IFNULL(document_version,''), IFNULL(publication_date_raw,''));

CREATE TABLE artifact_manifest (
    artifact_id INTEGER PRIMARY KEY,
    phase_task TEXT NOT NULL,
    artifact_path TEXT NOT NULL UNIQUE,
    artifact_role TEXT NOT NULL,
    target_table TEXT NOT NULL,
    required_for_phase3_normalization INTEGER NOT NULL CHECK (required_for_phase3_normalization IN (0,1)),
    expected_identity_coverage INTEGER,
    notes TEXT
);

CREATE TABLE ingestion_run (
    ingestion_run_id INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    schema_version TEXT NOT NULL,
    source_snapshot_label TEXT NOT NULL,
    status TEXT NOT NULL,
    records_inserted INTEGER NOT NULL DEFAULT 0,
    validation_report TEXT
);

CREATE TABLE observation (
    observation_id INTEGER PRIMARY KEY,
    scope_id INTEGER NOT NULL REFERENCES target_scope(scope_id),
    domain TEXT NOT NULL,
    fact_key TEXT NOT NULL,
    value_type TEXT NOT NULL,
    value_text TEXT,
    value_num REAL,
    value_bool INTEGER CHECK (value_bool IN (0,1) OR value_bool IS NULL),
    value_json TEXT,
    unit_raw TEXT,
    observation_status TEXT NOT NULL,
    verification_status TEXT NOT NULL,
    write_policy TEXT NOT NULL,
    observed_at TEXT,
    source_artifact TEXT,
    CHECK (
        value_text IS NOT NULL OR value_num IS NOT NULL OR value_bool IS NOT NULL OR value_json IS NOT NULL
        OR observation_status IN ('UNKNOWN','NOT_PUBLISHED','NOT_APPLICABLE','SOURCE_CONFLICT')
    )
);
CREATE INDEX ix_observation_lookup ON observation(scope_id, domain, fact_key);

CREATE TABLE observation_evidence (
    observation_evidence_id INTEGER PRIMARY KEY,
    observation_id INTEGER NOT NULL REFERENCES observation(observation_id) ON DELETE CASCADE,
    source_id INTEGER NOT NULL REFERENCES source(source_id),
    locator_section TEXT,
    locator_heading TEXT,
    locator_table TEXT,
    locator_row TEXT,
    locator_anchor TEXT,
    evidence_kind TEXT NOT NULL
);
CREATE INDEX ix_observation_evidence ON observation_evidence(observation_id, source_id);

CREATE TABLE physical_interface (
    physical_interface_id INTEGER PRIMARY KEY,
    observation_id INTEGER NOT NULL UNIQUE REFERENCES observation(observation_id) ON DELETE CASCADE,
    interface_role TEXT NOT NULL,
    media_type TEXT,
    connector_type TEXT,
    speed_raw TEXT,
    port_count_raw TEXT,
    poe_input INTEGER CHECK (poe_input IN (0,1) OR poe_input IS NULL),
    poe_output INTEGER CHECK (poe_output IN (0,1) OR poe_output IS NULL),
    shared_combo_group TEXT,
    conditions_json TEXT
);

CREATE TABLE metric_observation (
    metric_observation_id INTEGER PRIMARY KEY,
    observation_id INTEGER NOT NULL UNIQUE REFERENCES observation(observation_id) ON DELETE CASCADE,
    metric_domain TEXT NOT NULL CHECK (metric_domain IN ('PERFORMANCE','CAPACITY','POWER','ENVIRONMENTAL')),
    metric_name TEXT NOT NULL,
    value_min REAL,
    value_max REAL,
    value_raw TEXT,
    unit_raw TEXT,
    conditions_json TEXT
);

CREATE TABLE controller_compatibility (
    controller_compatibility_id INTEGER PRIMARY KEY,
    observation_id INTEGER NOT NULL UNIQUE REFERENCES observation(observation_id) ON DELETE CASCADE,
    controller_platform_id INTEGER REFERENCES controller_platform(controller_platform_id),
    relation_kind TEXT NOT NULL,
    controller_version_raw TEXT,
    adoption_supported INTEGER CHECK (adoption_supported IN (0,1) OR adoption_supported IS NULL),
    compatibility_status TEXT NOT NULL,
    transition_constraints_json TEXT
);

CREATE TABLE mode_feature_observation (
    mode_feature_observation_id INTEGER PRIMARY KEY,
    observation_id INTEGER NOT NULL UNIQUE REFERENCES observation(observation_id) ON DELETE CASCADE,
    feature_key TEXT NOT NULL,
    availability TEXT NOT NULL,
    behavior_class TEXT NOT NULL,
    controller_offline_behavior TEXT,
    comparison_scope TEXT,
    do_not_generalize_rule TEXT
);

CREATE TABLE limitation_constraint (
    limitation_constraint_id INTEGER PRIMARY KEY,
    observation_id INTEGER NOT NULL UNIQUE REFERENCES observation(observation_id) ON DELETE CASCADE,
    limitation_kind TEXT NOT NULL,
    semantic_class TEXT NOT NULL,
    severity TEXT,
    blocking_scope TEXT NOT NULL,
    requirement_or_rule TEXT NOT NULL,
    explicit_vendor_limitation INTEGER NOT NULL CHECK (explicit_vendor_limitation IN (0,1))
);

CREATE TABLE lifecycle_notice (
    lifecycle_notice_id INTEGER PRIMARY KEY,
    product_id INTEGER NOT NULL REFERENCES product(product_id),
    hardware_revision_id INTEGER REFERENCES hardware_revision(hardware_revision_id),
    region_scope_id INTEGER REFERENCES region_scope(region_scope_id),
    notice_kind TEXT NOT NULL CHECK (notice_kind IN ('EOL','EOM','EOS')),
    notification_date_raw TEXT,
    notification_date_iso TEXT,
    effective_date_raw TEXT,
    effective_date_iso TEXT,
    status_as_of_observed_at TEXT NOT NULL,
    source_id INTEGER NOT NULL REFERENCES source(source_id),
    source_page_raw TEXT,
    model_level_status TEXT NOT NULL DEFAULT 'UNKNOWN'
);
CREATE UNIQUE INDEX uq_lifecycle_notice
ON lifecycle_notice(
    product_id,
    IFNULL(hardware_revision_id,-1),
    IFNULL(region_scope_id,-1),
    notice_kind,
    IFNULL(effective_date_raw,''),
    source_id
);

CREATE TABLE conflict_group (
    conflict_group_id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL,
    conflict_key TEXT NOT NULL UNIQUE,
    classification TEXT NOT NULL,
    disposition TEXT NOT NULL,
    deterministic_rule TEXT NOT NULL,
    fail_closed INTEGER NOT NULL CHECK (fail_closed IN (0,1)),
    status TEXT NOT NULL
);

CREATE TABLE conflict_member (
    conflict_member_id INTEGER PRIMARY KEY,
    conflict_group_id INTEGER NOT NULL REFERENCES conflict_group(conflict_group_id) ON DELETE CASCADE,
    observation_id INTEGER NOT NULL REFERENCES observation(observation_id) ON DELETE CASCADE,
    member_role TEXT NOT NULL,
    UNIQUE(conflict_group_id, observation_id)
);

CREATE TABLE domain_review (
    domain_review_id INTEGER PRIMARY KEY,
    phase_task TEXT NOT NULL,
    domain TEXT NOT NULL,
    scope_label TEXT NOT NULL,
    reviewed_count INTEGER NOT NULL,
    total_count INTEGER NOT NULL,
    completion_status TEXT NOT NULL,
    closure_semantics TEXT NOT NULL,
    artifact_path TEXT,
    UNIQUE(phase_task, domain, scope_label)
);

CREATE VIEW v_effective_observations AS
SELECT
    o.observation_id,
    p.exact_model,
    hr.version_raw AS hardware_version_raw,
    rs.raw_marker AS region_raw,
    fr.version_raw AS firmware_version_raw,
    mm.mode_code AS management_mode,
    cp.platform_key AS controller_platform,
    ts.controller_version_raw,
    o.domain,
    o.fact_key,
    o.value_type,
    o.value_text,
    o.value_num,
    o.value_bool,
    o.value_json,
    o.unit_raw,
    o.observation_status,
    o.verification_status,
    o.write_policy,
    o.observed_at
FROM observation o
JOIN target_scope ts ON ts.scope_id = o.scope_id
JOIN product p ON p.product_id = ts.product_id
LEFT JOIN hardware_revision hr ON hr.hardware_revision_id = ts.hardware_revision_id
LEFT JOIN region_scope rs ON rs.region_scope_id = ts.region_scope_id
LEFT JOIN firmware_release fr ON fr.firmware_release_id = ts.firmware_release_id
LEFT JOIN management_mode mm ON mm.management_mode_id = ts.management_mode_id
LEFT JOIN controller_platform cp ON cp.controller_platform_id = ts.controller_platform_id;
