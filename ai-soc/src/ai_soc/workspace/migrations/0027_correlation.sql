ALTER TABLE alert_registry ADD CONSTRAINT alert_registry_source_witness_unique
    UNIQUE (site_id, alert_key, original_event_ts, source_hash);
ALTER TABLE group_members ADD CONSTRAINT group_members_source_witness_unique
    UNIQUE (site_id, group_id, group_revision, alert_key, event_ts, source_hash);
ALTER TABLE jobs ADD CONSTRAINT jobs_site_job_id_unique UNIQUE (site_id, job_id);
ALTER TABLE audit_outbox ADD CONSTRAINT audit_outbox_site_event_unique UNIQUE (site_id, event_id);

CREATE TABLE correlation_source_projections (
    site_id text NOT NULL,
    alert_key text NOT NULL,
    event_ts timestamptz NOT NULL,
    source_hash text NOT NULL CHECK (source_hash ~ '^[0-9a-f]{64}$'),
    extraction_version text NOT NULL CHECK (length(extraction_version) BETWEEN 1 AND 80),
    projection_digest text NOT NULL CHECK (projection_digest ~ '^[0-9a-f]{64}$'),
    availability text NOT NULL CHECK (availability IN
        ('available', 'raw_unavailable', 'syscheck_unavailable', 'path_unavailable',
         'event_unavailable', 'unsupported_event_pair')),
    source_path text CHECK (source_path IS NULL OR length(source_path) BETWEEN 1 AND 4096),
    source_event text CHECK (source_event IS NULL OR source_event IN ('modified', 'deleted', 'added')),
    PRIMARY KEY (site_id, alert_key, extraction_version),
    UNIQUE (site_id, alert_key, extraction_version, projection_digest),
    FOREIGN KEY (site_id, alert_key, event_ts, source_hash)
        REFERENCES alert_registry(site_id, alert_key, original_event_ts, source_hash),
    CHECK ((availability = 'available' AND source_path IS NOT NULL AND source_event IS NOT NULL)
        OR (availability <> 'available' AND source_path IS NULL AND source_event IS NULL)),
    CHECK (source_event IS DISTINCT FROM 'deleted' OR availability = 'available')
);

CREATE TABLE correlation_manifests (
    site_id text NOT NULL REFERENCES sites(site_id),
    manifest_id uuid NOT NULL,
    input_digest text NOT NULL CHECK (input_digest ~ '^[0-9a-f]{64}$'),
    rule_id text NOT NULL CHECK (length(rule_id) BETWEEN 1 AND 80),
    rule_version text NOT NULL CHECK (length(rule_version) BETWEEN 1 AND 40),
    rule_digest text NOT NULL CHECK (rule_digest ~ '^[0-9a-f]{64}$'),
    scope_digest text NOT NULL CHECK (scope_digest ~ '^[0-9a-f]{64}$'),
    computation_version text NOT NULL CHECK (length(computation_version) BETWEEN 1 AND 128),
    window_start timestamptz NOT NULL,
    window_end timestamptz NOT NULL,
    as_of timestamptz NOT NULL,
    complete boolean NOT NULL,
    frozen_input jsonb NOT NULL CHECK (jsonb_typeof(frozen_input) = 'object'),
    frozen_rule jsonb NOT NULL CHECK (jsonb_typeof(frozen_rule) = 'object'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, manifest_id),
    UNIQUE (site_id, input_digest, rule_digest),
    UNIQUE (site_id, manifest_id, scope_digest),
    UNIQUE (site_id, manifest_id, input_digest),
    UNIQUE (site_id, manifest_id, rule_id, rule_version),
    UNIQUE (site_id, manifest_id, as_of),
    CHECK (window_start < window_end AND window_end <= as_of
        AND window_end - window_start <= interval '48 hours')
);

CREATE TABLE correlation_input_groups (
    site_id text NOT NULL,
    manifest_id uuid NOT NULL,
    group_id text NOT NULL,
    group_revision text NOT NULL,
    score_version text,
    score_digest text,
    score double precision CHECK (score IS NULL OR score BETWEEN 0 AND 100),
    PRIMARY KEY (site_id, manifest_id, group_id, group_revision),
    FOREIGN KEY (site_id, manifest_id) REFERENCES correlation_manifests(site_id, manifest_id),
    FOREIGN KEY (site_id, group_id, group_revision)
        REFERENCES group_revisions(site_id, group_id, revision),
    FOREIGN KEY (site_id, group_id, group_revision, score_version, score_digest)
        REFERENCES scores(site_id, group_id, group_revision, computation_version, input_digest),
    CHECK ((score_version IS NULL) = (score_digest IS NULL)),
    CHECK (score IS NULL OR score_version IS NOT NULL)
);

CREATE TABLE correlation_input_members (
    site_id text NOT NULL,
    manifest_id uuid NOT NULL,
    group_id text NOT NULL,
    group_revision text NOT NULL,
    alert_key text NOT NULL,
    event_ts timestamptz NOT NULL,
    source_hash text NOT NULL CHECK (source_hash ~ '^[0-9a-f]{64}$'),
    normalized_snapshot jsonb NOT NULL CHECK (jsonb_typeof(normalized_snapshot) = 'object'),
    projection_version text NOT NULL,
    projection_digest text NOT NULL,
    PRIMARY KEY (site_id, manifest_id, group_id, group_revision, alert_key),
    UNIQUE (site_id, manifest_id, group_id, group_revision, alert_key, event_ts),
    FOREIGN KEY (site_id, manifest_id, group_id, group_revision)
        REFERENCES correlation_input_groups(site_id, manifest_id, group_id, group_revision),
    FOREIGN KEY (site_id, group_id, group_revision, alert_key, event_ts, source_hash)
        REFERENCES group_members(site_id, group_id, group_revision, alert_key, event_ts, source_hash),
    FOREIGN KEY (site_id, alert_key, event_ts, source_hash)
        REFERENCES alert_registry(site_id, alert_key, original_event_ts, source_hash),
    FOREIGN KEY (site_id, alert_key, projection_version, projection_digest)
        REFERENCES correlation_source_projections(site_id, alert_key, extraction_version, projection_digest)
);

CREATE TABLE correlation_edges (
    site_id text NOT NULL,
    manifest_id uuid NOT NULL,
    edge_id text NOT NULL CHECK (edge_id ~ '^[0-9a-f]{64}$'),
    from_group text NOT NULL,
    from_revision text NOT NULL,
    from_alert_key text NOT NULL,
    to_group text NOT NULL,
    to_revision text NOT NULL,
    to_alert_key text NOT NULL,
    edge_type text NOT NULL CHECK (edge_type IN ('same_src_ip_user', 'same_user_host', 'same_src_ip', 'same_hash', 'same_host')),
    confidence double precision NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    weak boolean NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 512),
    time_delta_seconds double precision NOT NULL CHECK (time_delta_seconds >= 0
        AND time_delta_seconds < 'Infinity'::double precision
        AND time_delta_seconds <> 'NaN'::double precision),
    shared_fields jsonb NOT NULL CHECK (jsonb_typeof(shared_fields) = 'array'),
    PRIMARY KEY (site_id, manifest_id, edge_id),
    FOREIGN KEY (site_id, manifest_id) REFERENCES correlation_manifests(site_id, manifest_id),
    FOREIGN KEY (site_id, manifest_id, from_group, from_revision, from_alert_key)
        REFERENCES correlation_input_members(site_id, manifest_id, group_id, group_revision, alert_key),
    FOREIGN KEY (site_id, manifest_id, to_group, to_revision, to_alert_key)
        REFERENCES correlation_input_members(site_id, manifest_id, group_id, group_revision, alert_key),
    CHECK ((from_group, from_revision) <> (to_group, to_revision)),
    CHECK (edge_type <> 'same_host' OR weak)
);

CREATE TABLE correlation_chains (
    site_id text NOT NULL,
    chain_id text NOT NULL CHECK (chain_id ~ '^[0-9a-f]{64}$'),
    rule_id text NOT NULL,
    rule_version text NOT NULL,
    anchor_alert_key text NOT NULL,
    anchor_group_id text NOT NULL CHECK (anchor_group_id ~ '^[0-9a-f]{64}$'),
    anchor_identity text NOT NULL CHECK (length(anchor_identity) BETWEEN 1 AND 512),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, chain_id),
    UNIQUE (site_id, chain_id, rule_id, rule_version, anchor_group_id),
    UNIQUE (site_id, rule_id, rule_version, anchor_group_id, anchor_identity),
    FOREIGN KEY (site_id, chain_id) REFERENCES subject_registry(site_id, subject_id),
    FOREIGN KEY (site_id, anchor_alert_key) REFERENCES alert_registry(site_id, alert_key),
    FOREIGN KEY (site_id, anchor_group_id) REFERENCES groups(site_id, group_id)
);

CREATE TABLE correlation_chain_revisions (
    site_id text NOT NULL,
    chain_id text NOT NULL,
    revision_digest text NOT NULL CHECK (revision_digest ~ '^[0-9a-f]{64}$'),
    manifest_id uuid NOT NULL,
    rule_id text NOT NULL,
    rule_version text NOT NULL,
    anchor_alert_key text NOT NULL,
    anchor_group_id text NOT NULL,
    anchor_group_revision text NOT NULL,
    result jsonb NOT NULL CHECK (jsonb_typeof(result) = 'object'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, chain_id, revision_digest, manifest_id),
    FOREIGN KEY (site_id, chain_id) REFERENCES correlation_chains(site_id, chain_id),
    FOREIGN KEY (site_id, chain_id, rule_id, rule_version, anchor_group_id)
        REFERENCES correlation_chains(site_id, chain_id, rule_id, rule_version, anchor_group_id),
    FOREIGN KEY (site_id, manifest_id, rule_id, rule_version)
        REFERENCES correlation_manifests(site_id, manifest_id, rule_id, rule_version),
    FOREIGN KEY (site_id, manifest_id, anchor_group_id, anchor_group_revision, anchor_alert_key)
        REFERENCES correlation_input_members(site_id, manifest_id, group_id, group_revision, alert_key)
);

CREATE TABLE correlation_stage_evidence (
    site_id text NOT NULL,
    chain_id text NOT NULL,
    revision_digest text NOT NULL,
    manifest_id uuid NOT NULL,
    ordinal smallint NOT NULL CHECK (ordinal BETWEEN 0 AND 7),
    stage_id text NOT NULL CHECK (stage_id ~ '^[a-z][a-z0-9_]{0,39}$'),
    outcome text NOT NULL CHECK (outcome IN ('matched', 'missing')),
    group_id text,
    group_revision text,
    alert_key text,
    event_ts timestamptz,
    confidence double precision CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 1),
    PRIMARY KEY (site_id, chain_id, revision_digest, manifest_id, ordinal),
    FOREIGN KEY (site_id, chain_id, revision_digest, manifest_id)
        REFERENCES correlation_chain_revisions(site_id, chain_id, revision_digest, manifest_id),
    FOREIGN KEY (site_id, manifest_id, group_id, group_revision, alert_key, event_ts)
        REFERENCES correlation_input_members(site_id, manifest_id, group_id, group_revision, alert_key, event_ts),
    CHECK ((outcome = 'matched') =
          (group_id IS NOT NULL AND group_revision IS NOT NULL AND alert_key IS NOT NULL
           AND event_ts IS NOT NULL AND confidence IS NOT NULL)),
    CHECK (outcome <> 'missing' OR (group_id IS NULL AND group_revision IS NULL
           AND alert_key IS NULL AND event_ts IS NULL AND confidence IS NULL))
);

CREATE TABLE correlation_heads (
    site_id text NOT NULL,
    chain_id text NOT NULL,
    revision_digest text NOT NULL,
    manifest_id uuid NOT NULL,
    intent_id uuid NOT NULL,
    cutoff timestamptz NOT NULL,
    intent_seq bigint NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, chain_id),
    FOREIGN KEY (site_id, chain_id, revision_digest, manifest_id)
        REFERENCES correlation_chain_revisions(site_id, chain_id, revision_digest, manifest_id),
    FOREIGN KEY (site_id, manifest_id, cutoff)
        REFERENCES correlation_manifests(site_id, manifest_id, as_of)
);

CREATE TABLE correlation_decisions (
    site_id text NOT NULL,
    chain_id text NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    state text NOT NULL CHECK (state IN ('open', 'dismissed')),
    reason text,
    actor_key text NOT NULL CHECK (length(actor_key) BETWEEN 1 AND 256),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, chain_id),
    FOREIGN KEY (site_id, chain_id) REFERENCES correlation_chains(site_id, chain_id),
    CHECK (state <> 'dismissed' OR length(COALESCE(reason, '')) BETWEEN 1 AND 512)
);

CREATE TABLE correlation_decision_history (
    site_id text NOT NULL,
    chain_id text NOT NULL,
    decision_id uuid NOT NULL,
    audit_event_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 128),
    version bigint NOT NULL,
    state text NOT NULL CHECK (state IN ('open', 'dismissed')),
    reason text,
    actor_key text NOT NULL CHECK (length(actor_key) BETWEEN 1 AND 256),
    at timestamptz NOT NULL,
    PRIMARY KEY (site_id, decision_id),
    UNIQUE (site_id, chain_id, idempotency_key),
    UNIQUE (site_id, chain_id, version),
    FOREIGN KEY (site_id, chain_id) REFERENCES correlation_chains(site_id, chain_id),
    FOREIGN KEY (site_id, audit_event_id) REFERENCES audit_outbox(site_id, event_id),
    CHECK (state <> 'dismissed' OR length(COALESCE(reason, '')) BETWEEN 1 AND 512)
);

CREATE TABLE correlation_publication_intents (
    site_id text NOT NULL,
    intent_id uuid NOT NULL,
    manifest_id uuid NOT NULL,
    scope_digest text NOT NULL CHECK (scope_digest ~ '^[0-9a-f]{64}$'),
    intent_seq bigserial NOT NULL,
    job_id bigint NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, intent_id),
    UNIQUE (site_id, job_id),
    UNIQUE (site_id, intent_seq),
    UNIQUE (site_id, intent_id, manifest_id, intent_seq),
    FOREIGN KEY (site_id, manifest_id) REFERENCES correlation_manifests(site_id, manifest_id),
    FOREIGN KEY (site_id, job_id) REFERENCES jobs(site_id, job_id),
    FOREIGN KEY (site_id, manifest_id, scope_digest)
        REFERENCES correlation_manifests(site_id, manifest_id, scope_digest)
);
CREATE INDEX correlation_intent_scope_idx ON correlation_publication_intents
    (site_id, scope_digest, intent_seq DESC);

ALTER TABLE correlation_heads ADD CONSTRAINT correlation_heads_intent_fk
    FOREIGN KEY (site_id, intent_id, manifest_id, intent_seq)
    REFERENCES correlation_publication_intents(site_id, intent_id, manifest_id, intent_seq);

CREATE FUNCTION workspace_require_correlation_chain_subject() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM subject_registry s WHERE s.site_id = NEW.site_id
                   AND s.subject_kind = 'chain' AND s.subject_id = NEW.chain_id) THEN
        RAISE EXCEPTION 'chain identity requires a registered chain subject';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER correlation_chain_subject BEFORE INSERT ON correlation_chains
FOR EACH ROW EXECUTE FUNCTION workspace_require_correlation_chain_subject();

CREATE FUNCTION workspace_reject_correlation_rewrite() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME;
END;
$$;

CREATE FUNCTION workspace_require_correlation_decision_audit() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'correlation decisions cannot be deleted';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'correlation decision versions must increase by one';
    END IF;
    IF TG_OP = 'INSERT' AND NEW.version <> 1 THEN
        RAISE EXCEPTION 'initial correlation decision version must be one';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM correlation_decision_history h
        WHERE h.site_id = NEW.site_id AND h.chain_id = NEW.chain_id
          AND h.version = NEW.version AND h.state = NEW.state
          AND h.reason IS NOT DISTINCT FROM NEW.reason AND h.actor_key = NEW.actor_key
          AND h.at = NEW.updated_at
    ) THEN
        RAISE EXCEPTION 'correlation decision requires matching append-only history';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION workspace_require_correlation_history_audit() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.version <> COALESCE((
        SELECT max(h.version) + 1 FROM correlation_decision_history h
        WHERE h.site_id = NEW.site_id AND h.chain_id = NEW.chain_id
    ), 1) THEN
        RAISE EXCEPTION 'correlation decision history versions must be sequential';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM audit_outbox a
        WHERE a.site_id = NEW.site_id AND a.event_id = NEW.audit_event_id
          AND a.kind = 'correlation_candidate_dismissed' AND a.actor_key = NEW.actor_key
          AND a.payload->>'chain_id' = NEW.chain_id
          AND a.payload->>'version' = NEW.version::text
          AND a.payload->>'reason' = NEW.reason
          AND a.payload->>'idempotency_key' = NEW.idempotency_key
    ) THEN
        RAISE EXCEPTION 'correlation decision history requires a matching audit event';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION workspace_guard_correlation_head_order() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.cutoff, NEW.intent_seq) <= (OLD.cutoff, OLD.intent_seq) THEN
        RAISE EXCEPTION 'correlation head publication order cannot regress';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER correlation_history_audited BEFORE INSERT ON correlation_decision_history
FOR EACH ROW EXECUTE FUNCTION workspace_require_correlation_history_audit();
CREATE TRIGGER correlation_decision_audited BEFORE INSERT OR UPDATE OR DELETE ON correlation_decisions
FOR EACH ROW EXECUTE FUNCTION workspace_require_correlation_decision_audit();
CREATE TRIGGER correlation_head_order BEFORE UPDATE ON correlation_heads
FOR EACH ROW EXECUTE FUNCTION workspace_guard_correlation_head_order();

CREATE TRIGGER correlation_source_projection_immutable BEFORE UPDATE OR DELETE ON correlation_source_projections
FOR EACH ROW EXECUTE FUNCTION workspace_reject_correlation_rewrite();
CREATE TRIGGER correlation_manifest_immutable BEFORE UPDATE OR DELETE ON correlation_manifests
FOR EACH ROW EXECUTE FUNCTION workspace_reject_correlation_rewrite();
CREATE TRIGGER correlation_input_group_immutable BEFORE UPDATE OR DELETE ON correlation_input_groups
FOR EACH ROW EXECUTE FUNCTION workspace_reject_correlation_rewrite();
CREATE TRIGGER correlation_input_member_immutable BEFORE UPDATE OR DELETE ON correlation_input_members
FOR EACH ROW EXECUTE FUNCTION workspace_reject_correlation_rewrite();
CREATE TRIGGER correlation_edge_immutable BEFORE UPDATE OR DELETE ON correlation_edges
FOR EACH ROW EXECUTE FUNCTION workspace_reject_correlation_rewrite();
CREATE TRIGGER correlation_chain_immutable BEFORE UPDATE OR DELETE ON correlation_chains
FOR EACH ROW EXECUTE FUNCTION workspace_reject_correlation_rewrite();
CREATE TRIGGER correlation_chain_revision_immutable BEFORE UPDATE OR DELETE ON correlation_chain_revisions
FOR EACH ROW EXECUTE FUNCTION workspace_reject_correlation_rewrite();
CREATE TRIGGER correlation_stage_evidence_immutable BEFORE UPDATE OR DELETE ON correlation_stage_evidence
FOR EACH ROW EXECUTE FUNCTION workspace_reject_correlation_rewrite();
CREATE TRIGGER correlation_decision_history_immutable BEFORE UPDATE OR DELETE ON correlation_decision_history
FOR EACH ROW EXECUTE FUNCTION workspace_reject_correlation_rewrite();
CREATE TRIGGER correlation_intent_immutable BEFORE UPDATE OR DELETE ON correlation_publication_intents
FOR EACH ROW EXECUTE FUNCTION workspace_reject_correlation_rewrite();

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'correlation_source_projections', 'correlation_manifests', 'correlation_input_groups',
        'correlation_input_members', 'correlation_edges', 'correlation_chains',
        'correlation_chain_revisions', 'correlation_stage_evidence', 'correlation_heads',
        'correlation_decisions', 'correlation_decision_history', 'correlation_publication_intents'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY %I ON %I USING (site_id = COALESCE(current_setting(''app.site_id'', true), '''')) WITH CHECK (site_id = COALESCE(current_setting(''app.site_id'', true), ''''))',
            t || '_site_scope', t
        );
    END LOOP;
END;
$$;
