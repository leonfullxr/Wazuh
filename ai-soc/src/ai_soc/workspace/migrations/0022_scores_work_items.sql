CREATE TABLE score_manifests (
    site_id text NOT NULL,
    group_id text NOT NULL,
    group_revision text NOT NULL,
    computation_version text NOT NULL,
    input_digest text NOT NULL CHECK (input_digest ~ '^[0-9a-f]{64}$'),
    manifest jsonb NOT NULL CHECK (jsonb_typeof(manifest) = 'object'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, group_id, group_revision, computation_version, input_digest),
    FOREIGN KEY (site_id, group_id, group_revision)
        REFERENCES group_revisions(site_id, group_id, revision)
);

CREATE TABLE scores (
    site_id text NOT NULL,
    group_id text NOT NULL,
    group_revision text NOT NULL,
    computation_version text NOT NULL,
    input_digest text NOT NULL,
    total numeric(9, 6) NOT NULL CHECK (total BETWEEN 0 AND 100),
    components jsonb NOT NULL CHECK (jsonb_typeof(components) = 'array'),
    computed_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, group_id, group_revision, computation_version, input_digest),
    FOREIGN KEY (site_id, group_id, group_revision)
        REFERENCES group_revisions(site_id, group_id, revision),
    FOREIGN KEY (site_id, group_id, group_revision, computation_version, input_digest)
        REFERENCES score_manifests(site_id, group_id, group_revision, computation_version, input_digest)
);

CREATE INDEX scores_queue_idx ON scores
    (site_id, computation_version, total DESC, computed_at DESC, group_id);

CREATE TABLE work_items (
    site_id text NOT NULL,
    group_id text NOT NULL,
    status text NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'in_progress', 'resolved', 'closed')),
    owner_key text CHECK (owner_key IS NULL OR length(owner_key) <= 256),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, group_id),
    FOREIGN KEY (site_id, group_id) REFERENCES groups(site_id, group_id)
);

CREATE TABLE work_history (
    site_id text NOT NULL,
    history_id uuid NOT NULL,
    group_id text NOT NULL,
    actor_key text NOT NULL,
    action text NOT NULL CHECK (action IN ('assign', 'status', 'disposition', 'bulk_assign', 'bulk_status', 'bulk_disposition')),
    before_value jsonb,
    after_value jsonb NOT NULL CHECK (jsonb_typeof(after_value) = 'object'),
    at timestamptz NOT NULL,
    PRIMARY KEY (site_id, history_id),
    FOREIGN KEY (site_id, group_id) REFERENCES groups(site_id, group_id)
);

CREATE TABLE dispositions (
    site_id text NOT NULL,
    disposition_id uuid NOT NULL,
    group_id text NOT NULL,
    label text NOT NULL CHECK (label IN ('true_positive', 'benign_true_positive', 'false_positive', 'duplicate', 'undetermined')),
    reason_code text CHECK (reason_code IS NULL OR length(reason_code) <= 64),
    note text CHECK (note IS NULL OR length(note) <= 2000),
    propagate_to_members boolean NOT NULL DEFAULT false,
    actor_key text NOT NULL,
    at timestamptz NOT NULL,
    group_revision_seen text NOT NULL,
    pipeline_version_seen text NOT NULL,
    PRIMARY KEY (site_id, disposition_id),
    FOREIGN KEY (site_id, group_id) REFERENCES groups(site_id, group_id),
    FOREIGN KEY (site_id, group_id, group_revision_seen)
        REFERENCES group_revisions(site_id, group_id, revision),
    CHECK (label <> 'false_positive' OR reason_code IN ('expected_admin_activity', 'known_scanner', 'misconfigured_rule', 'test_activity', 'other')),
    CHECK (reason_code <> 'other' OR note IS NOT NULL)
);

CREATE TABLE workspace_idempotency (
    site_id text NOT NULL REFERENCES sites(site_id),
    principal_key text NOT NULL,
    route_key text NOT NULL,
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 128),
    request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    response jsonb NOT NULL CHECK (jsonb_typeof(response) = 'object'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, principal_key, route_key, idempotency_key)
);

CREATE TRIGGER work_items_no_delete BEFORE DELETE ON work_items
FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite();
CREATE TRIGGER score_manifests_immutable BEFORE UPDATE OR DELETE ON score_manifests
FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite();
CREATE TRIGGER scores_immutable BEFORE UPDATE OR DELETE ON scores
FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite();
CREATE TRIGGER work_history_immutable BEFORE UPDATE OR DELETE ON work_history
FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite();
CREATE TRIGGER dispositions_immutable BEFORE UPDATE OR DELETE ON dispositions
FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite();
CREATE TRIGGER idempotency_immutable BEFORE UPDATE OR DELETE ON workspace_idempotency
FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite();

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['score_manifests', 'scores', 'work_items', 'work_history', 'dispositions', 'workspace_idempotency'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY %I ON %I USING (site_id = COALESCE(current_setting(''app.site_id'', true), '''')) WITH CHECK (site_id = COALESCE(current_setting(''app.site_id'', true), ''''))',
            t || '_site_scope', t
        );
    END LOOP;
END;
$$;
