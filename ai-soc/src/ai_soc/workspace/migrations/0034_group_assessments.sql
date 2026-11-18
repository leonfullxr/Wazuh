CREATE TABLE group_assessment_sites (
    site_id text PRIMARY KEY REFERENCES sites(site_id),
    enabled boolean NOT NULL
);
ALTER TABLE group_assessment_sites ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_assessment_sites FORCE ROW LEVEL SECURITY;
CREATE POLICY assessment_site_scope ON group_assessment_sites
    USING (site_id = COALESCE(current_setting('app.site_id', true), ''))
    WITH CHECK (site_id = COALESCE(current_setting('app.site_id', true), ''));

CREATE INDEX jobs_assessment_group_idx ON jobs (site_id, (payload->>'group_id'))
    WHERE kind IN ('prepare_group_assessment', 'prepare_demo_assessment');

CREATE TABLE group_assessment_requests (
    site_id text NOT NULL,
    request_id text NOT NULL CHECK (request_id ~ '^[a-f0-9]{64}$'),
    group_id text NOT NULL,
    group_revision text NOT NULL,
    computation_version text NOT NULL,
    input_digest text NOT NULL,
    pack_digest text NOT NULL,
    prompt_digest text NOT NULL,
    catalog_digest text NOT NULL,
    catalog_version text NOT NULL,
    catalog jsonb NOT NULL,
    evidence_pack jsonb NOT NULL,
    prompt bytea NOT NULL,
    job_id bigint NOT NULL,
    selection text NOT NULL CHECK (selection IN ('score_gate', 'sample', 'new_revision')),
    synthetic boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, request_id),
    UNIQUE (site_id, job_id),
    UNIQUE (site_id, group_id, group_revision, computation_version, input_digest, catalog_digest),
    FOREIGN KEY (site_id, group_id, group_revision, computation_version, input_digest)
        REFERENCES scores(site_id, group_id, group_revision, computation_version, input_digest),
    FOREIGN KEY (site_id, job_id) REFERENCES jobs(site_id, job_id),
    CHECK (octet_length(prompt) <= 131072)
);

CREATE INDEX group_assessment_subject_idx ON group_assessment_requests
    (site_id, group_id, group_revision, created_at DESC, job_id DESC);

CREATE TABLE group_assessment_attempts (
    site_id text NOT NULL,
    request_id text NOT NULL,
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 5),
    lease_token uuid NOT NULL,
    provider text NOT NULL,
    model text NOT NULL,
    started_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, request_id, attempt),
    UNIQUE (site_id, request_id),
    FOREIGN KEY (site_id, request_id) REFERENCES group_assessment_requests(site_id, request_id)
);

CREATE TABLE group_assessment_outcomes (
    site_id text NOT NULL,
    request_id text NOT NULL,
    attempt integer NOT NULL,
    status text NOT NULL CHECK (status IN
        ('accepted', 'no_assessment', 'invalid_response', 'provider_unavailable')),
    outcome jsonb NOT NULL,
    input_tokens bigint CHECK (input_tokens >= 0),
    output_tokens bigint CHECK (output_tokens >= 0),
    latency_ms bigint CHECK (latency_ms >= 0),
    finished_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, request_id),
    FOREIGN KEY (site_id, request_id, attempt)
        REFERENCES group_assessment_attempts(site_id, request_id, attempt),
    CHECK (outcome->>'status' IS NOT DISTINCT FROM status)
);

CREATE TABLE group_assessment_reviews (
    site_id text NOT NULL,
    review_id uuid NOT NULL,
    request_id text NOT NULL,
    decision text NOT NULL CHECK (decision IN ('agree', 'override')),
    verdict text NOT NULL CHECK (verdict IN
        ('benign', 'needs_review', 'likely_malicious', 'insufficient_evidence')),
    reason text NOT NULL CHECK (length(reason) <= 1000),
    actor_key text NOT NULL,
    at timestamptz NOT NULL,
    PRIMARY KEY (site_id, review_id),
    FOREIGN KEY (site_id, request_id) REFERENCES group_assessment_outcomes(site_id, request_id),
    CHECK (decision <> 'override' OR length(btrim(reason)) > 0)
);

CREATE INDEX group_assessment_review_history_idx ON group_assessment_reviews
    (site_id, request_id, at DESC, review_id DESC);

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'group_assessment_requests', 'group_assessment_attempts', 'group_assessment_outcomes',
        'group_assessment_reviews'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format(
            'CREATE POLICY assessment_site_scope ON %I USING (site_id = '
            'COALESCE(current_setting(''app.site_id'', true), '''')) WITH CHECK (site_id = '
            'COALESCE(current_setting(''app.site_id'', true), ''''))', table_name
        );
        EXECUTE format(
            'CREATE TRIGGER assessment_immutable BEFORE UPDATE OR DELETE ON %I '
            'FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite()', table_name
        );
    END LOOP;
END
$$;
