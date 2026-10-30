CREATE TABLE correlation_requests (
    site_id text PRIMARY KEY REFERENCES sites(site_id),
    requested_seq bigint NOT NULL DEFAULT 0 CHECK (requested_seq >= 0),
    prepared_seq bigint NOT NULL DEFAULT 0 CHECK (prepared_seq >= 0 AND prepared_seq <= requested_seq),
    generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
    latest_requested_at timestamptz,
    active_prepare_job_id bigint,
    active_config_identity text NOT NULL CHECK (active_config_identity ~ '^[0-9a-f]{64}$'),
    desired_config jsonb NOT NULL CHECK (jsonb_typeof(desired_config) = 'object'),
    desired_config_identity text NOT NULL CHECK (desired_config_identity ~ '^[0-9a-f]{64}$'),
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (site_id, active_prepare_job_id) REFERENCES jobs(site_id, job_id),
    CHECK ((requested_seq = 0) = (latest_requested_at IS NULL))
);

ALTER TABLE correlation_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE correlation_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY correlation_requests_site_scope ON correlation_requests
    USING (site_id = COALESCE(current_setting('app.site_id', true), ''))
    WITH CHECK (site_id = COALESCE(current_setting('app.site_id', true), ''));
