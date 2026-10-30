CREATE TABLE jobs (
    job_id bigserial PRIMARY KEY,
    site_id text NOT NULL REFERENCES sites(site_id),
    kind text NOT NULL,
    subject text NOT NULL,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    state text NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'running', 'done', 'dead')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    run_after timestamptz NOT NULL DEFAULT now(),
    locked_by text,
    locked_until timestamptz,
    lease_token uuid,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (site_id, kind, subject),
    CHECK (
        (state = 'running' AND locked_by IS NOT NULL AND locked_until IS NOT NULL AND lease_token IS NOT NULL)
        OR
        (state <> 'running' AND locked_by IS NULL AND locked_until IS NULL AND lease_token IS NULL)
    )
);

CREATE INDEX jobs_claimable_idx ON jobs (site_id, run_after, job_id)
WHERE state IN ('queued', 'running');
