CREATE TABLE pipeline_runs (
    run_id uuid PRIMARY KEY,
    site_id text NOT NULL REFERENCES sites(site_id),
    kind text NOT NULL CHECK (kind IN ('poll', 'reconcile', 'backfill', 'replay')),
    started_at timestamptz NOT NULL,
    finished_at timestamptz,
    window_from timestamptz,
    window_to timestamptz,
    read_count integer,
    inserted_count integer,
    duplicate_count integer,
    reconcile_expected integer,
    reconcile_stored integer,
    outcome text CHECK (outcome IS NULL OR outcome IN ('ok', 'partial', 'failed')),
    error_code text,
    pipeline_version text NOT NULL
);
