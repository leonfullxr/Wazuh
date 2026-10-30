ALTER TABLE pipeline_runs
    ADD COLUMN mutation_count integer NOT NULL DEFAULT 0 CHECK (mutation_count >= 0),
    ADD COLUMN partial_reason text;

ALTER TABLE pipeline_runs ADD CONSTRAINT pipeline_runs_site_run_unique UNIQUE (site_id, run_id);

CREATE TABLE alert_reconciliation (
    site_id text NOT NULL REFERENCES sites(site_id),
    run_id uuid NOT NULL,
    hour timestamptz NOT NULL,
    source_count integer CHECK (source_count IS NULL OR source_count >= 0),
    registry_before integer NOT NULL CHECK (registry_before >= 0),
    registry_after integer CHECK (registry_after IS NULL OR registry_after >= 0),
    count_equal boolean NOT NULL,
    alarm boolean NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('matched_count', 'repaired_count', 'mismatch', 'failed')),
    error_code text,
    checked_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_id, run_id, hour),
    FOREIGN KEY (site_id, run_id) REFERENCES pipeline_runs(site_id, run_id),
    CHECK (hour = date_trunc('hour', hour AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')
);

CREATE INDEX alert_reconciliation_site_alarm_idx
    ON alert_reconciliation (site_id, checked_at DESC) WHERE alarm;

ALTER TABLE alert_reconciliation ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_reconciliation FORCE ROW LEVEL SECURITY;
CREATE POLICY alert_reconciliation_site_scope ON alert_reconciliation
    USING (site_id = COALESCE(current_setting('app.site_id', true), ''))
    WITH CHECK (site_id = COALESCE(current_setting('app.site_id', true), ''));
