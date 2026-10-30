CREATE TABLE alert_sources (
    site_id text NOT NULL,
    index_pattern text NOT NULL CHECK (index_pattern <> ''),
    alert_key text NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_id, index_pattern, alert_key),
    FOREIGN KEY (site_id, alert_key)
        REFERENCES alert_registry(site_id, alert_key)
);

ALTER TABLE alert_reconciliation
    ADD COLUMN index_pattern text NOT NULL DEFAULT 'legacy-unscoped'
        CHECK (index_pattern <> '');
ALTER TABLE alert_reconciliation ALTER COLUMN index_pattern DROP DEFAULT;
CREATE INDEX alert_reconciliation_scope_hour_idx
    ON alert_reconciliation (site_id, index_pattern, hour DESC);

ALTER TABLE alert_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_sources FORCE ROW LEVEL SECURITY;
CREATE POLICY alert_sources_site_scope ON alert_sources
    USING (site_id = COALESCE(current_setting('app.site_id', true), ''))
    WITH CHECK (site_id = COALESCE(current_setting('app.site_id', true), ''));
