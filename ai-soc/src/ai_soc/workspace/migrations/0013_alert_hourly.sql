CREATE TABLE alert_hourly (
    site_id text NOT NULL REFERENCES sites(site_id),
    hour timestamptz NOT NULL,
    level_band text NOT NULL CHECK (level_band IN ('0-6', '7-9', '10-12', '13-15', 'unknown')),
    rule_id text NOT NULL,
    agent_id text NOT NULL,
    count integer NOT NULL CHECK (count >= 0),
    PRIMARY KEY (site_id, hour, level_band, rule_id, agent_id)
);

CREATE INDEX alert_hourly_site_hour_idx ON alert_hourly (site_id, hour);

ALTER TABLE alert_hourly ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_hourly FORCE ROW LEVEL SECURITY;
CREATE POLICY alert_hourly_site_scope ON alert_hourly
    USING (site_id = COALESCE(current_setting('app.site_id', true), ''))
    WITH CHECK (site_id = COALESCE(current_setting('app.site_id', true), ''));
