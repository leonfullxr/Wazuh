CREATE TABLE enrichments (
    site_id text NOT NULL,
    enrichment_id uuid NOT NULL,
    group_id text NOT NULL,
    group_revision text NOT NULL,
    source text NOT NULL CHECK (source IN ('prevalence', 'first_seen', 'vuln', 'kev', 'geoip', 'asset', 'privilege', 'known_noise')),
    source_version text NOT NULL,
    availability text NOT NULL CHECK (availability IN ('available', 'unavailable', 'stale')),
    value jsonb NOT NULL CHECK (jsonb_typeof(value) = 'object'),
    fetched_at timestamptz NOT NULL,
    expires_at timestamptz,
    PRIMARY KEY (site_id, enrichment_id),
    UNIQUE (site_id, group_id, group_revision, source, enrichment_id),
    FOREIGN KEY (site_id, group_id, group_revision)
        REFERENCES group_revisions(site_id, group_id, revision),
    CHECK (expires_at IS NULL OR expires_at > fetched_at)
);

CREATE INDEX enrichments_group_source_idx
    ON enrichments (site_id, group_id, group_revision, source, fetched_at DESC);

CREATE TRIGGER enrichments_immutable BEFORE UPDATE OR DELETE ON enrichments
FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite();

ALTER TABLE enrichments ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrichments FORCE ROW LEVEL SECURITY;
CREATE POLICY enrichments_site_scope ON enrichments
    USING (site_id = COALESCE(current_setting('app.site_id', true), ''))
    WITH CHECK (site_id = COALESCE(current_setting('app.site_id', true), ''));
