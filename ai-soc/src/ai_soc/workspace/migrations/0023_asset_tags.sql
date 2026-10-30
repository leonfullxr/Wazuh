CREATE TABLE asset_tags (
    site_id text NOT NULL,
    entity_id bigint NOT NULL,
    revision integer NOT NULL CHECK (revision > 0),
    criticality smallint NOT NULL CHECK (criticality BETWEEN 0 AND 3),
    tags text[] NOT NULL CHECK (cardinality(tags) <= 32),
    set_by text NOT NULL,
    set_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, entity_id, revision),
    FOREIGN KEY (site_id, entity_id) REFERENCES entities(site_id, entity_id),
    CHECK (array_position(tags, NULL) IS NULL)
);

CREATE INDEX asset_tags_latest_idx ON asset_tags (site_id, entity_id, revision DESC);

CREATE TABLE asset_tag_history (
    site_id text NOT NULL,
    history_id uuid NOT NULL,
    entity_id bigint NOT NULL,
    revision integer NOT NULL,
    actor_key text NOT NULL,
    before_value jsonb,
    after_value jsonb NOT NULL CHECK (jsonb_typeof(after_value) = 'object'),
    at timestamptz NOT NULL,
    PRIMARY KEY (site_id, history_id),
    FOREIGN KEY (site_id, entity_id, revision)
        REFERENCES asset_tags(site_id, entity_id, revision),
    FOREIGN KEY (site_id, entity_id) REFERENCES entities(site_id, entity_id)
);

CREATE TRIGGER asset_tags_immutable BEFORE UPDATE OR DELETE ON asset_tags
FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite();
CREATE TRIGGER asset_tag_history_immutable BEFORE UPDATE OR DELETE ON asset_tag_history
FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite();

ALTER TABLE asset_tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_tags FORCE ROW LEVEL SECURITY;
CREATE POLICY asset_tags_site_scope ON asset_tags
    USING (site_id = COALESCE(current_setting('app.site_id', true), ''))
    WITH CHECK (site_id = COALESCE(current_setting('app.site_id', true), ''));
ALTER TABLE asset_tag_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_tag_history FORCE ROW LEVEL SECURITY;
CREATE POLICY asset_tag_history_site_scope ON asset_tag_history
    USING (site_id = COALESCE(current_setting('app.site_id', true), ''))
    WITH CHECK (site_id = COALESCE(current_setting('app.site_id', true), ''));
