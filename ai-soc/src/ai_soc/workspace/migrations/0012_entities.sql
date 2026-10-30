CREATE TABLE entities (
    entity_id bigserial,
    site_id text NOT NULL REFERENCES sites(site_id),
    kind text NOT NULL,
    value_norm text NOT NULL,
    classification text CHECK (classification IS NULL OR classification IN ('private', 'public')),
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL,
    CHECK (last_seen >= first_seen),
    PRIMARY KEY (site_id, entity_id),
    UNIQUE (site_id, kind, value_norm)
);

CREATE TABLE alert_entities (
    site_id text NOT NULL,
    alert_key text NOT NULL,
    event_ts timestamptz NOT NULL,
    entity_id bigint NOT NULL,
    role text NOT NULL CHECK (role IN ('src', 'dst', 'actor', 'target', 'subject', 'agent')),
    PRIMARY KEY (site_id, alert_key, entity_id, role),
    FOREIGN KEY (site_id, alert_key, event_ts)
        REFERENCES alert_registry(site_id, alert_key, original_event_ts),
    FOREIGN KEY (site_id, entity_id) REFERENCES entities(site_id, entity_id)
);

CREATE INDEX alert_entities_site_entity_idx ON alert_entities (site_id, entity_id, alert_key);

ALTER TABLE entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE entities FORCE ROW LEVEL SECURITY;
CREATE POLICY entities_site_scope ON entities
    USING (site_id = COALESCE(current_setting('app.site_id', true), ''))
    WITH CHECK (site_id = COALESCE(current_setting('app.site_id', true), ''));

ALTER TABLE alert_entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_entities FORCE ROW LEVEL SECURITY;
CREATE POLICY alert_entities_site_scope ON alert_entities
    USING (site_id = COALESCE(current_setting('app.site_id', true), ''))
    WITH CHECK (site_id = COALESCE(current_setting('app.site_id', true), ''));
