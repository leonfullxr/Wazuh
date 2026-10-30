CREATE TABLE alert_registry (
    site_id text NOT NULL REFERENCES sites(site_id),
    alert_key text NOT NULL CHECK (alert_key ~ '^[0-9a-f]{64}$'),
    index_name text NOT NULL,
    doc_id text NOT NULL,
    original_event_ts timestamptz NOT NULL,
    source_hash text NOT NULL CHECK (source_hash ~ '^[0-9a-f]{64}$'),
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_id, alert_key),
    UNIQUE (site_id, index_name, doc_id),
    UNIQUE (site_id, alert_key, original_event_ts)
);

CREATE TABLE alert_mutations (
    mutation_id bigserial PRIMARY KEY,
    site_id text NOT NULL,
    alert_key text NOT NULL,
    observed_event_ts timestamptz NOT NULL,
    observed_source_hash text NOT NULL CHECK (observed_source_hash ~ '^[0-9a-f]{64}$'),
    observed_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (site_id, alert_key, observed_event_ts, observed_source_hash),
    FOREIGN KEY (site_id, alert_key) REFERENCES alert_registry(site_id, alert_key)
);

CREATE TABLE alerts (
    site_id text NOT NULL,
    alert_key text NOT NULL,
    event_ts timestamptz NOT NULL,
    ingested_at timestamptz NOT NULL DEFAULT now(),
    index_name text NOT NULL,
    doc_id text NOT NULL,
    normalized jsonb,
    raw jsonb NOT NULL,
    source_hash text NOT NULL CHECK (source_hash ~ '^[0-9a-f]{64}$'),
    mapping_profile text NOT NULL,
    normalized_at timestamptz,
    normalize_gaps text[],
    CHECK (jsonb_typeof(raw) = 'object'),
    CHECK (normalized IS NULL OR jsonb_typeof(normalized) = 'object'),
    CHECK ((normalized_at IS NULL) = (normalized IS NULL)),
    CHECK ((normalized_at IS NULL) = (normalize_gaps IS NULL)),
    PRIMARY KEY (site_id, alert_key, event_ts),
    FOREIGN KEY (site_id, alert_key, event_ts)
        REFERENCES alert_registry(site_id, alert_key, original_event_ts)
) PARTITION BY RANGE (event_ts);

CREATE FUNCTION workspace_reject_registry_rewrite() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'alert registry identities are durable tombstones';
END;
$$;

CREATE TRIGGER alert_registry_no_delete
BEFORE UPDATE OR DELETE ON alert_registry
FOR EACH ROW EXECUTE FUNCTION workspace_reject_registry_rewrite();

CREATE FUNCTION workspace_reject_mutation_rewrite() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'alert mutation records are append-only';
END;
$$;

CREATE TRIGGER alert_mutations_append_only
BEFORE UPDATE OR DELETE ON alert_mutations
FOR EACH ROW EXECUTE FUNCTION workspace_reject_mutation_rewrite();

CREATE FUNCTION workspace_guard_alert_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.site_id, NEW.alert_key, NEW.event_ts, NEW.index_name, NEW.doc_id, NEW.raw,
        NEW.source_hash, NEW.ingested_at)
       IS DISTINCT FROM
       (OLD.site_id, OLD.alert_key, OLD.event_ts, OLD.index_name, OLD.doc_id, OLD.raw,
        OLD.source_hash, OLD.ingested_at) THEN
        RAISE EXCEPTION 'alert source payload and identity are immutable';
    END IF;
    IF OLD.normalized_at IS NOT NULL AND
       (NEW.normalized, NEW.mapping_profile, NEW.normalized_at, NEW.normalize_gaps)
       IS DISTINCT FROM
       (OLD.normalized, OLD.mapping_profile, OLD.normalized_at, OLD.normalize_gaps) THEN
        RAISE EXCEPTION 'normalized values are immutable after first write';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER alerts_source_immutable
BEFORE UPDATE ON alerts
FOR EACH ROW EXECUTE FUNCTION workspace_guard_alert_update();

ALTER TABLE alert_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_registry FORCE ROW LEVEL SECURITY;
CREATE POLICY alert_registry_site_scope ON alert_registry
    USING (site_id = COALESCE(current_setting('app.site_id', true), ''))
    WITH CHECK (site_id = COALESCE(current_setting('app.site_id', true), ''));

ALTER TABLE alert_mutations ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_mutations FORCE ROW LEVEL SECURITY;
CREATE POLICY alert_mutations_site_scope ON alert_mutations
    USING (site_id = COALESCE(current_setting('app.site_id', true), ''))
    WITH CHECK (site_id = COALESCE(current_setting('app.site_id', true), ''));

ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts FORCE ROW LEVEL SECURITY;
CREATE POLICY alerts_site_scope ON alerts
    USING (site_id = COALESCE(current_setting('app.site_id', true), ''))
    WITH CHECK (site_id = COALESCE(current_setting('app.site_id', true), ''));
