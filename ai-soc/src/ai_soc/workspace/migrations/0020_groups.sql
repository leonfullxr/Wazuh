CREATE TABLE subject_registry (
    site_id text NOT NULL REFERENCES sites(site_id),
    subject_kind text NOT NULL CHECK (subject_kind IN ('entity', 'group', 'chain', 'incident')),
    subject_id text NOT NULL,
    PRIMARY KEY (site_id, subject_kind, subject_id)
);
ALTER TABLE subject_registry ADD CONSTRAINT subject_registry_site_id_unique UNIQUE (site_id, subject_id);


CREATE TABLE groups (
    site_id text NOT NULL REFERENCES sites(site_id),
    group_id text NOT NULL CHECK (group_id ~ '^[0-9a-f]{64}$'),
    fingerprint_spec text NOT NULL,
    fingerprint text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    bucket_start timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, group_id),
    UNIQUE (site_id, fingerprint_spec, fingerprint, bucket_start),
    FOREIGN KEY (site_id, group_id) REFERENCES subject_registry(site_id, subject_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE FUNCTION workspace_require_group_subject() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM subject_registry AS subject
        WHERE subject.site_id = NEW.site_id
          AND subject.subject_kind = 'group'
          AND subject.subject_id = NEW.group_id
    ) THEN
        RAISE EXCEPTION 'group identity requires a registered group subject';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER groups_registered_subject BEFORE INSERT ON groups
FOR EACH ROW EXECUTE FUNCTION workspace_require_group_subject();

CREATE TABLE group_revisions (
    site_id text NOT NULL,
    group_id text NOT NULL,
    revision text NOT NULL CHECK (revision ~ '^[0-9a-f]{64}$'),
    first_ts timestamptz NOT NULL,
    last_ts timestamptz NOT NULL,
    alert_count integer NOT NULL CHECK (alert_count > 0),
    rule_id text,
    agent_id text,
    primary_entity text,
    title text NOT NULL,
    pipeline_version text NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, group_id, revision),
    FOREIGN KEY (site_id, group_id) REFERENCES groups(site_id, group_id),
    CHECK (first_ts <= last_ts)
);

CREATE TABLE group_members (
    site_id text NOT NULL,
    group_id text NOT NULL,
    group_revision text NOT NULL,
    alert_key text NOT NULL,
    event_ts timestamptz NOT NULL,
    source_hash text NOT NULL CHECK (source_hash ~ '^[0-9a-f]{64}$'),
    normalized_snapshot jsonb NOT NULL CHECK (jsonb_typeof(normalized_snapshot) = 'object'),
    PRIMARY KEY (site_id, group_id, group_revision, alert_key),
    FOREIGN KEY (site_id, group_id, group_revision)
        REFERENCES group_revisions(site_id, group_id, revision),
    FOREIGN KEY (site_id, alert_key, event_ts)
        REFERENCES alert_registry(site_id, alert_key, original_event_ts)
);

CREATE TABLE group_heads (
    site_id text NOT NULL,
    group_id text NOT NULL,
    current_revision text NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, group_id),
    FOREIGN KEY (site_id, group_id) REFERENCES groups(site_id, group_id),
    FOREIGN KEY (site_id, group_id, current_revision)
        REFERENCES group_revisions(site_id, group_id, revision)
);

CREATE INDEX groups_bucket_idx ON groups (site_id, bucket_start DESC, group_id);
CREATE INDEX group_revisions_recent_idx ON group_revisions (site_id, last_ts DESC, group_id);
CREATE INDEX group_members_alert_idx ON group_members (site_id, alert_key);
CREATE INDEX group_heads_revision_idx ON group_heads (site_id, current_revision);

CREATE FUNCTION workspace_reject_immutable_rewrite() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER subject_registry_immutable BEFORE UPDATE OR DELETE ON subject_registry
FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite();
CREATE TRIGGER groups_identity_immutable BEFORE UPDATE OR DELETE ON groups
FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite();
CREATE TRIGGER group_revisions_immutable BEFORE UPDATE OR DELETE ON group_revisions
FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite();
CREATE TRIGGER group_members_immutable BEFORE UPDATE OR DELETE ON group_members
FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite();

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['subject_registry', 'groups', 'group_revisions', 'group_members', 'group_heads'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY %I ON %I USING (site_id = COALESCE(current_setting(''app.site_id'', true), '''')) WITH CHECK (site_id = COALESCE(current_setting(''app.site_id'', true), ''''))',
            t || '_site_scope', t
        );
    END LOOP;
END;
$$;
