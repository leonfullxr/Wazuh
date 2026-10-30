CREATE TABLE incidents (
    site_id text NOT NULL,
    incident_id uuid NOT NULL,
    title text NOT NULL CHECK (length(title) BETWEEN 1 AND 240),
    owner_key text CHECK (owner_key IS NULL OR length(owner_key) BETWEEN 1 AND 256),
    status text NOT NULL CHECK (status IN ('new', 'in_progress', 'resolved', 'closed')),
    work_version integer NOT NULL CHECK (work_version >= 1),
    evidence_head uuid,
    created_at timestamptz NOT NULL,
    created_by text NOT NULL CHECK (length(created_by) BETWEEN 1 AND 256),
    PRIMARY KEY (site_id, incident_id),
    UNIQUE (site_id, incident_id, evidence_head)
);
CREATE FUNCTION workspace_require_incident_subject() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM subject_registry s WHERE s.site_id=NEW.site_id
                   AND s.subject_kind='incident' AND s.subject_id=NEW.incident_id::text) THEN
        RAISE EXCEPTION 'incident identity requires a registered incident subject';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER incidents_registered_subject BEFORE INSERT ON incidents
FOR EACH ROW EXECUTE FUNCTION workspace_require_incident_subject();

CREATE TABLE incident_membership_intervals (
    site_id text NOT NULL,
    membership_id uuid NOT NULL,
    incident_id uuid NOT NULL,
    group_id text NOT NULL,
    added_by text NOT NULL CHECK (length(added_by) BETWEEN 1 AND 256),
    added_at timestamptz NOT NULL,
    removed_by text CHECK (removed_by IS NULL OR length(removed_by) BETWEEN 1 AND 256),
    removed_at timestamptz,
    PRIMARY KEY (site_id, membership_id),
    UNIQUE (site_id, incident_id, group_id, membership_id),
    FOREIGN KEY (site_id, incident_id) REFERENCES incidents(site_id, incident_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (site_id, group_id) REFERENCES groups(site_id, group_id),
    CHECK ((removed_by IS NULL) = (removed_at IS NULL)),
    CHECK (removed_at IS NULL OR removed_at >= added_at)
);
CREATE UNIQUE INDEX incident_membership_one_active_group
    ON incident_membership_intervals(site_id, incident_id, group_id) WHERE removed_at IS NULL;
CREATE FUNCTION workspace_guard_incident_membership_close() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'UPDATE' OR OLD.removed_at IS NOT NULL
       OR NEW.site_id <> OLD.site_id OR NEW.membership_id <> OLD.membership_id
       OR NEW.incident_id <> OLD.incident_id OR NEW.group_id <> OLD.group_id
       OR NEW.added_by <> OLD.added_by OR NEW.added_at <> OLD.added_at
       OR NEW.removed_at IS NULL OR NEW.removed_by IS NULL THEN
        RAISE EXCEPTION 'membership intervals are immutable except for one close';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER incident_membership_close_only BEFORE UPDATE OR DELETE ON incident_membership_intervals
FOR EACH ROW EXECUTE FUNCTION workspace_guard_incident_membership_close();
CREATE FUNCTION workspace_check_incident_membership_bound() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE active_count integer;
BEGIN
    SELECT count(*) INTO active_count FROM incident_membership_intervals m
      WHERE m.site_id=NEW.site_id AND m.incident_id=NEW.incident_id AND m.removed_at IS NULL;
    IF active_count < 1 OR active_count > 100 THEN
        RAISE EXCEPTION 'incidents require 1..100 active group memberships';
    END IF;
    RETURN NULL;
END;
$$;
CREATE TRIGGER incident_has_active_members AFTER INSERT ON incidents
FOR EACH ROW
EXECUTE FUNCTION workspace_check_incident_membership_bound();
CREATE TRIGGER membership_keeps_incident_nonempty
AFTER INSERT OR UPDATE ON incident_membership_intervals
FOR EACH ROW
EXECUTE FUNCTION workspace_check_incident_membership_bound();
CREATE TABLE incident_evidence_revisions (
    site_id text NOT NULL,
    incident_revision_id uuid NOT NULL,
    incident_id uuid NOT NULL,
    revision_seq integer NOT NULL CHECK (revision_seq >= 1),
    content_digest text NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    as_of timestamptz NOT NULL,
    policy_id text NOT NULL CHECK (policy_id = 'workspace.incident-priority.v1'),
    priority numeric(9,6) CHECK (priority IS NULL OR priority BETWEEN 0 AND 100),
    promotion_chain_id text,
    promotion_revision_digest text,
    promotion_manifest_id uuid,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, incident_revision_id),
    UNIQUE (site_id, incident_id, revision_seq),
    UNIQUE (site_id, incident_id, incident_revision_id),
    FOREIGN KEY (site_id, incident_id) REFERENCES incidents(site_id, incident_id),
    FOREIGN KEY (site_id, promotion_chain_id, promotion_revision_digest, promotion_manifest_id)
        REFERENCES correlation_chain_revisions(site_id, chain_id, revision_digest, manifest_id),
    CHECK ((promotion_chain_id IS NULL) = (promotion_revision_digest IS NULL)
       AND (promotion_chain_id IS NULL) = (promotion_manifest_id IS NULL))
);
ALTER TABLE incidents ADD CONSTRAINT incidents_evidence_head_fk
    FOREIGN KEY (site_id, incident_id, evidence_head)
    REFERENCES incident_evidence_revisions(site_id, incident_id, incident_revision_id)
    DEFERRABLE INITIALLY DEFERRED;
CREATE UNIQUE INDEX incident_one_per_promoted_chain
    ON incident_evidence_revisions(site_id, promotion_chain_id)
    WHERE promotion_chain_id IS NOT NULL;

CREATE TABLE incident_revision_members (
    site_id text NOT NULL,
    incident_id uuid NOT NULL,
    incident_revision_id uuid NOT NULL,
    group_id text NOT NULL,
    membership_id uuid NOT NULL,
    group_revision text NOT NULL,
    score_version text,
    score_digest text,
    score numeric(9,6) CHECK (score IS NULL OR score BETWEEN 0 AND 100),
    PRIMARY KEY (site_id, incident_revision_id, group_id),
    FOREIGN KEY (site_id, incident_id, incident_revision_id)
        REFERENCES incident_evidence_revisions(site_id, incident_id, incident_revision_id),
    FOREIGN KEY (site_id, incident_id, group_id, membership_id)
        REFERENCES incident_membership_intervals(site_id, incident_id, group_id, membership_id),
    FOREIGN KEY (site_id, group_id, group_revision)
        REFERENCES group_revisions(site_id, group_id, revision),
    FOREIGN KEY (site_id, group_id, group_revision, score_version, score_digest)
        REFERENCES scores(site_id, group_id, group_revision, computation_version, input_digest),
    CHECK ((score_version IS NULL) = (score_digest IS NULL)),
    CHECK ((score IS NULL) = (score_version IS NULL))
);
CREATE FUNCTION workspace_check_evidence_membership_active() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM incident_membership_intervals m WHERE m.site_id=NEW.site_id
       AND m.incident_id=NEW.incident_id AND m.group_id=NEW.group_id
       AND m.membership_id=NEW.membership_id AND m.removed_at IS NULL) THEN
        RAISE EXCEPTION 'evidence member must reference an active membership interval';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER incident_evidence_member_active BEFORE INSERT ON incident_revision_members
FOR EACH ROW EXECUTE FUNCTION workspace_check_evidence_membership_active();

CREATE TABLE incident_history (
    site_id text NOT NULL,
    history_id uuid NOT NULL,
    incident_id uuid NOT NULL,
    incident_revision_id uuid,
    work_version integer NOT NULL,
    actor_key text NOT NULL CHECK (length(actor_key) BETWEEN 1 AND 256),
    action text NOT NULL CHECK (action IN ('created','members_changed','assigned','status_changed','commented','disposition','promoted','evidence_refreshed')),
    before_value jsonb,
    after_value jsonb NOT NULL CHECK (jsonb_typeof(after_value)='object'),
    at timestamptz NOT NULL,
    PRIMARY KEY (site_id, history_id),
    FOREIGN KEY (site_id, incident_id) REFERENCES incidents(site_id, incident_id),
    FOREIGN KEY (site_id, incident_id, incident_revision_id)
        REFERENCES incident_evidence_revisions(site_id, incident_id, incident_revision_id)
);
CREATE TABLE incident_comments (
    site_id text NOT NULL,
    comment_id uuid NOT NULL,
    incident_id uuid NOT NULL,
    incident_revision_id uuid NOT NULL,
    work_version integer NOT NULL,
    actor_key text NOT NULL CHECK (length(actor_key) BETWEEN 1 AND 256),
    body text NOT NULL CHECK (length(body) BETWEEN 1 AND 4000),
    at timestamptz NOT NULL,
    PRIMARY KEY (site_id, comment_id),
    FOREIGN KEY (site_id, incident_id) REFERENCES incidents(site_id, incident_id),
    FOREIGN KEY (site_id, incident_id, incident_revision_id)
        REFERENCES incident_evidence_revisions(site_id, incident_id, incident_revision_id)
);
CREATE TABLE incident_dispositions (
    site_id text NOT NULL,
    disposition_id uuid NOT NULL,
    incident_id uuid NOT NULL,
    incident_revision_id uuid NOT NULL,
    work_version integer NOT NULL,
    label text NOT NULL CHECK (label IN ('true_positive','benign_true_positive','false_positive','duplicate','undetermined')),
    reason_code text CHECK (reason_code IS NULL OR length(reason_code)<=64),
    note text CHECK (note IS NULL OR length(note)<=2000),
    actor_key text NOT NULL CHECK (length(actor_key) BETWEEN 1 AND 256),
    at timestamptz NOT NULL,
    PRIMARY KEY (site_id, disposition_id),
    FOREIGN KEY (site_id, incident_id) REFERENCES incidents(site_id, incident_id),
    FOREIGN KEY (site_id, incident_id, incident_revision_id)
        REFERENCES incident_evidence_revisions(site_id, incident_id, incident_revision_id),
    CHECK (label <> 'false_positive' OR reason_code IN ('expected_admin_activity','known_scanner','misconfigured_rule','test_activity','other')),
    CHECK (reason_code <> 'other' OR note IS NOT NULL)
);
CREATE TRIGGER incident_evidence_immutable BEFORE UPDATE OR DELETE ON incident_evidence_revisions
FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite();
CREATE TRIGGER incident_revision_members_immutable BEFORE UPDATE OR DELETE ON incident_revision_members
FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite();
CREATE TRIGGER incident_history_immutable BEFORE UPDATE OR DELETE ON incident_history
FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite();
CREATE TRIGGER incident_comments_immutable BEFORE UPDATE OR DELETE ON incident_comments
FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite();
CREATE TRIGGER incident_dispositions_immutable BEFORE UPDATE OR DELETE ON incident_dispositions
FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite();
CREATE FUNCTION workspace_guard_incident_state() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.site_id <> OLD.site_id OR NEW.incident_id <> OLD.incident_id
       OR NEW.created_at <> OLD.created_at OR NEW.created_by <> OLD.created_by
       OR NEW.title IS NULL OR NEW.work_version < OLD.work_version
       OR NEW.work_version > OLD.work_version + 1 THEN
        RAISE EXCEPTION 'invalid incident state transition';
    END IF;
    IF (NEW.title,NEW.owner_key,NEW.status) IS DISTINCT FROM
       (OLD.title,OLD.owner_key,OLD.status) AND NEW.work_version <> OLD.work_version+1 THEN
        RAISE EXCEPTION 'analyst state changes require one work version increment';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER incident_state_guard BEFORE UPDATE ON incidents
FOR EACH ROW EXECUTE FUNCTION workspace_guard_incident_state();
DO $$ DECLARE t text; BEGIN
    FOREACH t IN ARRAY ARRAY['incidents','incident_membership_intervals','incident_evidence_revisions',
      'incident_revision_members','incident_history','incident_comments','incident_dispositions'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
        EXECUTE format('CREATE POLICY %I ON %I USING (site_id=COALESCE(current_setting(''app.site_id'',true),'''')) WITH CHECK (site_id=COALESCE(current_setting(''app.site_id'',true),''''))',t||'_site_scope',t);
    END LOOP;
END $$;
ALTER TABLE correlation_decisions DROP CONSTRAINT correlation_decisions_state_check;
ALTER TABLE correlation_decisions ADD CONSTRAINT correlation_decisions_state_check
    CHECK (state IN ('open','dismissed','promoted'));
ALTER TABLE correlation_decision_history DROP CONSTRAINT correlation_decision_history_state_check;
ALTER TABLE correlation_decision_history ADD CONSTRAINT correlation_decision_history_state_check
    CHECK (state IN ('open','dismissed','promoted'));
CREATE OR REPLACE FUNCTION workspace_require_correlation_history_audit() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE expected_kind text;
BEGIN
    IF NEW.version <> COALESCE((SELECT max(h.version)+1 FROM correlation_decision_history h
       WHERE h.site_id=NEW.site_id AND h.chain_id=NEW.chain_id),1) THEN
        RAISE EXCEPTION 'correlation decision history versions must be sequential';
    END IF;
    expected_kind := CASE WHEN NEW.state='promoted' THEN 'incident_candidate_promoted'
                         ELSE 'correlation_candidate_dismissed' END;
    IF NOT EXISTS (SELECT 1 FROM audit_outbox a WHERE a.site_id=NEW.site_id
       AND a.event_id=NEW.audit_event_id AND a.kind=expected_kind AND a.actor_key=NEW.actor_key
       AND a.payload->>'chain_id'=NEW.chain_id AND a.payload->>'version'=NEW.version::text
       AND a.payload->>'idempotency_key'=NEW.idempotency_key
       AND (NEW.state <> 'dismissed' OR a.payload->>'reason' IS NOT DISTINCT FROM NEW.reason)) THEN
        RAISE EXCEPTION 'correlation decision history requires a matching audit event';
    END IF;
    RETURN NEW;
END;
$$;
