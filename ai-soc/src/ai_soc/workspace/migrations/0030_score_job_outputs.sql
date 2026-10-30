CREATE TABLE score_job_outputs (
    site_id text NOT NULL,
    job_id bigint NOT NULL,
    group_id text NOT NULL,
    group_revision text NOT NULL,
    computation_version text NOT NULL,
    input_digest text NOT NULL CHECK (input_digest ~ '^[0-9a-f]{64}$'),
    producing_attempt integer NOT NULL CHECK (producing_attempt > 0),
    producing_lease_token uuid NOT NULL,
    PRIMARY KEY (site_id, job_id),
    FOREIGN KEY (site_id, job_id) REFERENCES jobs(site_id, job_id),
    FOREIGN KEY (site_id, group_id, group_revision, computation_version, input_digest)
        REFERENCES scores(site_id, group_id, group_revision, computation_version, input_digest)
);

CREATE INDEX score_job_outputs_key_job_idx
    ON score_job_outputs
    (site_id, group_id, group_revision, computation_version, input_digest, job_id DESC);

CREATE FUNCTION workspace_score_job_output_insert_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE job_row jobs%ROWTYPE;
BEGIN
    SELECT * INTO job_row FROM jobs
    WHERE site_id = NEW.site_id AND job_id = NEW.job_id
    FOR KEY SHARE;
    IF NOT FOUND OR job_row.state <> 'running'
       OR job_row.kind NOT IN ('enrich_group', 'rescore_group')
       OR job_row.attempts <> NEW.producing_attempt
       OR job_row.lease_token IS DISTINCT FROM NEW.producing_lease_token
       OR job_row.payload->>'group_id' IS DISTINCT FROM NEW.group_id
       OR job_row.payload->>'group_revision' IS DISTINCT FROM NEW.group_revision THEN
        RAISE EXCEPTION 'score output does not match the live producing job';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER score_job_outputs_insert_guard
BEFORE INSERT ON score_job_outputs
FOR EACH ROW EXECUTE FUNCTION workspace_score_job_output_insert_guard();

CREATE FUNCTION workspace_score_job_output_completed_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    job_row jobs%ROWTYPE;
    previous_site text;
    job_found boolean;
BEGIN
    previous_site := current_setting('app.site_id', true);
    PERFORM set_config('app.site_id', NEW.site_id, true);
    SELECT * INTO job_row FROM jobs
    WHERE site_id = NEW.site_id AND job_id = NEW.job_id;
    job_found := FOUND;
    PERFORM set_config('app.site_id', COALESCE(previous_site, ''), true);
    IF NOT job_found OR job_row.state <> 'done' OR job_row.completed_at IS NULL
       OR job_row.attempts <> NEW.producing_attempt THEN
        RAISE EXCEPTION 'score output requires its producer job to complete with known time';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER score_job_outputs_completed_guard
AFTER INSERT ON score_job_outputs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION workspace_score_job_output_completed_guard();

CREATE FUNCTION workspace_linked_score_job_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM score_job_outputs o
               WHERE o.site_id = OLD.site_id AND o.job_id = OLD.job_id)
       AND ((NEW.site_id, NEW.job_id, NEW.kind, NEW.subject, NEW.payload)
            IS DISTINCT FROM
            (OLD.site_id, OLD.job_id, OLD.kind, OLD.subject, OLD.payload)
            OR (OLD.state = 'running'
                AND (NEW.attempts IS DISTINCT FROM OLD.attempts
                    OR NOT ((NEW.state = 'running'
                             AND NEW.lease_token IS NOT DISTINCT FROM OLD.lease_token
                             AND NEW.locked_by IS NOT DISTINCT FROM OLD.locked_by)
                            OR (NEW.state = 'done' AND NEW.lease_token IS NULL
                                AND NEW.locked_by IS NULL))))
            OR (OLD.state = 'done'
                AND (NEW.state, NEW.attempts, NEW.completed_at)
                    IS DISTINCT FROM (OLD.state, OLD.attempts, OLD.completed_at))) THEN
        RAISE EXCEPTION 'a recorded score producer cannot be rebound or rewritten';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER linked_score_job_immutable
BEFORE UPDATE ON jobs
FOR EACH ROW EXECUTE FUNCTION workspace_linked_score_job_immutable();

CREATE TRIGGER score_job_outputs_immutable BEFORE UPDATE OR DELETE ON score_job_outputs
FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite();

ALTER TABLE score_job_outputs ENABLE ROW LEVEL SECURITY;
ALTER TABLE score_job_outputs FORCE ROW LEVEL SECURITY;
CREATE POLICY score_job_outputs_site_scope ON score_job_outputs
USING (site_id = COALESCE(current_setting('app.site_id', true), ''))
WITH CHECK (site_id = COALESCE(current_setting('app.site_id', true), ''));
