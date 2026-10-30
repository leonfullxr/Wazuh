CREATE TABLE narrative_runtime_bindings (
    site_id text PRIMARY KEY REFERENCES sites(site_id),
    host_id text NOT NULL,
    runtime_id text NOT NULL,
    slot_directory text NOT NULL CHECK (left(slot_directory,1) = '/'),
    directory_device bigint NOT NULL,
    directory_inode bigint NOT NULL,
    slot_count integer NOT NULL CHECK (slot_count = 1),
    provisioned_at timestamptz NOT NULL,
    UNIQUE (site_id, host_id, runtime_id)
);
CREATE FUNCTION workspace_narrative_runtime_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM narrative_runtime_bindings b WHERE b.host_id=NEW.host_id
       AND (b.runtime_id,b.slot_directory,b.directory_device,b.directory_inode)
           IS DISTINCT FROM
           (NEW.runtime_id,NEW.slot_directory,NEW.directory_device,NEW.directory_inode)) THEN
        RAISE EXCEPTION 'one host requires one protected narrative slot domain';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER narrative_runtime_domain BEFORE INSERT ON narrative_runtime_bindings
FOR EACH ROW EXECUTE FUNCTION workspace_narrative_runtime_guard();
CREATE TABLE narrative_generations (
    site_id text NOT NULL,
    generation_id uuid NOT NULL,
    incident_id uuid NOT NULL,
    incident_revision_id uuid NOT NULL,
    revision_seq integer NOT NULL CHECK (revision_seq > 0),
    preparation_job_id bigint NOT NULL,
    preparation_attempt integer NOT NULL CHECK (preparation_attempt > 0),
    preparation_lease_token uuid NOT NULL,
    narrate_job_id bigint NOT NULL,
    pack_bytes bytea NOT NULL CHECK (octet_length(pack_bytes) <= 65536),
    pack_digest text NOT NULL CHECK (pack_digest ~ '^[0-9a-f]{64}$'),
    prompt_bytes bytea NOT NULL CHECK (octet_length(prompt_bytes) <= 131072),
    prompt_sha256 text NOT NULL CHECK (prompt_sha256 ~ '^[0-9a-f]{64}$'),
    schema_bytes bytea NOT NULL,
    instructions_bytes bytea NOT NULL,
    catalog_bytes bytea NOT NULL,
    execution_bundle jsonb NOT NULL CHECK (jsonb_typeof(execution_bundle)='object'),
    generation_digest text NOT NULL CHECK (generation_digest ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (site_id,generation_id),
    UNIQUE (site_id,generation_digest),
    UNIQUE (site_id,narrate_job_id),
    UNIQUE (site_id,incident_id,incident_revision_id,generation_id),
    FOREIGN KEY (site_id,incident_id,incident_revision_id)
        REFERENCES incident_evidence_revisions(site_id,incident_id,incident_revision_id),
    FOREIGN KEY (site_id,preparation_job_id) REFERENCES jobs(site_id,job_id),
    FOREIGN KEY (site_id,narrate_job_id) REFERENCES jobs(site_id,job_id)
);
CREATE FUNCTION workspace_narrative_generation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p jobs%ROWTYPE; n jobs%ROWTYPE; e incident_evidence_revisions%ROWTYPE;
BEGIN
    SELECT * INTO p FROM jobs WHERE site_id=NEW.site_id AND job_id=NEW.preparation_job_id;
    SELECT * INTO n FROM jobs WHERE site_id=NEW.site_id AND job_id=NEW.narrate_job_id;
    SELECT * INTO e FROM incident_evidence_revisions WHERE site_id=NEW.site_id
        AND incident_revision_id=NEW.incident_revision_id;
    IF p.kind IS DISTINCT FROM 'prepare_narrative' OR p.state IS DISTINCT FROM 'running'
       OR p.attempts IS DISTINCT FROM NEW.preparation_attempt
       OR p.lease_token IS DISTINCT FROM NEW.preparation_lease_token
       OR p.subject IS DISTINCT FROM NEW.incident_revision_id::text
       OR p.payload->>'incident_id' IS DISTINCT FROM NEW.incident_id::text
       OR p.payload->>'incident_revision_id' IS DISTINCT FROM NEW.incident_revision_id::text
       OR p.payload->>'revision_seq' IS DISTINCT FROM NEW.revision_seq::text
       OR e.incident_id IS DISTINCT FROM NEW.incident_id
       OR e.revision_seq IS DISTINCT FROM NEW.revision_seq
       OR n.kind IS DISTINCT FROM 'narrate' OR n.state IS DISTINCT FROM 'queued'
       OR n.subject IS DISTINCT FROM NEW.generation_digest
       OR n.payload <> jsonb_build_object('generation_id',NEW.generation_id::text) THEN
        RAISE EXCEPTION 'generation requires exact preparation evidence and successor request';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER narrative_generation_guard BEFORE INSERT ON narrative_generations
FOR EACH ROW EXECUTE FUNCTION workspace_narrative_generation_guard();
CREATE TABLE narrative_calls (
    site_id text NOT NULL,
    call_id uuid NOT NULL,
    generation_id uuid NOT NULL,
    job_id bigint NOT NULL,
    producing_attempt integer NOT NULL CHECK (producing_attempt BETWEEN 1 AND 5),
    producing_lease_token uuid NOT NULL,
    worker_id text NOT NULL,
    host_id text NOT NULL,
    runtime_id text NOT NULL,
    boot_id text NOT NULL,
    guardian_pid integer NOT NULL CHECK (guardian_pid > 0),
    guardian_start text NOT NULL,
    slot integer NOT NULL CHECK (slot=0),
    authorized_at timestamptz NOT NULL,
    PRIMARY KEY (site_id,call_id),
    UNIQUE (site_id,job_id,producing_attempt),
    UNIQUE (site_id,generation_id,call_id),
    FOREIGN KEY (site_id,generation_id) REFERENCES narrative_generations(site_id,generation_id),
    FOREIGN KEY (site_id,job_id) REFERENCES jobs(site_id,job_id),
    FOREIGN KEY (site_id,host_id,runtime_id)
        REFERENCES narrative_runtime_bindings(site_id,host_id,runtime_id)
);
CREATE TABLE narrative_outcomes (
    site_id text NOT NULL,
    call_id uuid NOT NULL,
    generation_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('validated','all_removed','unavailable','abandoned_unknown')),
    error_code text CHECK (error_code ~ '^[a-z][a-z0-9_]{0,95}$'),
    narrative jsonb CHECK (narrative IS NULL OR jsonb_typeof(narrative)='object'),
    input_tokens bigint CHECK (input_tokens >= 0),
    cached_input_tokens bigint CHECK (cached_input_tokens >= 0),
    output_tokens bigint CHECK (output_tokens >= 0),
    provenance jsonb NOT NULL CHECK (jsonb_typeof(provenance)='object'),
    elapsed_ms integer CHECK (elapsed_ms >= 0),
    finished_at timestamptz NOT NULL,
    PRIMARY KEY (site_id,call_id),
    UNIQUE (site_id,generation_id,call_id),
    FOREIGN KEY (site_id,generation_id,call_id)
        REFERENCES narrative_calls(site_id,generation_id,call_id),
    CHECK ((status IN ('validated','all_removed')) = (narrative IS NOT NULL)),
    CHECK (status <> 'validated' OR (narrative->>'status'='validated'
       AND jsonb_array_length(narrative->'selections') BETWEEN 1 AND 8)),
    CHECK (status <> 'all_removed' OR (narrative->>'status'='all_removed'
       AND jsonb_array_length(narrative->'selections')=0))
);
CREATE FUNCTION workspace_narrative_outcome_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE c narrative_calls%ROWTYPE; j jobs%ROWTYPE; g narrative_generations%ROWTYPE;
BEGIN
    SELECT * INTO c FROM narrative_calls WHERE site_id=NEW.site_id AND call_id=NEW.call_id;
    SELECT * INTO j FROM jobs WHERE site_id=c.site_id AND job_id=c.job_id FOR UPDATE;
    SELECT * INTO g FROM narrative_generations WHERE site_id=c.site_id
        AND generation_id=c.generation_id;
    IF j.state IS DISTINCT FROM 'running' OR j.attempts IS DISTINCT FROM c.producing_attempt
       OR j.lease_token IS DISTINCT FROM c.producing_lease_token
       OR j.locked_by IS DISTINCT FROM c.worker_id
       OR NEW.generation_id IS DISTINCT FROM c.generation_id THEN
        RAISE EXCEPTION 'narrative outcome requires its producing attempt';
    END IF;
    IF NEW.status='abandoned_unknown' THEN
        IF j.locked_until > clock_timestamp() OR j.locked_until > NEW.finished_at THEN
            RAISE EXCEPTION 'only expired authorizations may be abandoned';
        END IF;
    ELSIF j.locked_until <= clock_timestamp() OR j.locked_until <= NEW.finished_at THEN
        RAISE EXCEPTION 'expired narrative attempts cannot persist results';
    END IF;
    IF NEW.narrative IS NOT NULL AND
        (NEW.narrative->>'pack_digest' IS DISTINCT FROM g.pack_digest
         OR NEW.narrative->>'status' IS DISTINCT FROM NEW.status) THEN
        RAISE EXCEPTION 'narrative outcome requires its frozen pack';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER narrative_outcome_guard BEFORE INSERT ON narrative_outcomes
FOR EACH ROW EXECUTE FUNCTION workspace_narrative_outcome_guard();
CREATE FUNCTION workspace_narrative_outcome_closed_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE j jobs%ROWTYPE; c narrative_calls%ROWTYPE; previous_site text;
BEGIN
    previous_site := current_setting('app.site_id',true);
    PERFORM set_config('app.site_id',NEW.site_id,true);
    SELECT * INTO c FROM narrative_calls WHERE site_id=NEW.site_id AND call_id=NEW.call_id;
    SELECT * INTO j FROM jobs WHERE site_id=c.site_id AND job_id=c.job_id;
    PERFORM set_config('app.site_id',COALESCE(previous_site,''),true);
    IF j.attempts IS DISTINCT FROM c.producing_attempt
       OR (NEW.status IN ('validated','all_removed')
           AND (j.state IS DISTINCT FROM 'done' OR j.completed_at IS NULL))
       OR (NEW.status IN ('unavailable','abandoned_unknown')
           AND j.state NOT IN ('queued','dead')) THEN
        RAISE EXCEPTION 'narrative outcome must atomically close its producing attempt';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER narrative_outcome_closed_guard AFTER INSERT ON narrative_outcomes
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
EXECUTE FUNCTION workspace_narrative_outcome_closed_guard();
CREATE TABLE incident_narrative_heads (
    site_id text NOT NULL,
    incident_id uuid NOT NULL,
    incident_revision_id uuid NOT NULL,
    desired_generation_id uuid NOT NULL,
    published_call_id uuid,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (site_id,incident_id),
    FOREIGN KEY (site_id,incident_id,incident_revision_id,desired_generation_id)
        REFERENCES narrative_generations(site_id,incident_id,incident_revision_id,generation_id),
    FOREIGN KEY (site_id,desired_generation_id,published_call_id)
        REFERENCES narrative_outcomes(site_id,generation_id,call_id)
);
CREATE FUNCTION workspace_narrative_head_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM incidents i WHERE i.site_id=NEW.site_id
        AND i.incident_id=NEW.incident_id AND i.evidence_head=NEW.incident_revision_id) THEN
        RAISE EXCEPTION 'narrative target requires current incident evidence';
    END IF;
    IF NEW.published_call_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM narrative_outcomes o WHERE o.site_id=NEW.site_id
        AND o.generation_id=NEW.desired_generation_id AND o.call_id=NEW.published_call_id
        AND o.status='validated') THEN
        RAISE EXCEPTION 'only validated matching narrative outcomes may publish';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER narrative_head_guard BEFORE INSERT OR UPDATE ON incident_narrative_heads
FOR EACH ROW EXECUTE FUNCTION workspace_narrative_head_guard();
CREATE FUNCTION workspace_narrative_call_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE j jobs%ROWTYPE; g narrative_generations%ROWTYPE;
BEGIN
    SELECT * INTO j FROM jobs WHERE site_id=NEW.site_id AND job_id=NEW.job_id FOR UPDATE;
    SELECT * INTO g FROM narrative_generations WHERE site_id=NEW.site_id
        AND generation_id=NEW.generation_id;
    IF j.kind IS DISTINCT FROM 'narrate' OR j.state IS DISTINCT FROM 'running'
       OR j.attempts IS DISTINCT FROM NEW.producing_attempt
       OR j.lease_token IS DISTINCT FROM NEW.producing_lease_token
       OR j.locked_by IS DISTINCT FROM NEW.worker_id OR j.locked_until <= NEW.authorized_at
       OR g.narrate_job_id IS DISTINCT FROM NEW.job_id
       OR j.payload->>'generation_id' IS DISTINCT FROM NEW.generation_id::text
       OR j.subject IS DISTINCT FROM g.generation_digest THEN
        RAISE EXCEPTION 'narrative authorization requires its exact live request';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER narrative_call_guard BEFORE INSERT ON narrative_calls
FOR EACH ROW EXECUTE FUNCTION workspace_narrative_call_guard();
CREATE FUNCTION workspace_linked_narrative_job_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- Other narrow job roles need no SELECT permission on narrative tables.
    IF OLD.kind <> 'narrate' THEN RETURN NEW; END IF;
    IF EXISTS (SELECT 1 FROM narrative_generations g
               WHERE g.site_id=OLD.site_id AND g.narrate_job_id=OLD.job_id)
       AND (NEW.site_id,NEW.job_id,NEW.kind,NEW.subject,NEW.payload)
           IS DISTINCT FROM (OLD.site_id,OLD.job_id,OLD.kind,OLD.subject,OLD.payload) THEN
        RAISE EXCEPTION 'narrative producer request is immutable';
    END IF;
    IF OLD.state='running' AND EXISTS (SELECT 1 FROM narrative_calls c
        WHERE c.site_id=OLD.site_id AND c.job_id=OLD.job_id
          AND c.producing_attempt=OLD.attempts)
       AND (NEW.attempts IS DISTINCT FROM OLD.attempts
         OR (NEW.state='running' AND (NEW.lease_token,NEW.locked_by)
            IS DISTINCT FROM (OLD.lease_token,OLD.locked_by))
         OR (NEW.state <> 'running' AND NOT EXISTS (SELECT 1 FROM narrative_calls c
              JOIN narrative_outcomes o USING(site_id,call_id)
              WHERE c.site_id=OLD.site_id AND c.job_id=OLD.job_id
                AND c.producing_attempt=OLD.attempts))) THEN
        RAISE EXCEPTION 'running narrative authorization must close before retry';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER linked_narrative_job_guard BEFORE UPDATE ON jobs
FOR EACH ROW EXECUTE FUNCTION workspace_linked_narrative_job_guard();
DO $$ DECLARE t text; BEGIN
    FOREACH t IN ARRAY ARRAY['narrative_runtime_bindings','narrative_generations',
        'narrative_calls','narrative_outcomes','incident_narrative_heads'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
        EXECUTE format('CREATE POLICY %I ON %I USING (site_id = COALESCE(current_setting(''app.site_id'',true),'''')) WITH CHECK (site_id = COALESCE(current_setting(''app.site_id'',true),''''))',t||'_site_scope',t);
        IF t <> 'incident_narrative_heads' THEN
            EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION workspace_reject_immutable_rewrite()',t||'_immutable',t);
        END IF;
    END LOOP;
END $$;
