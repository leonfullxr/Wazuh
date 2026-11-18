ALTER TABLE narrative_calls
    ALTER COLUMN host_id DROP NOT NULL,
    ALTER COLUMN runtime_id DROP NOT NULL,
    ALTER COLUMN boot_id DROP NOT NULL,
    ALTER COLUMN guardian_pid DROP NOT NULL,
    ALTER COLUMN guardian_start DROP NOT NULL,
    ALTER COLUMN slot DROP NOT NULL,
    ADD COLUMN execution_path text NOT NULL DEFAULT 'guardian',
    ADD COLUMN provider_id text,
    ADD COLUMN model_id text,
    ADD CONSTRAINT narrative_call_execution_path CHECK (
        (execution_path='guardian'
         AND host_id IS NOT NULL AND runtime_id IS NOT NULL AND boot_id IS NOT NULL
         AND guardian_pid IS NOT NULL AND guardian_start IS NOT NULL
         AND slot IS NOT NULL AND slot=0
         AND provider_id IS NULL AND model_id IS NULL)
        OR
        (execution_path='provider'
         AND host_id IS NULL AND runtime_id IS NULL AND boot_id IS NULL
         AND guardian_pid IS NULL AND guardian_start IS NULL AND slot IS NULL
         AND provider_id IS NOT NULL AND model_id IS NOT NULL
         AND provider_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'
         AND model_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$')
    );

CREATE FUNCTION workspace_narrative_provider_call_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE g narrative_generations%ROWTYPE;
BEGIN
    IF NEW.execution_path <> 'provider' THEN RETURN NEW; END IF;
    SELECT * INTO g FROM narrative_generations WHERE site_id=NEW.site_id
        AND generation_id=NEW.generation_id;
    IF g.execution_bundle->>'version' IS DISTINCT FROM
           'workspace.narrative-provider-execution.v1'
       OR g.execution_bundle->>'provider_id' IS DISTINCT FROM NEW.provider_id
       OR g.execution_bundle->>'model_id' IS DISTINCT FROM NEW.model_id THEN
        RAISE EXCEPTION 'provider narrative call requires its frozen provider identity';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER narrative_provider_call_guard BEFORE INSERT ON narrative_calls
FOR EACH ROW EXECUTE FUNCTION workspace_narrative_provider_call_guard();
