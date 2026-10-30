CREATE INDEX alerts_event_ts_brin_idx ON alerts USING brin (event_ts);
CREATE INDEX alerts_site_rule_event_idx ON alerts (site_id, (normalized ->> 'rule_id'), event_ts);
CREATE INDEX alerts_site_agent_event_idx ON alerts (site_id, (normalized ->> 'agent_id'), event_ts);
CREATE INDEX alerts_mitre_techniques_gin_idx ON alerts USING gin ((normalized -> 'mitre_techniques'));
CREATE INDEX alert_registry_site_event_idx ON alert_registry (site_id, original_event_ts);

CREATE FUNCTION ensure_alert_partition(partition_day date) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    partition_name text;
    lower_bound text;
    upper_bound text;
BEGIN
    partition_name := 'alerts_' || to_char(partition_day, 'YYYYMMDD');
    lower_bound := to_char(partition_day::timestamp, 'YYYY-MM-DD HH24:MI:SS') || '+00';
    upper_bound := to_char((partition_day + 1)::timestamp, 'YYYY-MM-DD HH24:MI:SS') || '+00';

    BEGIN
        EXECUTE format(
            'CREATE TABLE public.%I PARTITION OF public.alerts FOR VALUES FROM (%L) TO (%L)',
            partition_name, lower_bound, upper_bound
        );
    EXCEPTION WHEN duplicate_table THEN
        IF NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_inherits AS inheritance
            JOIN pg_catalog.pg_class AS child ON child.oid = inheritance.inhrelid
            JOIN pg_catalog.pg_namespace AS child_schema ON child_schema.oid = child.relnamespace
            JOIN pg_catalog.pg_class AS parent ON parent.oid = inheritance.inhparent
            JOIN pg_catalog.pg_namespace AS parent_schema ON parent_schema.oid = parent.relnamespace
            WHERE child_schema.nspname = 'public'
              AND child.relname = partition_name
              AND parent_schema.nspname = 'public'
              AND parent.relname = 'alerts'
        ) THEN
            RAISE EXCEPTION 'alert partition name is occupied by an unrelated relation';
        END IF;
    END;

    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', partition_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', partition_name);
    EXECUTE format('DROP POLICY IF EXISTS alerts_partition_site_scope ON public.%I', partition_name);
    EXECUTE format(
        'CREATE POLICY alerts_partition_site_scope ON public.%I '
        'USING (site_id = COALESCE(current_setting(''app.site_id'', true), '''')) '
        'WITH CHECK (site_id = COALESCE(current_setting(''app.site_id'', true), ''''))',
        partition_name
    );
END;
$$;

REVOKE ALL ON FUNCTION ensure_alert_partition(date) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'workspace_app') THEN
        GRANT EXECUTE ON FUNCTION ensure_alert_partition(date) TO workspace_app;
    END IF;
END;
$$;
