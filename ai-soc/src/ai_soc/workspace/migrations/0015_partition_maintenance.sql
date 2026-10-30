-- Partition DDL belongs to the migration/maintenance owner, never the data role.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'workspace_app') THEN
        REVOKE EXECUTE ON FUNCTION public.ensure_alert_partition(date) FROM workspace_app;
    END IF;
END;
$$;
