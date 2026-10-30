CREATE FUNCTION workspace_keep_audit_envelope() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.event_id, NEW.site_id, NEW.kind, NEW.actor_key, NEW.payload, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.event_id, OLD.site_id, OLD.kind, OLD.actor_key, OLD.payload, OLD.created_at) THEN
        RAISE EXCEPTION 'audit event envelopes are immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER audit_outbox_immutable_envelope BEFORE UPDATE ON audit_outbox
FOR EACH ROW EXECUTE FUNCTION workspace_keep_audit_envelope();
