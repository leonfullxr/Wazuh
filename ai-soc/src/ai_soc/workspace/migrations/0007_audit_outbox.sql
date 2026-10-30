CREATE TABLE audit_outbox (
    event_id uuid PRIMARY KEY,
    site_id text NOT NULL REFERENCES sites(site_id),
    kind text NOT NULL,
    actor_key text,
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    sent_at timestamptz,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error text
);

CREATE INDEX audit_outbox_pending_idx ON audit_outbox (site_id, created_at, event_id)
WHERE sent_at IS NULL;

ALTER TABLE audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_outbox_site_scope ON audit_outbox
    USING (site_id = COALESCE(current_setting('app.site_id', true), ''))
    WITH CHECK (site_id = COALESCE(current_setting('app.site_id', true), ''));
