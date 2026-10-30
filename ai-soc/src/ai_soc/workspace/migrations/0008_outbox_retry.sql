ALTER TABLE audit_outbox
    ADD COLUMN last_attempt_at timestamptz,
    ADD COLUMN retry_at timestamptz NOT NULL DEFAULT '-infinity';

CREATE INDEX audit_outbox_retry_idx ON audit_outbox (site_id, retry_at, created_at, event_id)
WHERE sent_at IS NULL;
