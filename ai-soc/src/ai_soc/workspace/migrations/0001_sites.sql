CREATE TABLE sites (
    site_id text PRIMARY KEY,
    label text NOT NULL,
    wazuh_version text,
    health text NOT NULL DEFAULT 'unknown'
        CHECK (health IN ('unknown', 'ok', 'lagging', 'auth_failed', 'unreachable')),
    health_detail text,
    updated_at timestamptz NOT NULL DEFAULT now()
);
