CREATE TABLE checkpoints (
    site_id text NOT NULL REFERENCES sites(site_id),
    index_pattern text NOT NULL,
    checkpoint_ts timestamptz NOT NULL,
    last_sort jsonb,
    overlap_seconds integer NOT NULL DEFAULT 900 CHECK (overlap_seconds >= 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_id, index_pattern)
);
