CREATE TABLE knowledge_documents (
    site_id text NOT NULL REFERENCES sites(site_id),
    document_id text NOT NULL CHECK (document_id ~ '^[a-z0-9][a-z0-9_.-]{0,127}$'),
    content_version text NOT NULL CHECK (content_version ~ '^[a-f0-9]{40}$'),
    title text NOT NULL CHECK (title <> '' AND octet_length(title) <= 1024),
    kind text NOT NULL CHECK (kind IN ('runbook', 'reference', 'rule_note', 'policy')),
    language text NOT NULL CHECK (language IN ('en', 'es')),
    source_path text NOT NULL CHECK (source_path LIKE 'knowledge/%.md'),
    source_sha256 text NOT NULL CHECK (source_sha256 ~ '^[a-f0-9]{64}$'),
    reviewer text NOT NULL CHECK (reviewer <> '' AND octet_length(reviewer) <= 1024),
    review_date date NOT NULL,
    expiry date,
    pack_digest text NOT NULL CHECK (pack_digest ~ '^[a-f0-9]{64}$'),
    loaded_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, document_id, content_version),
    CHECK (expiry IS NULL OR expiry > review_date)
);
ALTER TABLE knowledge_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge_documents FORCE ROW LEVEL SECURITY;
CREATE POLICY knowledge_document_site_scope ON knowledge_documents
    USING (site_id = COALESCE(current_setting('app.site_id', true), ''))
    WITH CHECK (site_id = COALESCE(current_setting('app.site_id', true), ''));
CREATE INDEX knowledge_documents_cutoff_idx
    ON knowledge_documents (site_id, loaded_at DESC, document_id, content_version);

CREATE TABLE knowledge_chunks (
    site_id text NOT NULL,
    document_id text NOT NULL,
    content_version text NOT NULL,
    chunk_id text NOT NULL CHECK (chunk_id <> '' AND octet_length(chunk_id) <= 512),
    section text NOT NULL CHECK (section <> '' AND octet_length(section) <= 1024),
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 0 AND 127),
    body text NOT NULL CHECK (body <> '' AND octet_length(body) <= 4096),
    body_sha256 text NOT NULL CHECK (body_sha256 ~ '^[a-f0-9]{64}$'),
    rule_ids text[] NOT NULL DEFAULT '{}',
    rule_groups text[] NOT NULL DEFAULT '{}',
    attack_techniques text[] NOT NULL DEFAULT '{}',
    cves text[] NOT NULL DEFAULT '{}',
    search_en tsvector GENERATED ALWAYS AS (
        CASE WHEN language = 'en' THEN to_tsvector('english', body) ELSE ''::tsvector END
    ) STORED,
    search_es tsvector GENERATED ALWAYS AS (
        CASE WHEN language = 'es' THEN to_tsvector('spanish', body) ELSE ''::tsvector END
    ) STORED,
    language text NOT NULL CHECK (language IN ('en', 'es')),
    PRIMARY KEY (site_id, chunk_id, content_version),
    UNIQUE (site_id, document_id, content_version, ordinal),
    FOREIGN KEY (site_id, document_id, content_version)
        REFERENCES knowledge_documents(site_id, document_id, content_version) ON DELETE CASCADE,
    CHECK (cardinality(rule_ids) <= 32),
    CHECK (cardinality(rule_groups) <= 32),
    CHECK (cardinality(attack_techniques) <= 32),
    CHECK (cardinality(cves) <= 32)
);
ALTER TABLE knowledge_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge_chunks FORCE ROW LEVEL SECURITY;
CREATE POLICY knowledge_chunk_site_scope ON knowledge_chunks
    USING (site_id = COALESCE(current_setting('app.site_id', true), ''))
    WITH CHECK (site_id = COALESCE(current_setting('app.site_id', true), ''));
CREATE INDEX knowledge_chunks_exact_idx ON knowledge_chunks
    USING gin (rule_ids, rule_groups, attack_techniques, cves);
CREATE INDEX knowledge_chunks_en_idx ON knowledge_chunks USING gin (search_en);
CREATE INDEX knowledge_chunks_es_idx ON knowledge_chunks USING gin (search_es);
