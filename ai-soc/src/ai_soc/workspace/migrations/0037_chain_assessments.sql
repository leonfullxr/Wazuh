ALTER TABLE group_assessment_requests
    DROP CONSTRAINT group_assessment_requests_site_id_group_id_group_revision_c_key,
    DROP CONSTRAINT group_assessment_requests_selection_check,
    ADD COLUMN chain_id text,
    ADD COLUMN chain_revision text,
    ADD COLUMN chain_manifest_id uuid,
    ADD FOREIGN KEY (site_id, chain_id, chain_revision, chain_manifest_id)
        REFERENCES correlation_chain_revisions(site_id, chain_id, revision_digest, manifest_id),
    ADD CHECK (
        (chain_id IS NULL AND chain_revision IS NULL AND chain_manifest_id IS NULL
            AND selection IN ('score_gate', 'sample', 'new_revision'))
        OR (chain_id IS NOT NULL AND chain_revision IS NOT NULL AND chain_manifest_id IS NOT NULL
            AND selection = 'chain_candidate')
    );

CREATE UNIQUE INDEX assessment_group_pin ON group_assessment_requests
    (site_id, group_id, group_revision, computation_version, input_digest, catalog_digest)
    WHERE chain_id IS NULL;

CREATE UNIQUE INDEX assessment_chain_pin ON group_assessment_requests
    (site_id, chain_id, chain_revision, chain_manifest_id, catalog_digest)
    WHERE chain_id IS NOT NULL;
