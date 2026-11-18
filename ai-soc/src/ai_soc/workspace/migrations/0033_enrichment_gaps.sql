-- Retained rows predate explicit gap states and are immutable. Keep their state
-- unknown so readers can distinguish historical ambiguity from measured absence.
ALTER TABLE enrichments ADD COLUMN gap_state text;

ALTER TABLE enrichments ADD CONSTRAINT enrichments_gap_state_matches_availability CHECK (
    gap_state IS NULL
    OR (availability = 'available' AND gap_state IN ('present', 'empty'))
    OR (availability = 'unavailable' AND gap_state IN ('empty', 'not_configured', 'failed', 'stale'))
    OR (availability = 'stale' AND gap_state = 'stale')
);
