CREATE INDEX work_items_status_recent_idx
    ON work_items (site_id, status, updated_at DESC, group_id);
CREATE INDEX work_items_owner_recent_idx
    ON work_items (site_id, owner_key, updated_at DESC, group_id);
CREATE INDEX dispositions_window_idx
    ON dispositions (site_id, at DESC, group_id, label);
CREATE INDEX dispositions_rule_lookup_idx
    ON dispositions (site_id, group_id, at DESC);
CREATE INDEX group_members_entity_lookup_idx
    ON group_members (site_id, group_id, group_revision, alert_key);
CREATE INDEX alerts_metrics_window_idx
    ON alerts (site_id, event_ts DESC, alert_key) WHERE normalized_at IS NOT NULL;
CREATE INDEX pipeline_runs_site_finished_idx
    ON pipeline_runs (site_id, finished_at DESC) WHERE finished_at IS NOT NULL;
CREATE INDEX jobs_site_state_age_idx
    ON jobs (site_id, state, created_at) WHERE state IN ('queued', 'running', 'dead');
