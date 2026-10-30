-- Bounded event/context sampling over an exact retained group revision.
CREATE INDEX group_members_revision_event_order_idx
    ON group_members (site_id, group_id, group_revision, event_ts, alert_key);
