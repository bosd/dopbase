DROP INDEX IF EXISTS audit_events_seq_idx;

ALTER TABLE audit_events DROP COLUMN seq;
ALTER TABLE audit_events DROP COLUMN prev_hash;
ALTER TABLE audit_events DROP COLUMN record_hash;
