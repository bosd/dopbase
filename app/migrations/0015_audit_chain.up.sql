ALTER TABLE audit_events ADD COLUMN seq INTEGER;
ALTER TABLE audit_events ADD COLUMN prev_hash TEXT;
ALTER TABLE audit_events ADD COLUMN record_hash TEXT;

CREATE UNIQUE INDEX audit_events_seq_idx ON audit_events(seq);
