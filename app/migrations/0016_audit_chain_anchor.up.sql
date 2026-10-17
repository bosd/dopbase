-- Where the audit hash chain continues after retention removed records: the
-- position and hash of the newest pruned record. Verification starts here
-- when the oldest surviving record no longer starts at genesis.
CREATE TABLE audit_chain_anchor (
  id TEXT PRIMARY KEY CHECK (id = 'chain'),
  pruned_seq INTEGER NOT NULL,
  pruned_hash TEXT NOT NULL,
  pruned_at TEXT NOT NULL
);
