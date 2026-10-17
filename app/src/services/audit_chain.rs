//! Tamper-evident hash chain over audit records.
//!
//! Every audit record stores three extra values: its position in the chain
//! (`seq`), the hash of the record before it (`prev_hash`), and the hash of
//! its own stored contents (`record_hash`). Recomputing the hashes in
//! sequence order therefore detects any record that was modified, inserted,
//! or removed after the fact.
//!
//! Two invariants keep the chain sound:
//!
//! - Appends read the chain head and insert in the same write transaction,
//!   so SQLite's single-writer lock makes them atomic.
//! - The digest is computed from the values as stored, never from a
//!   re-serialization, so verification hashes exactly what it reads back.
//! - Retention archives expired records to the data directory before
//!   deleting them, and leaves an anchor so the surviving records still
//!   verify as one unbroken chain.

use std::{fs, path::PathBuf, sync::OnceLock};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool, sqlite::SqliteConnection};

/// Domain separator, mixed into every digest so audit hashes cannot collide
/// with other SHA-256 uses of the same field values.
const DOMAIN: &str = "dopbase:audit-chain:v1";

/// Records verified per query while walking the chain.
const VERIFY_PAGE: i64 = 500;

/// The record that starts the chain stores no predecessor hash.
pub const GENESIS: &str = "";

/// A record as stored in `audit_events`, including its chain columns.
#[derive(sqlx::FromRow)]
struct Record {
  id: String,
  actor_type: String,
  actor_id: Option<String>,
  actor_label: Option<String>,
  action: String,
  project_id: Option<String>,
  environment_id: Option<String>,
  resource_type: Option<String>,
  resource_id: Option<String>,
  ip_address: Option<String>,
  user_agent: Option<String>,
  metadata: String,
  created_at: String,
  seq: Option<i64>,
  prev_hash: Option<String>,
  record_hash: Option<String>,
}

impl Record {
  /// The record as retention archives it: every stored column, chain fields
  /// included, in the same camelCase shape the audit list API returns.
  fn archived(&self) -> Value {
    json!({
      "id": self.id,
      "actorType": self.actor_type,
      "actorId": self.actor_id,
      "actorLabel": self.actor_label,
      "action": self.action,
      "projectId": self.project_id,
      "environmentId": self.environment_id,
      "resourceType": self.resource_type,
      "resourceId": self.resource_id,
      "ipAddress": self.ip_address,
      "userAgent": self.user_agent,
      "metadata": serde_json::from_str::<Value>(&self.metadata)
        .unwrap_or_else(|_| Value::String(self.metadata.clone())),
      "createdAt": self.created_at,
      "seq": self.seq,
      "prevHash": self.prev_hash,
      "recordHash": self.record_hash,
    })
  }

  /// Hash the record's stored values together with its chain position.
  ///
  /// `ip_address` and `user_agent` are stored as NULL today and hash as
  /// empty strings; because both write and verification read the stored
  /// values, a later release that fills them keeps verification correct.
  fn digest(
    &self,
    seq: i64,
    prev_hash: &str,
  ) -> String {
    digest(&[
      &seq.to_string(),
      &self.id,
      &self.actor_type,
      self.actor_id.as_deref().unwrap_or(GENESIS),
      self.actor_label.as_deref().unwrap_or(GENESIS),
      &self.action,
      self.project_id.as_deref().unwrap_or(GENESIS),
      self.environment_id.as_deref().unwrap_or(GENESIS),
      self.resource_type.as_deref().unwrap_or(GENESIS),
      self.resource_id.as_deref().unwrap_or(GENESIS),
      self.ip_address.as_deref().unwrap_or(GENESIS),
      self.user_agent.as_deref().unwrap_or(GENESIS),
      &self.metadata,
      &self.created_at,
      prev_hash,
    ])
  }
}

const COLUMNS: &str = "id,actor_type,actor_id,actor_label,action,project_id,environment_id,resource_type,resource_id,ip_address,user_agent,metadata,created_at,seq,prev_hash,record_hash";

fn digest(fields: &[&str]) -> String {
  let mut hasher = Sha256::new();
  hasher.update(DOMAIN.as_bytes());
  for field in fields {
    hasher.update(field.len().to_string().as_bytes());
    hasher.update(b":");
    hasher.update(field.as_bytes());
    hasher.update(b"\n");
  }
  hex::encode(hasher.finalize())
}

async fn head(executor: &mut SqliteConnection) -> Result<Option<(i64, String)>, sqlx::Error> {
  let row = sqlx::query(
    "SELECT seq,record_hash FROM audit_events WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1",
  )
  .fetch_optional(&mut *executor)
  .await?;
  if let Some(row) = row {
    return Ok(Some((
      row.get::<i64, _>("seq"),
      row.get::<String, _>("record_hash"),
    )));
  }
  // Retention can remove every record; the chain then continues from the
  // pruning anchor instead of restarting at the genesis position.
  let anchor =
    sqlx::query("SELECT pruned_seq,pruned_hash FROM audit_chain_anchor WHERE id='chain'")
      .fetch_optional(&mut *executor)
      .await?;
  Ok(anchor.map(|row| {
    (
      row.get::<i64, _>("pruned_seq"),
      row.get::<String, _>("pruned_hash"),
    )
  }))
}

/// Append one record to the chain.
///
/// The caller's connection must already hold SQLite's write lock: either an
/// immediate transaction, or a transaction whose first statement was a
/// write. That makes reading the head and inserting atomic, so concurrent
/// appends cannot claim the same sequence number.
#[allow(clippy::too_many_arguments)]
pub async fn append(
  connection: &mut SqliteConnection,
  id: &str,
  actor_type: &str,
  actor_id: Option<&str>,
  actor_label: Option<&str>,
  action: &str,
  project_id: Option<&str>,
  environment_id: Option<&str>,
  resource_type: Option<&str>,
  resource_id: Option<&str>,
  metadata: &str,
  created_at: &str,
) -> Result<(), sqlx::Error> {
  let (seq, prev_hash) = head(connection)
    .await?
    .map_or((1, GENESIS.to_owned()), |(seq, hash)| (seq + 1, hash));
  let record_hash = digest(&[
    &seq.to_string(),
    id,
    actor_type,
    actor_id.unwrap_or(GENESIS),
    actor_label.unwrap_or(GENESIS),
    action,
    project_id.unwrap_or(GENESIS),
    environment_id.unwrap_or(GENESIS),
    resource_type.unwrap_or(GENESIS),
    resource_id.unwrap_or(GENESIS),
    GENESIS, // ip_address, stored as NULL
    GENESIS, // user_agent, stored as NULL
    metadata,
    created_at,
    &prev_hash,
  ]);
  sqlx::query("INSERT INTO audit_events(id,actor_type,actor_id,actor_label,action,project_id,environment_id,resource_type,resource_id,metadata,created_at,seq,prev_hash,record_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
    .bind(id).bind(actor_type).bind(actor_id).bind(actor_label).bind(action)
    .bind(project_id).bind(environment_id).bind(resource_type).bind(resource_id)
    .bind(metadata).bind(created_at).bind(seq).bind((seq > 1).then_some(prev_hash.as_str())).bind(record_hash)
    .execute(&mut *connection).await.map(|_| ())
}

/// Give records written before the chain existed their chain columns.
///
/// Runs during every migration pass and is a no-op once no record is left
/// without a sequence number, so restored backups from older releases are
/// sealed on the next startup. Returns how many records were sequenced.
pub async fn backfill(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
  let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
  let sequenced = backfill_connection(&mut transaction).await?;
  transaction.commit().await?;
  Ok(sequenced)
}

/// Seal unsequenced records on a connection that already holds the write
/// lock, for callers that restore or rebuild tables inside their own
/// transaction.
pub async fn backfill_connection(connection: &mut SqliteConnection) -> Result<u64, sqlx::Error> {
  let (mut seq, mut prev_hash) = head(connection).await?.unwrap_or((0, GENESIS.to_owned()));
  let legacy = sqlx::query_as::<_, Record>(&format!(
    "SELECT {COLUMNS} FROM audit_events WHERE seq IS NULL ORDER BY created_at,id"
  ))
  .fetch_all(&mut *connection)
  .await?;
  let mut sequenced = 0;
  for record in legacy {
    seq += 1;
    let record_hash = record.digest(seq, &prev_hash);
    sqlx::query("UPDATE audit_events SET seq=?,prev_hash=?,record_hash=? WHERE id=?")
      .bind(seq)
      .bind((seq > 1).then_some(prev_hash.as_str()))
      .bind(&record_hash)
      .bind(&record.id)
      .execute(&mut *connection)
      .await?;
    prev_hash = record_hash;
    sequenced += 1;
  }
  Ok(sequenced)
}

/// The first inconsistency found while walking the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBreak {
  pub seq: i64,
  pub id: String,
  pub reason: String,
}

/// The outcome of walking the whole chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReport {
  pub ok: bool,
  /// Records checked before the first break.
  pub records: u64,
  pub head_seq: Option<i64>,
  pub head_hash: Option<String>,
  /// Records with no chain position. Should stay at zero.
  pub unsequenced: u64,
  /// Sequence number retention removed up to, when records were pruned.
  /// The surviving records continue the chain after it.
  pub pruned_seq: Option<i64>,
  pub broken: Option<ChainBreak>,
}

/// Walk the chain in sequence order and recompute every hash.
pub async fn verify(pool: &SqlitePool) -> Result<ChainReport, sqlx::Error> {
  let unsequenced = sqlx::query("SELECT COUNT(*) AS records FROM audit_events WHERE seq IS NULL")
    .fetch_one(pool)
    .await?
    .get::<i64, _>("records")
    .max(0) as u64;
  let mut report = ChainReport {
    ok: true,
    records: 0,
    head_seq: None,
    head_hash: None,
    unsequenced,
    pruned_seq: None,
    broken: None,
  };
  // Records retention removed leave an anchor behind: the chain starts
  // there instead of at genesis, so pruning does not look like tampering.
  let anchor =
    sqlx::query("SELECT pruned_seq,pruned_hash FROM audit_chain_anchor WHERE id='chain'")
      .fetch_optional(pool)
      .await?;
  report.pruned_seq = anchor.as_ref().map(|row| row.get::<i64, _>("pruned_seq"));
  let mut after: Option<i64> = None;
  let mut previous: Option<(i64, String)> = anchor.map(|row| {
    (
      row.get::<i64, _>("pruned_seq"),
      row.get::<String, _>("pruned_hash"),
    )
  });
  'walk: loop {
    let page = sqlx::query_as::<_, Record>(&format!(
      "SELECT {COLUMNS} FROM audit_events WHERE seq IS NOT NULL AND (?1 IS NULL OR seq > ?1) ORDER BY seq ASC LIMIT {VERIFY_PAGE}"
    ))
    .bind(after)
    .fetch_all(pool)
    .await?;
    if page.is_empty() {
      break;
    }
    for record in page {
      let seq = record.seq.unwrap_or_default();
      let expected_prev = previous
        .as_ref()
        .map_or(GENESIS.to_owned(), |(_, hash)| hash.clone());
      let reason = if previous
        .as_ref()
        .is_some_and(|(previous_seq, _)| seq != *previous_seq + 1)
      {
        Some("sequence gap")
      } else if record.prev_hash.as_deref().unwrap_or(GENESIS) != expected_prev {
        Some("previous record hash does not match")
      } else if record.record_hash.as_deref() != Some(record.digest(seq, &expected_prev).as_str()) {
        Some("record hash does not match its contents")
      } else {
        None
      };
      if let Some(reason) = reason {
        report.broken = Some(ChainBreak {
          seq,
          id: record.id.clone(),
          reason: reason.into(),
        });
        report.ok = false;
        break 'walk;
      }
      report.records += 1;
      report.head_seq = Some(seq);
      report.head_hash = record.record_hash.clone();
      previous = Some((seq, record.record_hash.clone().unwrap_or_default()));
      after = Some(seq);
    }
  }
  report.ok = report.ok && report.unsequenced == 0;
  Ok(report)
}

/// How long the audit log is kept.
///
/// Records older than the window are archived to the data directory as JSON
/// lines before they are deleted, so the evidence outlives the deletion and
/// an operator can ship the archive elsewhere. Only the oldest contiguous
/// run of records is removed: the deletion leaves an anchor with the newest
/// removed record's position and hash, which is where verification picks
/// the chain back up.
#[derive(Clone, Debug)]
pub struct Retention {
  archive_dir: PathBuf,
  keep_days: u64,
}

impl Retention {
  pub fn new(
    archive_dir: PathBuf,
    keep_days: u64,
  ) -> Self {
    Self {
      archive_dir,
      keep_days,
    }
  }

  /// Archive and delete every record older than the retention window.
  ///
  /// The caller's connection must hold SQLite's write lock, so the deletion
  /// and the anchor update are atomic with the transaction that triggered
  /// them. Returns how many records were removed.
  pub async fn apply(
    &self,
    connection: &mut SqliteConnection,
  ) -> anyhow::Result<u64> {
    self
      .apply_before(connection, &cutoff_for(self.keep_days))
      .await
  }

  async fn apply_before(
    &self,
    connection: &mut SqliteConnection,
    cutoff: &str,
  ) -> anyhow::Result<u64> {
    let expired = sqlx::query_as::<_, Record>(&format!(
      "SELECT {COLUMNS} FROM audit_events WHERE seq IS NOT NULL AND created_at < ? ORDER BY seq"
    ))
    .bind(cutoff)
    .fetch_all(&mut *connection)
    .await?;
    // Only the oldest contiguous run of records can be removed: an expired
    // record that sits behind a retained one would leave a hole in the
    // chain that no anchor can describe, so it stays until everything
    // before it has expired too.
    let minimum = sqlx::query("SELECT MIN(seq) AS seq FROM audit_events WHERE seq IS NOT NULL")
      .fetch_one(&mut *connection)
      .await?
      .get::<Option<i64>, _>("seq");
    let mut prefix: Vec<Record> = Vec::new();
    for record in expired {
      let expected = prefix
        .last()
        .map_or(minimum, |last| last.seq.map(|seq| seq + 1));
      if record.seq != expected {
        break;
      }
      prefix.push(record);
    }
    let Some(first) = prefix.first() else {
      return Ok(0);
    };
    let latest = prefix.last().unwrap_or(first);
    let position = |record: &Record| record.seq.unwrap_or_default();
    // The archive is named after the sequence range it holds, so a retry
    // after a failed transaction rewrites the same file instead of leaving
    // two copies of one range for an offline verifier to double-count.
    fs::create_dir_all(&self.archive_dir)?;
    let path = self.archive_dir.join(format!(
      "audit-{:06}-{:06}.jsonl",
      position(first),
      position(latest)
    ));
    let mut contents = Vec::new();
    for record in &prefix {
      serde_json::to_writer(&mut contents, &record.archived())?;
      contents.push(b'\n');
    }
    crate::utils::private_file::write(&path, &contents, true)?;
    sqlx::query("DELETE FROM audit_events WHERE seq IS NOT NULL AND seq <= ?")
      .bind(position(latest))
      .execute(&mut *connection)
      .await?;
    sqlx::query(
      "INSERT INTO audit_chain_anchor(id,pruned_seq,pruned_hash,pruned_at) VALUES('chain',?,?,?) \
       ON CONFLICT(id) DO UPDATE SET pruned_seq=excluded.pruned_seq,pruned_hash=excluded.pruned_hash,pruned_at=excluded.pruned_at",
    )
    .bind(position(latest))
    .bind(latest.record_hash.clone().unwrap_or_default())
    .bind(chrono::Utc::now().to_rfc3339())
    .execute(&mut *connection)
    .await?;
    Ok(prefix.len() as u64)
  }
}

fn cutoff_for(keep_days: u64) -> String {
  let days = i64::try_from(keep_days).unwrap_or(i64::MAX).min(365_000);
  (chrono::Utc::now() - chrono::Duration::days(days)).to_rfc3339()
}

/// The retention policy configured for this process, set once at startup.
static RETENTION: OnceLock<Retention> = OnceLock::new();

/// Configure the retention policy applied to the audit log.
pub fn configure_retention(retention: Retention) {
  let _ = RETENTION.set(retention);
}

/// Apply the configured retention in a transaction this function owns.
/// Runs once at startup; audit writes apply retention in the caller's
/// transaction instead. Returns how many records were removed, and zero
/// when retention is not configured.
pub async fn apply_retention(pool: &SqlitePool) -> anyhow::Result<u64> {
  let Some(retention) = RETENTION.get() else {
    return Ok(0);
  };
  let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
  let pruned = retention.apply(&mut transaction).await?;
  transaction.commit().await?;
  Ok(pruned)
}

/// Apply the configured retention on a connection that already holds the
/// write lock. Returns `None` when retention is not configured.
pub async fn prune_configured(connection: &mut SqliteConnection) -> anyhow::Result<Option<u64>> {
  let Some(retention) = RETENTION.get() else {
    return Ok(None);
  };
  retention.apply(connection).await.map(Some)
}
