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
  Ok(row.map(|row| {
    (
      row.get::<i64, _>("seq"),
      row.get::<String, _>("record_hash"),
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
    broken: None,
  };
  let mut after: Option<i64> = None;
  let mut previous: Option<(i64, String)> = None;
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
