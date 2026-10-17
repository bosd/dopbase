use app::services::audit_chain::{self, Retention};
use app::services::db::DbClient;
use serde_json::json;

async fn database() -> (tempfile::TempDir, DbClient) {
  let directory = tempfile::TempDir::new().unwrap();
  let database = directory.path().join("audit-chain.db");
  let db = DbClient::connect(&format!("sqlite://{}", database.display()))
    .await
    .unwrap();
  db.migrate().await.unwrap();
  (directory, db)
}

async fn record(
  db: &DbClient,
  id: &str,
  action: &str,
) {
  record_at(db, id, action, &chrono::Utc::now().to_rfc3339()).await;
}

async fn record_at(
  db: &DbClient,
  id: &str,
  action: &str,
  created_at: &str,
) {
  let mut transaction = db.pool().begin_with("BEGIN IMMEDIATE").await.unwrap();
  audit_chain::append(
    &mut transaction,
    id,
    "admin",
    Some("adm_1"),
    Some("admin@example.com"),
    action,
    Some("prj_1"),
    Some("env_1"),
    Some("secret"),
    Some("API_KEY"),
    &json!({ "action": action }).to_string(),
    created_at,
  )
  .await
  .unwrap();
  transaction.commit().await.unwrap();
}

async fn verify(db: &DbClient) -> audit_chain::ChainReport {
  audit_chain::verify(db.pool()).await.unwrap()
}

#[tokio::test]
async fn appends_form_a_verifiable_chain() {
  let (_directory, db) = database().await;
  for index in 0..5 {
    record(&db, &format!("aud_{index}"), "secret.updated").await;
  }

  let report = verify(&db).await;
  assert!(report.ok);
  assert_eq!(report.records, 5);
  assert_eq!(report.head_seq, Some(5));
  assert_eq!(report.unsequenced, 0);
  assert!(report.broken.is_none());

  let rows: Vec<(i64, Option<String>, Option<String>)> =
    sqlx::query_as("SELECT seq,prev_hash,record_hash FROM audit_events ORDER BY seq")
      .fetch_all(db.pool())
      .await
      .unwrap();
  // Only the first record names no predecessor.
  assert!(rows[0].1.is_none());
  for pair in rows.windows(2) {
    assert_eq!(pair[1].1.as_deref(), pair[0].2.as_deref());
  }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_appends_claim_distinct_sequence_numbers() {
  let (_directory, db) = database().await;
  let mut appends = Vec::new();
  for index in 0..24 {
    let pool = db.pool().clone();
    appends.push(tokio::spawn(async move {
      let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
      audit_chain::append(
        &mut transaction,
        &format!("aud_{index}"),
        "admin",
        None,
        None,
        "secret.updated",
        None,
        None,
        None,
        None,
        "{}",
        &chrono::Utc::now().to_rfc3339(),
      )
      .await
      .unwrap();
      transaction.commit().await.unwrap();
    }));
  }
  for append in appends {
    append.await.unwrap();
  }

  let report = verify(&db).await;
  assert!(report.ok, "chain broke: {:?}", report.broken);
  assert_eq!(report.records, 24);
  assert_eq!(report.head_seq, Some(24));
}

#[tokio::test]
async fn modifying_a_record_breaks_the_chain_at_that_record() {
  let (_directory, db) = database().await;
  for index in 0..4 {
    record(&db, &format!("aud_{index}"), "secret.updated").await;
  }

  sqlx::query("UPDATE audit_events SET action='login.succeeded' WHERE seq=3")
    .execute(db.pool())
    .await
    .unwrap();

  let report = verify(&db).await;
  assert!(!report.ok);
  assert_eq!(report.records, 2);
  let chain_break = report.broken.expect("the edited record must be reported");
  assert_eq!(chain_break.seq, 3);
  assert_eq!(chain_break.id, "aud_2");
  assert!(
    chain_break.reason.contains("hash"),
    "{}",
    chain_break.reason
  );
}

#[tokio::test]
async fn removing_a_record_breaks_the_chain_at_the_following_one() {
  let (_directory, db) = database().await;
  for index in 0..4 {
    record(&db, &format!("aud_{index}"), "secret.updated").await;
  }

  sqlx::query("DELETE FROM audit_events WHERE seq=2")
    .execute(db.pool())
    .await
    .unwrap();

  let report = verify(&db).await;
  assert!(!report.ok);
  assert_eq!(report.records, 1);
  let chain_break = report.broken.expect("the gap must be reported");
  assert_eq!(chain_break.seq, 3);
  assert!(chain_break.reason.contains("gap"), "{}", chain_break.reason);
}

#[tokio::test]
async fn records_without_a_chain_position_fail_verification() {
  let (_directory, db) = database().await;
  record(&db, "aud_0", "secret.updated").await;
  sqlx::query(
    "INSERT INTO audit_events(id,actor_type,action,metadata,created_at) VALUES(?,?,?,?,?)",
  )
  .bind("aud_legacy")
  .bind("admin")
  .bind("secret.updated")
  .bind("{}")
  .bind("2026-01-01T00:00:00Z")
  .execute(db.pool())
  .await
  .unwrap();

  let report = verify(&db).await;
  assert!(!report.ok);
  assert_eq!(report.unsequenced, 1);
  assert_eq!(report.records, 1);
  assert!(report.broken.is_none());
}

#[tokio::test]
async fn backfill_seals_older_records_and_keeps_chaining() {
  let (_directory, db) = database().await;
  for index in 0..3 {
    sqlx::query(
      "INSERT INTO audit_events(id,actor_type,action,metadata,created_at) VALUES(?,?,?,?,?)",
    )
    .bind(format!("aud_legacy_{index}"))
    .bind("admin")
    .bind("secret.updated")
    .bind("{}")
    .bind(format!("2026-01-0{}T00:00:00Z", index + 1))
    .execute(db.pool())
    .await
    .unwrap();
  }

  assert_eq!(audit_chain::backfill(db.pool()).await.unwrap(), 3);
  // Sealing is idempotent: nothing is left without a chain position.
  assert_eq!(audit_chain::backfill(db.pool()).await.unwrap(), 0);

  let report = verify(&db).await;
  assert!(report.ok, "chain broke: {:?}", report.broken);
  assert_eq!(report.records, 3);
  assert_eq!(report.head_seq, Some(3));

  // New appends continue after the sealed records.
  record(&db, "aud_after_upgrade", "secret.updated").await;
  let report = verify(&db).await;
  assert!(report.ok, "chain broke: {:?}", report.broken);
  assert_eq!(report.records, 4);
  assert_eq!(report.head_seq, Some(4));
}

#[tokio::test]
async fn legacy_records_are_sealed_during_the_migration_pass() {
  let (_directory, db) = database().await;
  // A database from before the chain: records without chain columns.
  sqlx::query(
    "INSERT INTO audit_events(id,actor_type,action,metadata,created_at) VALUES(?,?,?,?,?)",
  )
  .bind("aud_legacy")
  .bind("admin")
  .bind("secret.updated")
  .bind("{}")
  .bind("2026-01-01T00:00:00Z")
  .execute(db.pool())
  .await
  .unwrap();

  // Startup runs the migration pass, which seals what it finds.
  db.migrate().await.unwrap();

  let report = verify(&db).await;
  assert!(report.ok, "chain broke: {:?}", report.broken);
  assert_eq!(report.records, 1);
  assert_eq!(report.unsequenced, 0);
}

#[tokio::test]
async fn chain_survives_a_migration_rollback_and_reapply() {
  let (_directory, db) = database().await;
  for index in 0..3 {
    record(&db, &format!("aud_{index}"), "secret.updated").await;
  }

  // Reverting only the chain migration drops the chain columns but keeps
  // the records; the next migration pass seals them again.
  app::services::db::MIGRATOR
    .undo(db.pool(), 14)
    .await
    .unwrap();
  app::services::db::MIGRATOR.run(db.pool()).await.unwrap();
  db.migrate().await.unwrap();

  let report = verify(&db).await;
  assert!(report.ok, "chain broke: {:?}", report.broken);
  assert_eq!(report.records, 3);
}

#[tokio::test]
async fn retention_archives_expired_records_and_the_chain_still_verifies() {
  let (directory, db) = database().await;
  for index in 0..5 {
    record_at(
      &db,
      &format!("aud_old_{index}"),
      "secret.updated",
      "2000-01-01T00:00:00+00:00",
    )
    .await;
  }
  for index in 0..2 {
    record(&db, &format!("aud_new_{index}"), "secret.updated").await;
  }

  let archive = directory.path().join("archive");
  let retention = Retention::new(archive.clone(), 30);
  let mut transaction = db.pool().begin_with("BEGIN IMMEDIATE").await.unwrap();
  assert_eq!(retention.apply(&mut transaction).await.unwrap(), 5);
  transaction.commit().await.unwrap();

  // Expired records are gone from the log and archived as JSON lines that
  // keep every stored column, chain fields included.
  let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
    .fetch_one(db.pool())
    .await
    .unwrap();
  assert_eq!(remaining, 2);
  let archived = std::fs::read_to_string(archive.join("audit-000001-000005.jsonl")).unwrap();
  let lines = archived
    .lines()
    .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
    .collect::<Vec<_>>();
  assert_eq!(lines.len(), 5);
  assert_eq!(lines[0]["id"], "aud_old_0");
  assert_eq!(lines[4]["id"], "aud_old_4");
  assert_eq!(lines[4]["seq"], 5);
  assert!(lines[0]["recordHash"].is_string(), "{:?}", lines[0]);
  assert!(lines[0]["metadata"].is_object());

  // The surviving records verify from the anchor the pruning left behind.
  let report = verify(&db).await;
  assert!(report.ok, "chain broke: {:?}", report.broken);
  assert_eq!(report.records, 2);
  assert_eq!(report.pruned_seq, Some(5));
  assert_eq!(report.head_seq, Some(7));

  // A later append continues the chain after the anchor.
  record(&db, "aud_after", "secret.updated").await;
  let report = verify(&db).await;
  assert!(report.ok, "chain broke: {:?}", report.broken);
  assert_eq!(report.records, 3);
  assert_eq!(report.head_seq, Some(8));

  // Applying again finds nothing left to prune.
  let mut transaction = db.pool().begin_with("BEGIN IMMEDIATE").await.unwrap();
  assert_eq!(retention.apply(&mut transaction).await.unwrap(), 0);
  transaction.commit().await.unwrap();
}

#[tokio::test]
async fn retention_keeps_the_chain_continuous_when_it_removes_every_record() {
  let (directory, db) = database().await;
  for index in 0..3 {
    record_at(
      &db,
      &format!("aud_old_{index}"),
      "secret.updated",
      "2000-01-01T00:00:00+00:00",
    )
    .await;
  }

  let retention = Retention::new(directory.path().join("archive"), 30);
  let mut transaction = db.pool().begin_with("BEGIN IMMEDIATE").await.unwrap();
  assert_eq!(retention.apply(&mut transaction).await.unwrap(), 3);
  transaction.commit().await.unwrap();

  let report = verify(&db).await;
  assert!(report.ok, "chain broke: {:?}", report.broken);
  assert_eq!(report.records, 0);
  assert_eq!(report.pruned_seq, Some(3));

  // The next append continues after the anchor instead of restarting the
  // sequence at genesis, which would look like tampering.
  record(&db, "aud_new", "secret.updated").await;
  let report = verify(&db).await;
  assert!(report.ok, "chain broke: {:?}", report.broken);
  assert_eq!(report.records, 1);
  assert_eq!(report.head_seq, Some(4));
  let predecessor: Option<String> =
    sqlx::query_scalar("SELECT prev_hash FROM audit_events WHERE id='aud_new'")
      .fetch_one(db.pool())
      .await
      .unwrap();
  assert!(
    predecessor.is_some(),
    "the first surviving record stores its predecessor's hash"
  );
}

#[tokio::test]
async fn retention_keeps_an_expired_record_behind_a_retained_one() {
  let (directory, db) = database().await;
  // A clock that stepped backwards can timestamp a later append before an
  // earlier one. Retention keeps that record: removing it would leave a
  // hole in the chain no anchor can describe.
  record_at(
    &db,
    "aud_old",
    "secret.updated",
    "2000-01-01T00:00:00+00:00",
  )
  .await;
  record(&db, "aud_fresh", "secret.updated").await;
  record_at(
    &db,
    "aud_stale",
    "secret.updated",
    "2000-01-02T00:00:00+00:00",
  )
  .await;

  let retention = Retention::new(directory.path().join("archive"), 30);
  let mut transaction = db.pool().begin_with("BEGIN IMMEDIATE").await.unwrap();
  assert_eq!(retention.apply(&mut transaction).await.unwrap(), 1);
  transaction.commit().await.unwrap();

  let ids = sqlx::query_scalar::<_, String>("SELECT id FROM audit_events ORDER BY seq")
    .fetch_all(db.pool())
    .await
    .unwrap();
  assert_eq!(ids, ["aud_fresh", "aud_stale"]);
  let report = verify(&db).await;
  assert!(report.ok, "chain broke: {:?}", report.broken);
  assert_eq!(report.records, 2);
  assert_eq!(report.pruned_seq, Some(1));
}
