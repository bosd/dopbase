use app::services::audit_chain;
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
    &chrono::Utc::now().to_rfc3339(),
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
