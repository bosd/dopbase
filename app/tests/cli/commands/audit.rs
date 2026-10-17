use super::support::{Fixture, output};
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread")]
async fn audit_verify_reports_an_intact_chain_and_flags_tampering() {
  let fixture = Fixture::new().await;
  fixture.environment().await;

  let human = fixture.run(&["audit", "verify"]).await;
  assert!(
    human.status.success(),
    "{}",
    String::from_utf8_lossy(&human.stderr)
  );
  let stdout = String::from_utf8_lossy(&human.stdout);
  assert!(stdout.contains("Chain"), "{stdout}");
  assert!(stdout.contains("intact"), "{stdout}");
  assert!(stdout.contains("Records verified"), "{stdout}");

  let report = fixture.json(&["audit", "verify"]).await;
  assert_eq!(report["ok"], json!(true));
  assert_eq!(report["unsequenced"], json!(0));
  assert_eq!(report["broken"], Value::Null);
  assert!(report["records"].as_u64().unwrap() >= 3);
  assert_eq!(report["headSeq"].as_u64(), report["records"].as_u64());

  // Editing a record in place makes verification fail with exit code 2, so
  // monitoring can alert on it.
  sqlx::query("UPDATE audit_events SET action='tampered.for.test' WHERE seq=2")
    .execute(fixture.state.db.pool())
    .await
    .unwrap();

  let broken = fixture.run(&["audit", "verify"]).await;
  assert_eq!(broken.status.code(), Some(2));
  let stdout = String::from_utf8_lossy(&broken.stdout);
  assert!(stdout.contains("BROKEN at sequence 2"), "{stdout}");
  assert!(stdout.contains("Reason:"), "{stdout}");
  assert!(stdout.contains("Records verified"), "{stdout}");

  let mut command = fixture.command();
  command.args(["--json", "audit", "verify"]);
  let output = output(command, None).await;
  assert_eq!(output.status.code(), Some(2));
  let report: Value = serde_json::from_slice(&output.stdout).unwrap();
  assert_eq!(report["ok"], json!(false));
  assert_eq!(report["records"], json!(1));
  assert_eq!(report["broken"]["seq"], json!(2));
  assert!(
    report["broken"]["reason"]
      .as_str()
      .unwrap()
      .contains("hash"),
    "unexpected reason: {}",
    report["broken"]["reason"]
  );
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_help_points_at_the_hash_chain() {
  let fixture = Fixture::new().await;
  let help = fixture.run(&["audit", "--help"]).await;
  assert!(help.status.success());
  let stdout = String::from_utf8_lossy(&help.stdout);
  assert!(stdout.contains("dopbase audit verify"), "{stdout}");
  assert!(stdout.contains("hash chain"), "{stdout}");
}

fn json_lines(stdout: &[u8]) -> Vec<Value> {
  String::from_utf8_lossy(stdout)
    .lines()
    .filter(|line| !line.trim().is_empty())
    .map(|line| {
      serde_json::from_str(line).unwrap_or_else(|error| panic!("invalid JSON line {line}: {error}"))
    })
    .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_export_streams_json_lines_with_chain_fields_and_filters() {
  use super::support::{EMAIL, failure};
  let fixture = Fixture::new().await;
  fixture.environment().await;

  // Every line is one record as the list API returns it, including the
  // chain fields, so an export can be anchored and checked outside Dopbase.
  let human = fixture.run(&["audit", "export"]).await;
  assert!(
    human.status.success(),
    "{}",
    String::from_utf8_lossy(&human.stderr)
  );
  let records = json_lines(&human.stdout);
  assert!(records.len() >= 3, "exported {} records", records.len());
  let mut previous_seq = u64::MAX;
  for record in &records {
    let seq = record["seq"]
      .as_u64()
      .unwrap_or_else(|| panic!("missing seq: {record}"));
    assert!(record["action"].is_string(), "{record}");
    assert!(record["recordHash"].is_string(), "{record}");
    // Only the genesis record has no predecessor; every later record
    // carries the hash of the record before it.
    if seq == 1 {
      assert!(record["prevHash"].is_null(), "{record}");
    } else {
      assert!(record["prevHash"].is_string(), "{record}");
    }
    assert!(seq < previous_seq, "records are exported newest first");
    previous_seq = seq;
  }

  // Action, project and environment filters narrow the stream.
  let filtered = fixture
    .run(&["audit", "export", "--action", "environment.created"])
    .await;
  assert!(filtered.status.success());
  let records = json_lines(&filtered.stdout);
  assert!(!records.is_empty());
  assert!(
    records
      .iter()
      .all(|record| record["action"] == "environment.created"),
    "{records:?}"
  );

  let by_project = fixture
    .run(&["audit", "export", "--project", "fixture"])
    .await;
  assert!(by_project.status.success());
  let records = json_lines(&by_project.stdout);
  assert!(
    records
      .iter()
      .any(|record| record["action"] == "project.created")
  );
  assert!(records.iter().all(|record| record["projectId"].is_string()));

  let by_environment = fixture
    .run(&["audit", "export", "--environment", "fixture/local"])
    .await;
  assert!(by_environment.status.success());
  let records = json_lines(&by_environment.stdout);
  assert!(!records.is_empty());
  assert!(
    records
      .iter()
      .all(|record| record["environmentId"].is_string())
  );

  let by_actor = fixture.run(&["audit", "export", "--actor", EMAIL]).await;
  assert!(by_actor.status.success());
  assert!(!json_lines(&by_actor.stdout).is_empty());

  // Unknown references and a zero limit fail instead of exporting nothing.
  failure(
    &fixture
      .run(&["audit", "export", "--project", "absent"])
      .await,
    "Project not found",
  );
  failure(
    &fixture.run(&["audit", "export", "--limit", "0"]).await,
    "greater than zero",
  );

  // --limit caps the stream, and pages are followed beyond the first one.
  let limited = fixture.run(&["audit", "export", "--limit", "1"]).await;
  assert!(limited.status.success());
  assert_eq!(json_lines(&limited.stdout).len(), 1);

  // More records than one API page are followed through the pagination
  // cursor, so an export never silently stops at 200 records.
  let mut transaction = fixture
    .state
    .db
    .pool()
    .begin_with("BEGIN IMMEDIATE")
    .await
    .unwrap();
  for index in 0..205 {
    app::services::audit_chain::append(
      &mut transaction,
      &format!("aud_page_{index:04}"),
      "admin",
      Some("adm_1"),
      Some(EMAIL),
      "page.seeded",
      None,
      None,
      None,
      None,
      "{}",
      &chrono::Utc::now().to_rfc3339(),
    )
    .await
    .unwrap();
  }
  transaction.commit().await.unwrap();
  let paged = fixture
    .run(&["audit", "export", "--action", "page.seeded"])
    .await;
  assert!(
    paged.status.success(),
    "{}",
    String::from_utf8_lossy(&paged.stderr)
  );
  assert_eq!(json_lines(&paged.stdout).len(), 205);
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_export_writes_a_private_file_and_needs_force_to_replace_it() {
  use super::support::failure;
  let fixture = Fixture::new().await;
  fixture.environment().await;
  let path = fixture.directory.path().join("audit.jsonl");

  let created = fixture
    .run(&["audit", "export", "--output", path.to_str().unwrap()])
    .await;
  assert!(
    created.status.success(),
    "{}",
    String::from_utf8_lossy(&created.stderr)
  );
  let contents = std::fs::read_to_string(&path).unwrap();
  let file_records = contents
    .lines()
    .filter(|line| !line.trim().is_empty())
    .map(|line| serde_json::from_str::<Value>(line).unwrap())
    .collect::<Vec<_>>();
  assert!(!file_records.is_empty());
  assert_eq!(
    file_records.len(),
    json_lines(&fixture.run(&["audit", "export"]).await.stdout).len()
  );
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
      std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
      0o600
    );
  }

  // An existing file is never replaced silently.
  failure(
    &fixture
      .run(&["audit", "export", "--output", path.to_str().unwrap()])
      .await,
    "already exists",
  );
  assert_eq!(std::fs::read_to_string(&path).unwrap(), contents);

  // --force replaces it, and --json reports the count as an object.
  let replaced = fixture
    .json(&[
      "audit",
      "export",
      "--output",
      path.to_str().unwrap(),
      "--force",
    ])
    .await;
  assert_eq!(
    replaced["exported"].as_u64().unwrap(),
    file_records.len() as u64
  );
  assert_eq!(replaced["path"], path.to_str().unwrap());
  assert!(!std::fs::read_to_string(&path).unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_retention_archives_expired_records_and_verification_continues() {
  use app::services::audit_chain::{self, Retention};
  let fixture = Fixture::new().await;
  fixture.environment().await;

  // The log went quiet past the retention window: every record written so
  // far is older than it.
  let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
    .fetch_one(fixture.state.db.pool())
    .await
    .unwrap();
  sqlx::query("UPDATE audit_events SET created_at='2000-01-01T00:00:00+00:00'")
    .execute(fixture.state.db.pool())
    .await
    .unwrap();

  // The next audit write applies the configured retention.
  audit_chain::configure_retention(Retention::new(
    fixture.directory.path().join("audit-archive"),
    30,
  ));
  fixture.run(&["project", "create", "second"]).await;

  // The expired records are gone from the log and archived as JSON lines
  // that keep every stored column, chain fields included.
  let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
    .fetch_one(fixture.state.db.pool())
    .await
    .unwrap();
  assert_eq!(
    remaining, 1,
    "only the record that resumed the log survives"
  );
  let archive_dir = fixture.directory.path().join("audit-archive");
  let mut archives = std::fs::read_dir(&archive_dir)
    .unwrap()
    .map(|entry| entry.unwrap().path())
    .collect::<Vec<_>>();
  archives.sort();
  assert_eq!(archives.len(), 1, "{archives:?}");
  let archived = std::fs::read_to_string(&archives[0]).unwrap();
  let archived_records = archived
    .lines()
    .map(|line| serde_json::from_str::<Value>(line).unwrap())
    .collect::<Vec<_>>();
  assert_eq!(archived_records.len() as i64, before);
  assert_eq!(archived_records[0]["seq"], json!(1));
  assert!(archived_records[0]["action"].is_string());
  assert!(archived_records[before as usize - 1]["recordHash"].is_string());

  // Verification continues from the anchor instead of reporting a gap.
  let human = fixture.run(&["audit", "verify"]).await;
  assert!(
    human.status.success(),
    "{}",
    String::from_utf8_lossy(&human.stderr)
  );
  let stdout = String::from_utf8_lossy(&human.stdout);
  assert!(stdout.contains("intact"), "{stdout}");
  assert!(stdout.contains("Pruned through"), "{stdout}");
  let report = fixture.json(&["audit", "verify"]).await;
  assert_eq!(report["ok"], json!(true));
  assert_eq!(report["records"], json!(1));
  assert_eq!(report["prunedSeq"], json!(before));
}
