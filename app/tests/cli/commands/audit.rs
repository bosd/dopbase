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
