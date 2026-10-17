use super::AuditCommand;
use crate::cli::{client, local_config, output};
use anyhow::Result;
use reqwest::Method;
use serde_json::Value;

use crate::constants::api as api_paths;

pub(crate) async fn execute(
  command: AuditCommand,
  server: &local_config::ResolvedServer,
  json_output: bool,
) -> Result<i32> {
  let api = client::human_client(server).await?;
  match command {
    AuditCommand::Verify => {
      let report = api
        .request(Method::GET, api_paths::audit::VERIFY, None)
        .await?;
      let ok = report.get("ok").and_then(Value::as_bool).unwrap_or(false);
      if json_output {
        output::print_json(&report)?;
      } else {
        print_report(&report);
      }
      Ok(if ok { 0 } else { 2 })
    }
  }
}

fn print_report(report: &Value) {
  let records = output::number(report, "records");
  let unsequenced = output::number(report, "unsequenced");
  let broken = report
    .get("broken")
    .filter(|value| !value.is_null())
    .filter(|value| value.is_object());
  let mut fields = match broken {
    Some(chain_break) => vec![
      (
        "Chain:",
        format!(
          "BROKEN at sequence {} ({})",
          chain_break
            .get("seq")
            .and_then(Value::as_i64)
            .unwrap_or_default(),
          output::string(chain_break, "id"),
        ),
      ),
      ("Reason:", output::string(chain_break, "reason")),
      ("Records verified:", records.to_string()),
    ],
    None => vec![
      ("Chain:", "intact".to_owned()),
      ("Records verified:", records.to_string()),
      (
        "Head sequence",
        report
          .get("headSeq")
          .and_then(Value::as_i64)
          .map_or_else(|| "none".to_owned(), |seq| seq.to_string()),
      ),
    ],
  };
  if unsequenced > 0 {
    fields.push(("Unsequenced records:", unsequenced.to_string()));
  }
  output::print_fields(&fields);
}
