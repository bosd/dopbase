use std::{io::Write, path::Path};

use super::AuditCommand;
use crate::cli::commands::environment;
use crate::cli::{
  client::{self, ApiClient},
  local_config, output,
};
use anyhow::{Context, Result, bail};
use reqwest::Method;
use serde_json::{Value, json};

use crate::constants::api as api_paths;

/// Page size used while streaming; the audit API caps `limit` at 200.
const PAGE_SIZE: u64 = 200;

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
    AuditCommand::Export {
      output,
      force,
      action,
      project,
      environment,
      actor,
      limit,
    } => {
      let exported = export(
        &api,
        ExportFilters {
          action,
          project,
          environment,
          actor,
        },
        output.as_deref(),
        force,
        limit,
      )
      .await?;
      if let Some(path) = output {
        report_export(exported, &path, json_output)?;
      }
      Ok(0)
    }
  }
}

struct ExportFilters {
  action: Option<String>,
  project: Option<String>,
  environment: Option<String>,
  actor: Option<String>,
}

/// Streams matching audit records as JSON lines, one object per line, in
/// the order returned by the audit list API (newest first).
async fn export(
  api: &ApiClient,
  filters: ExportFilters,
  output: Option<&Path>,
  force: bool,
  limit: Option<u64>,
) -> Result<u64> {
  if let Some(0) = limit {
    bail!("audit export requires --limit greater than zero");
  }
  let project = match &filters.project {
    Some(reference) => Some(resolve_project(api, reference).await?),
    None => None,
  };
  let environment = match &filters.environment {
    Some(reference) => {
      let resolved = environment::resolve_environment(api, reference).await?;
      Some(environment::env_id(&resolved)?.to_owned())
    }
    None => None,
  };
  let page_size = PAGE_SIZE.to_string();
  let mut file = Vec::new();
  let mut cursor: Option<String> = None;
  let mut exported = 0u64;
  'stream: loop {
    let mut params: Vec<(&str, &str)> = vec![("limit", page_size.as_str())];
    if let Some(value) = filters.action.as_deref() {
      params.push(("action", value));
    }
    if let Some(value) = project.as_deref() {
      params.push(("projectId", value));
    }
    if let Some(value) = environment.as_deref() {
      params.push(("environmentId", value));
    }
    if let Some(value) = filters.actor.as_deref() {
      params.push(("actor", value));
    }
    if let Some(value) = cursor.as_deref() {
      params.push(("cursor", value));
    }
    let path = api_paths::audit::collection(&params);
    let page = api.request(Method::GET, &path, None).await?;
    let Some(items) = page.get("items").and_then(Value::as_array) else {
      break;
    };
    for item in items {
      let mut line = serde_json::to_vec(item)?;
      line.push(b'\n');
      match output {
        Some(_) => file.extend_from_slice(&line),
        None => std::io::stdout()
          .write_all(&line)
          .context("failed to write audit export")?,
      }
      exported += 1;
      if limit.is_some_and(|limit| exported >= limit) {
        break 'stream;
      }
    }
    match page.get("nextCursor").and_then(Value::as_str) {
      Some(next) if !next.is_empty() => cursor = Some(next.to_owned()),
      _ => break,
    }
  }
  if let Some(path) = output {
    output::write_private(path, &file, force)?;
  }
  Ok(exported)
}

fn report_export(
  exported: u64,
  path: &Path,
  json_output: bool,
) -> Result<()> {
  if json_output {
    output::print_json(&json!({"exported": exported, "path": path.display().to_string()}))
  } else {
    output::print_success(&format!(
      "Exported {exported} audit record(s) to {}.",
      path.display()
    ));
    Ok(())
  }
}

/// Resolves a project name or ID to its ID. The API only resolves
/// environments by reference, so projects are matched against the list.
async fn resolve_project(
  api: &ApiClient,
  reference: &str,
) -> Result<String> {
  let projects = api
    .request(Method::GET, api_paths::projects::COLLECTION, None)
    .await?;
  output::array(&projects)
    .iter()
    .find(|project| {
      let id = project
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default();
      let name = project
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
      id == reference || name.eq_ignore_ascii_case(reference)
    })
    .and_then(|project| project.get("id").and_then(Value::as_str))
    .map(str::to_owned)
    .ok_or_else(|| anyhow::anyhow!("Project not found: {reference}"))
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
  if let Some(pruned) = report.get("prunedSeq").and_then(Value::as_i64) {
    fields.push(("Pruned through:", format!("sequence {pruned}")));
  }
  output::print_fields(&fields);
}
