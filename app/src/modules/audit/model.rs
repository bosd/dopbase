use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
#[derive(Clone, Debug, Serialize, sqlx::FromRow, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
  pub id: String,
  pub actor_type: String,
  pub actor_id: Option<String>,
  pub actor_label: Option<String>,
  pub action: String,
  pub project_id: Option<String>,
  pub environment_id: Option<String>,
  pub resource_type: Option<String>,
  pub resource_id: Option<String>,
  #[sqlx(json)]
  pub metadata: Value,
  pub created_at: String,
}
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in=Query)]
#[serde(rename_all = "camelCase")]
pub struct AuditQuery {
  pub cursor: Option<String>,
  pub limit: Option<u32>,
  pub action: Option<String>,
  pub project_id: Option<String>,
  pub environment_id: Option<String>,
  pub actor: Option<String>,
}
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditPage {
  pub items: Vec<AuditEvent>,
  pub next_cursor: Option<String>,
}
/// The first inconsistency found while walking the audit hash chain.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChainVerifyBreak {
  pub seq: i64,
  pub id: String,
  pub reason: String,
}
/// The outcome of recomputing every audit record's hash in sequence order.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChainVerifyReport {
  /// True when every record matched its stored hashes and no record sits
  /// outside the chain.
  pub ok: bool,
  /// Records checked before the first break.
  pub records: u64,
  pub head_seq: Option<i64>,
  pub head_hash: Option<String>,
  /// Records with no chain position. Should stay at zero.
  pub unsequenced: u64,
  pub broken: Option<ChainVerifyBreak>,
}

impl From<crate::services::audit_chain::ChainReport> for ChainVerifyReport {
  fn from(report: crate::services::audit_chain::ChainReport) -> Self {
    Self {
      ok: report.ok,
      records: report.records,
      head_seq: report.head_seq,
      head_hash: report.head_hash,
      unsequenced: report.unsequenced,
      broken: report.broken.map(|chain_break| ChainVerifyBreak {
        seq: chain_break.seq,
        id: chain_break.id,
        reason: chain_break.reason,
      }),
    }
  }
}
