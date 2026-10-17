use super::{error::AuditError, model::*, service};
use crate::{
  http::{HttpResponse, HttpResponseFormat},
  models::AuthIdentity,
  state::AppState,
};
use axum::extract::{Query, State};

/// List audit events
///
/// Return a cursor-paginated page of audit events, newest first. Filter by
/// `action`, `projectId`, `environmentId`, or `actor`. `limit` is clamped
/// to 1-200. The `nextCursor` value is opaque. Pass it back unchanged to
/// fetch the next page.
#[utoipa::path(
  get,
  path = crate::constants::api::audit::COLLECTION,
  tag = "audit",
  security(("bearerAuth" = []), ("cookieAuth" = [])),
  params(AuditQuery),
  responses(
    (status = 200, description = "Audit events fetched", body = inline(HttpResponseFormat<AuditPage>)),
    (status = 400, description = "The pagination cursor is invalid", body = crate::http::ErrorBody),
    (status = 401, description = "Authentication is required", body = crate::http::ErrorBody),
    (status = 403, description = "Only administrators may read audit events", body = crate::http::ErrorBody),
  ),
)]
pub async fn list(
  State(state): State<AppState>,
  identity: AuthIdentity,
  Query(query): Query<AuditQuery>,
) -> Result<HttpResponse<AuditPage>, AuditError> {
  Ok(HttpResponse::ok(
    service::list(&state, &identity, query).await?,
    "AUDIT_EVENTS_FETCHED",
  ))
}

/// Verify the audit hash chain
///
/// Walks every audit record in sequence order, recomputes each record's
/// hash from its stored contents, and reports the first inconsistency. The
/// walk stops at the first break, so `records` counts the records checked
/// before it. `unsequenced` counts records written before the chain
/// existed and not yet sealed; it should stay at zero.
#[utoipa::path(
  get,
  path = crate::constants::api::audit::VERIFY,
  tag = "audit",
  security(("bearerAuth" = []), ("cookieAuth" = [])),
  responses(
    (status = 200, description = "Audit chain verified", body = inline(HttpResponseFormat<ChainVerifyReport>)),
    (status = 401, description = "Authentication is required", body = crate::http::ErrorBody),
    (status = 403, description = "Only administrators may verify the audit chain", body = crate::http::ErrorBody),
  ),
)]
pub async fn verify(
  State(state): State<AppState>,
  identity: AuthIdentity,
) -> Result<HttpResponse<ChainVerifyReport>, AuditError> {
  Ok(HttpResponse::ok(
    service::verify(&state, &identity).await?,
    "AUDIT_CHAIN_VERIFIED",
  ))
}
