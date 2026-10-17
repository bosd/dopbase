use super::{controller, model::*};
use crate::http::{ErrorBody, HttpResponseFormat};
use utoipa::OpenApi;
#[derive(OpenApi)]
#[openapi(paths(controller::list,controller::verify),components(schemas(AuditEvent,AuditPage,ChainVerifyReport,ChainVerifyBreak,ErrorBody,HttpResponseFormat<AuditPage>,HttpResponseFormat<ChainVerifyReport>)),tags((name="audit")))]
struct AuditApi;
pub fn build() -> utoipa::openapi::OpenApi {
  AuditApi::openapi()
}
