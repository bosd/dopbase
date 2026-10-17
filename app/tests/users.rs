use app::{config::ServerConfig, server};
use axum::{
  Router,
  body::{Body, to_bytes},
  http::{Request, header},
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

async fn fixture() -> (TempDir, app::state::AppState, Router) {
  let dir = TempDir::new().unwrap();
  let config = ServerConfig {
    data_dir: dir.path().to_path_buf(),
    database_url: format!("sqlite://{}", dir.path().join("dopbase.db").display()),
    master_key: app::config::MasterKeyConfig {
      provider: "file".into(),
      path: dir.path().join("master.key"),
    },
    ..ServerConfig::default()
  };
  let state = server::build_setup_state(config).await.unwrap();
  let router = server::router(state.clone());
  (dir, state, router)
}

async fn call(
  router: &Router,
  method: &str,
  path: &str,
  cookie: Option<&str>,
  csrf: Option<&str>,
  body: Option<Value>,
) -> (u16, Value, axum::http::HeaderMap) {
  let mut request = Request::builder().method(method).uri(path);
  if let Some(cookie) = cookie {
    if cookie.starts_with("Bearer ") {
      request = request.header(header::AUTHORIZATION, cookie);
    } else {
      request = request.header(header::COOKIE, cookie);
    }
  }
  if let Some(csrf) = csrf {
    request = request.header("x-dopbase-csrf", csrf);
  }
  if body.is_some() {
    request = request.header(header::CONTENT_TYPE, "application/json");
  }
  let response = router
    .clone()
    .oneshot(
      request
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap(),
    )
    .await
    .unwrap();
  let status = response.status().as_u16();
  let headers = response.headers().clone();
  let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
  (
    status,
    serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    headers,
  )
}

#[tokio::test]
async fn root_can_manage_admins_but_cannot_delete_root_and_can_reset() {
  let (_dir, state, router) = fixture().await;
  let setup = state.setup.read().await.token.clone().unwrap();
  let (status, bootstrap, headers) = call(
    &router,
    "POST",
    "/api/v1/bootstrap/admin",
    None,
    None,
    Some(json!({"setupToken": setup, "email":"root@example.com", "password":"correct-horse-123"})),
  )
  .await;
  assert_eq!(status, 201);
  let cookie = headers
    .get(header::SET_COOKIE)
    .unwrap()
    .to_str()
    .unwrap()
    .split(';')
    .next()
    .unwrap()
    .to_string();
  let csrf = bootstrap["data"]["csrfToken"].as_str().unwrap().to_string();
  let (status, created, _) = call(
    &router,
    "POST",
    "/api/v1/users",
    Some(&cookie),
    Some(&csrf),
    Some(json!({"email":"admin@example.com","password":"correct-horse-456"})),
  )
  .await;
  assert_eq!(status, 201);
  assert_eq!(created["data"]["role"], "admin");
  let (status, _, admin_headers) = call(
    &router,
    "POST",
    "/api/v1/auth/login",
    None,
    None,
    Some(
      json!({"email":"admin@example.com","password":"correct-horse-456","sessionKind":"browser"}),
    ),
  )
  .await;
  assert_eq!(status, 200);
  let admin_cookie = admin_headers
    .get(header::SET_COOKIE)
    .unwrap()
    .to_str()
    .unwrap()
    .split(';')
    .next()
    .unwrap()
    .to_string();
  let (status, body, _) = call(
    &router,
    "GET",
    "/api/v1/users",
    Some(&admin_cookie),
    None,
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(body["data"].as_array().unwrap().len(), 2);
  let (status, listed, _) = call(&router, "GET", "/api/v1/users", Some(&cookie), None, None).await;
  assert_eq!(status, 200);
  assert_eq!(listed["data"].as_array().unwrap().len(), 2);
  let root_id = listed["data"][0]["id"].as_str().unwrap();
  let (status, body, _) = call(
    &router,
    "DELETE",
    &format!("/api/v1/users/{root_id}"),
    Some(&cookie),
    Some(&csrf),
    None,
  )
  .await;
  assert_eq!(status, 403);
  assert_eq!(
    body["error"]["SELF_DELETE_FORBIDDEN"],
    "You cannot delete your own account."
  );
  let (status, _, _) = call(&router, "POST", "/api/v1/instance/factory-reset", Some(&cookie), Some(&csrf), Some(json!({"currentPassword":"correct-horse-123","confirmation":"FACTORY RESET","acknowledged":true}))).await;
  assert_eq!(status, 200);
  let (status, body, _) = call(&router, "GET", "/api/v1/bootstrap/status", None, None, None).await;
  assert_eq!(status, 200);
  assert_eq!(body["data"]["state"], "setupRequired");
  state.db.close().await;
}

#[tokio::test]
async fn member_manages_projects_and_agent_is_metadata_only() {
  let (_dir, state, router) = fixture().await;
  let setup = state.setup.read().await.token.clone().unwrap();
  let (status, bootstrap, headers) = call(
    &router,
    "POST",
    "/api/v1/bootstrap/admin",
    None,
    None,
    Some(json!({"setupToken":setup,"email":"root@example.com","password":"correct-horse-123"})),
  )
  .await;
  assert_eq!(status, 201);
  let root_cookie = headers
    .get(header::SET_COOKIE)
    .unwrap()
    .to_str()
    .unwrap()
    .split(';')
    .next()
    .unwrap()
    .to_string();
  let root_csrf = bootstrap["data"]["csrfToken"].as_str().unwrap().to_string();
  let (status, member, _) = call(
    &router,
    "POST",
    "/api/v1/users",
    Some(&root_cookie),
    Some(&root_csrf),
    Some(json!({"email":"member@example.com","password":"correct-horse-456","role":"member"})),
  )
  .await;
  assert_eq!(status, 201);
  assert_eq!(member["data"]["role"], "member");
  let (status, login, headers) = call(
    &router,
    "POST",
    "/api/v1/auth/login",
    None,
    None,
    Some(
      json!({"email":"member@example.com","password":"correct-horse-456","sessionKind":"browser"}),
    ),
  )
  .await;
  assert_eq!(status, 200);
  let member_cookie = headers
    .get(header::SET_COOKIE)
    .unwrap()
    .to_str()
    .unwrap()
    .split(';')
    .next()
    .unwrap()
    .to_string();
  let member_csrf = login["data"]["csrfToken"].as_str().unwrap().to_string();
  let (status, _, _) = call(
    &router,
    "POST",
    "/api/v1/projects",
    Some(&member_cookie),
    Some(&member_csrf),
    Some(json!({"name":"member-project"})),
  )
  .await;
  assert_eq!(status, 201);
  let (status, _, _) = call(
    &router,
    "GET",
    "/api/v1/users",
    Some(&member_cookie),
    None,
    None,
  )
  .await;
  assert_eq!(status, 403);
  let (status, agent, _) = call(
    &router,
    "POST",
    "/api/v1/service-accounts",
    Some(&root_cookie),
    Some(&root_csrf),
    Some(json!({"name":"build-agent"})),
  )
  .await;
  assert_eq!(status, 201);
  let agent_id = agent["data"]["id"].as_str().unwrap();
  let (status, token, _) = call(
    &router,
    "POST",
    &format!("/api/v1/service-accounts/{agent_id}/tokens"),
    Some(&root_cookie),
    Some(&root_csrf),
    Some(json!({"name":"default"})),
  )
  .await;
  assert_eq!(status, 201);
  let bearer = token["data"]["plaintextToken"].as_str().unwrap();
  let (status, _, _) = call(
    &router,
    "GET",
    "/api/v1/status",
    Some(&format!("Bearer {bearer}")),
    None,
    None,
  )
  .await;
  assert_eq!(status, 200);
  let (status, _, _) = call(
    &router,
    "POST",
    "/api/v1/projects",
    Some(&format!("Bearer {bearer}")),
    None,
    Some(json!({"name":"agent-project"})),
  )
  .await;
  assert_eq!(status, 403);
  state.db.close().await;
}

#[tokio::test]
async fn agent_token_accepts_no_expiry_and_rejects_over_three_years() {
  let (_dir, state, router) = fixture().await;
  let setup = state.setup.read().await.token.clone().unwrap();
  let (status, bootstrap, headers) = call(
    &router,
    "POST",
    "/api/v1/bootstrap/admin",
    None,
    None,
    Some(json!({"setupToken":setup,"email":"root@example.com","password":"correct-horse-123"})),
  )
  .await;
  assert_eq!(status, 201);
  let cookie = headers
    .get(header::SET_COOKIE)
    .unwrap()
    .to_str()
    .unwrap()
    .split(';')
    .next()
    .unwrap()
    .to_string();
  let csrf = bootstrap["data"]["csrfToken"].as_str().unwrap();
  let (status, account, _) = call(
    &router,
    "POST",
    "/api/v1/service-accounts",
    Some(&cookie),
    Some(csrf),
    Some(json!({"name":"build-agent"})),
  )
  .await;
  assert_eq!(status, 201);
  let id = account["data"]["id"].as_str().unwrap();
  let path = format!("/api/v1/service-accounts/{id}/tokens");
  let (status, never, _) = call(
    &router,
    "POST",
    &path,
    Some(&cookie),
    Some(csrf),
    Some(json!({"name":"never","expiresIn":"never"})),
  )
  .await;
  assert_eq!(status, 201);
  assert!(never["data"]["token"]["expiresAt"].is_null());
  let bearer = never["data"]["plaintextToken"].as_str().unwrap();
  let token_id = never["data"]["token"]["id"].as_str().unwrap();
  let (status, _, _) = call(
    &router,
    "GET",
    "/api/v1/status",
    Some(&format!("Bearer {bearer}")),
    None,
    None,
  )
  .await;
  assert_eq!(status, 200);
  sqlx::query("UPDATE agent_tokens SET expires_at=? WHERE id=?")
    .bind((chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339())
    .bind(token_id)
    .execute(state.db.pool())
    .await
    .unwrap();
  let (status, _, _) = call(
    &router,
    "GET",
    "/api/v1/status",
    Some(&format!("Bearer {bearer}")),
    None,
    None,
  )
  .await;
  assert_eq!(status, 401);
  let (status, _, _) = call(
    &router,
    "POST",
    &path,
    Some(&cookie),
    Some(csrf),
    Some(json!({"name":"limit","expiresIn":"1095d"})),
  )
  .await;
  assert_eq!(status, 201);
  let (status, _, _) = call(
    &router,
    "POST",
    &path,
    Some(&cookie),
    Some(csrf),
    Some(json!({"name":"invalid","expiresIn":"1096d"})),
  )
  .await;
  assert_eq!(status, 400);
  let (status, _, _) = call(
    &router,
    "POST",
    &path,
    Some(&cookie),
    Some(csrf),
    Some(json!({"name":"both","expiresIn":"1h","expiresAt":"2026-12-01T00:00:00Z"})),
  )
  .await;
  assert_eq!(status, 400);
  state.db.close().await;
}

#[tokio::test]
async fn auditor_reads_the_audit_log_and_nothing_else() {
  let (_dir, state, router) = fixture().await;
  let setup = state.setup.read().await.token.clone().unwrap();
  let (status, bootstrap, headers) = call(
    &router,
    "POST",
    "/api/v1/bootstrap/admin",
    None,
    None,
    Some(json!({"setupToken":setup,"email":"root@example.com","password":"correct-horse-123"})),
  )
  .await;
  assert_eq!(status, 201);
  let root_cookie = headers
    .get(header::SET_COOKIE)
    .unwrap()
    .to_str()
    .unwrap()
    .split(';')
    .next()
    .unwrap()
    .to_string();
  let root_csrf = bootstrap["data"]["csrfToken"].as_str().unwrap().to_string();

  // The auditor role is a first-class option when creating an account.
  let (status, auditor, _) = call(
    &router,
    "POST",
    "/api/v1/users",
    Some(&root_cookie),
    Some(&root_csrf),
    Some(json!({"email":"auditor@example.com","password":"correct-horse-789","role":"auditor"})),
  )
  .await;
  assert_eq!(status, 201, "{auditor}");
  assert_eq!(auditor["data"]["role"], "auditor");
  let (status, listed, _) = call(
    &router,
    "GET",
    "/api/v1/users",
    Some(&root_cookie),
    None,
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert!(
    listed["data"]
      .as_array()
      .unwrap()
      .iter()
      .any(|user| user["email"] == "auditor@example.com" && user["role"] == "auditor"),
    "{listed}"
  );

  // An auditor signs in the way `dopbase login` does.
  let (status, login, _) = call(
    &router,
    "POST",
    "/api/v1/auth/login",
    None,
    None,
    Some(json!({"email":"auditor@example.com","password":"correct-horse-789","sessionKind":"cli"})),
  )
  .await;
  assert_eq!(status, 200);
  let bearer = format!("Bearer {}", login["data"]["token"].as_str().unwrap());

  // The audit log, and the export and verification that read it, are the
  // whole surface an auditor reaches.
  let (status, body, _) = call(
    &router,
    "GET",
    "/api/v1/audit-events",
    Some(&bearer),
    None,
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert!(body["data"]["items"].is_array());
  let (status, body, _) = call(
    &router,
    "GET",
    "/api/v1/audit-events/verify",
    Some(&bearer),
    None,
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(body["data"]["ok"], json!(true));

  // Everything else is refused: secrets metadata, project data, mutations,
  // and account administration.
  for (method, path, body_value) in [
    ("GET", "/api/v1/status", None),
    ("GET", "/api/v1/projects", None),
    ("GET", "/api/v1/users", None),
    ("GET", "/api/v1/environments/env_000000/secrets", None),
    ("POST", "/api/v1/projects", Some(json!({"name":"audited"}))),
    (
      "POST",
      "/api/v1/service-accounts",
      Some(json!({"name":"auditor-agent"})),
    ),
  ] {
    let (status, body, _) = call(&router, method, path, Some(&bearer), None, body_value).await;
    assert_eq!(status, 403, "{method} {path} should be refused: {body}");
  }

  // Reading the audit log stays closed to members, who manage projects.
  let (status, member, _) = call(
    &router,
    "POST",
    "/api/v1/users",
    Some(&root_cookie),
    Some(&root_csrf),
    Some(json!({"email":"member@example.com","password":"correct-horse-456","role":"member"})),
  )
  .await;
  assert_eq!(status, 201);
  assert_eq!(member["data"]["role"], "member");
  let (status, login, _) = call(
    &router,
    "POST",
    "/api/v1/auth/login",
    None,
    None,
    Some(json!({"email":"member@example.com","password":"correct-horse-456","sessionKind":"cli"})),
  )
  .await;
  assert_eq!(status, 200);
  let member_bearer = format!("Bearer {}", login["data"]["token"].as_str().unwrap());
  let (status, body, _) = call(
    &router,
    "GET",
    "/api/v1/audit-events",
    Some(&member_bearer),
    None,
    None,
  )
  .await;
  assert_eq!(status, 403, "{body}");
  state.db.close().await;
}
