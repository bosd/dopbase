use std::{
  collections::BTreeMap,
  sync::{Arc, OnceLock},
};

use argon2::{
  Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
  password_hash::{SaltString, rand_core::OsRng},
};
use regex::Regex;
use serde_json::Value;

use crate::{
  constants::errors::{EMAIL_INVAILD, EMAIL_INVAILD_MESSAGE},
  http::HttpError,
  services::token,
};

pub fn validate_slug(
  value: &str,
  code: &str,
  label: &str,
) -> Result<(), HttpError> {
  if !crate::utils::slug::is_valid(value) {
    return Err(HttpError::validation(BTreeMap::from([(
      code.into(),
      format!("{label} must be a lowercase slug of at most 63 characters."),
    )])));
  }
  Ok(())
}

pub fn validate_email(value: &str) -> Result<String, HttpError> {
  static EMAIL: OnceLock<Regex> = OnceLock::new();
  let normalized = value.trim().to_lowercase();
  let valid = EMAIL.get_or_init(|| Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").unwrap());
  if normalized.len() > 254 || !valid.is_match(&normalized) {
    return Err(HttpError::validation(BTreeMap::from([(
      EMAIL_INVAILD.into(),
      EMAIL_INVAILD_MESSAGE.into(),
    )])));
  }
  Ok(normalized)
}

pub fn validate_password(value: &str) -> Result<(), HttpError> {
  let length = value.chars().count();
  let mut errors = BTreeMap::new();
  if length < 12 {
    errors.insert(
      "PASSWORD_TOO_SHORT".into(),
      "Password must contain at least 12 characters.".into(),
    );
  }
  if length > 128 {
    errors.insert(
      "PASSWORD_TOO_LONG".into(),
      "Password must contain at most 128 characters.".into(),
    );
  }
  if errors.is_empty() {
    Ok(())
  } else {
    Err(HttpError::validation(errors))
  }
}

pub fn hash_password(value: &str) -> Result<String, HttpError> {
  let params = Params::new(19_456, 2, 1, None).map_err(|_| HttpError::internal())?;
  let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
  let salt = SaltString::generate(&mut OsRng);
  argon
    .hash_password(value.as_bytes(), &salt)
    .map(|hash| hash.to_string())
    .map_err(|_| HttpError::internal())
}

pub fn verify_password(
  value: &str,
  encoded: &str,
) -> bool {
  PasswordHash::new(encoded).ok().is_some_and(|hash| {
    Argon2::default()
      .verify_password(value.as_bytes(), &hash)
      .is_ok()
  })
}

fn password_workers() -> &'static Arc<tokio::sync::Semaphore> {
  static WORKERS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
  WORKERS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(4)))
}

pub async fn hash_password_async(value: String) -> Result<String, HttpError> {
  let value = zeroize::Zeroizing::new(value);
  let permit = password_workers()
    .clone()
    .acquire_owned()
    .await
    .map_err(|_| HttpError::internal())?;
  tokio::task::spawn_blocking(move || {
    let _permit = permit;
    hash_password(&value)
  })
  .await
  .map_err(|error| {
    tracing::error!(%error, "password hashing worker failed");
    HttpError::internal()
  })?
}

pub async fn verify_password_async(
  value: String,
  encoded: String,
) -> Result<bool, HttpError> {
  let permit = password_workers()
    .clone()
    .acquire_owned()
    .await
    .map_err(|_| HttpError::internal())?;
  tokio::task::spawn_blocking(move || {
    let _permit = permit;
    verify_password(&value, &encoded)
  })
  .await
  .map_err(|error| {
    tracing::error!(%error, "password verification worker failed");
    HttpError::internal()
  })
}

/// Record an audit event on the caller's connection.
///
/// The record joins the tamper-evident hash chain, which reads the chain head
/// before inserting. The connection must therefore already hold SQLite's
/// write lock: pass an immediate transaction, or a transaction whose first
/// statement was a write. Every business transaction that audits already
/// writes first, and [`audit_standalone`] handles the remaining cases.
#[allow(clippy::too_many_arguments)]
pub async fn audit(
  connection: &mut sqlx::SqliteConnection,
  actor_type: &str,
  actor_id: Option<&str>,
  actor_label: Option<&str>,
  action: &str,
  project_id: Option<&str>,
  environment_id: Option<&str>,
  resource_type: Option<&str>,
  resource_id: Option<&str>,
  metadata: Value,
) -> Result<(), sqlx::Error> {
  let metadata = metadata.to_string();
  let created_at = chrono::Utc::now().to_rfc3339();
  crate::services::audit_chain::append(
    connection,
    &token::public_id("aud_"),
    actor_type,
    actor_id,
    actor_label,
    action,
    project_id,
    environment_id,
    resource_type,
    resource_id,
    &metadata,
    &created_at,
  )
  .await?;
  // Retention runs in the caller's transaction, after the append, so it
  // cannot remove the record being written and needs no second lock. A
  // failure to prune must not fail the operation that was audited.
  if let Err(error) = crate::services::audit_chain::prune_configured(connection).await {
    tracing::warn!(%error, "audit retention could not be applied");
  }
  Ok(())
}

/// Record an audit event in its own committed transaction.
///
/// For actions that have no business transaction to join, so the record is
/// durable on its own and the chain append stays atomic.
#[allow(clippy::too_many_arguments)]
pub async fn audit_standalone(
  pool: &sqlx::SqlitePool,
  actor_type: &str,
  actor_id: Option<&str>,
  actor_label: Option<&str>,
  action: &str,
  project_id: Option<&str>,
  environment_id: Option<&str>,
  resource_type: Option<&str>,
  resource_id: Option<&str>,
  metadata: Value,
) -> Result<(), sqlx::Error> {
  let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
  audit(
    &mut transaction,
    actor_type,
    actor_id,
    actor_label,
    action,
    project_id,
    environment_id,
    resource_type,
    resource_id,
    metadata,
  )
  .await?;
  transaction.commit().await
}
