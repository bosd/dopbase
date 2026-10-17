use anyhow::{Context, Result};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use std::{fs, str::FromStr, time::Duration};

use crate::config::database_path;

/// Embedded database migrations, exposed so tests can drive `run`/`undo`.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// SQLite database client backed by an async sqlx connection pool.
///
/// Cheap to clone because every clone shares the same underlying pool.
#[derive(Clone, Debug)]
pub struct DbClient {
  pool: SqlitePool,
}

impl DbClient {
  /// Open a pooled connection to the SQLite database at `url`
  /// (e.g. `sqlite://./dopbase.db`). The database file is created
  /// when missing.
  pub async fn connect(url: &str) -> Result<Self> {
    let database = (!url.contains(":memory:"))
      .then(|| database_path(url))
      .transpose()?;
    let database_existed = database.as_ref().is_some_and(|path| path.exists());
    if let Some(parent) = database.as_ref().and_then(|path| path.parent()) {
      fs::create_dir_all(parent)
        .with_context(|| format!("failed to create database directory {}", parent.display()))?;
    }
    let options = SqliteConnectOptions::from_str(url)?
      .create_if_missing(true)
      .journal_mode(SqliteJournalMode::Wal)
      .synchronous(SqliteSynchronous::Normal)
      .foreign_keys(true)
      .busy_timeout(Duration::from_secs(5));

    let pool = SqlitePoolOptions::new()
      .max_connections(10)
      .acquire_timeout(Duration::from_secs(5))
      .idle_timeout(Duration::from_secs(60))
      .connect_with(options)
      .await?;

    #[cfg(unix)]
    if !database_existed && let Some(path) = database {
      use std::os::unix::fs::PermissionsExt;
      fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to secure database file {}", path.display()))?;
    }

    Ok(Self { pool })
  }

  /// Run the migrations embedded in the Dopbase executable.
  ///
  /// Also seals audit records written before the hash chain existed, so a
  /// database restored from an older backup verifies from its first record.
  pub async fn migrate(&self) -> Result<()> {
    MIGRATOR.run(&self.pool).await?;
    let sealed = crate::services::audit_chain::backfill(&self.pool)
      .await
      .context("failed to seal pre-existing audit records")?;
    if sealed > 0 {
      tracing::info!(
        sealed,
        "sealed pre-existing audit records into the hash chain"
      );
    }
    Ok(())
  }

  /// Access the underlying pool for ad-hoc queries.
  pub fn pool(&self) -> &SqlitePool {
    &self.pool
  }

  /// Verify the database is reachable.
  pub async fn ping(&self) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT 1")
      .execute(&self.pool)
      .await
      .map(|_| ())
  }

  /// Flush committed WAL pages into the main database before shutdown.
  pub async fn checkpoint(&self) -> Result<(), sqlx::Error> {
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
      .execute(&self.pool)
      .await
      .map(|_| ())
  }

  /// Gracefully close all pooled connections.
  pub async fn close(&self) {
    self.pool.close().await;
  }
}
