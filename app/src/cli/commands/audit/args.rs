use std::path::PathBuf;

use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum AuditCommand {
  /// Recompute the audit log's hash chain and report the first inconsistency.
  ///
  /// Exits with code 0 when the chain is intact and 2 when it is broken.
  #[command(after_help = VERIFY_HELP)]
  Verify,

  /// Stream audit records as JSON lines to standard output or a file.
  #[command(after_help = EXPORT_HELP)]
  Export {
    /// Write the export to a file instead of standard output.
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Overwrite the output file if it already exists.
    #[arg(long)]
    force: bool,

    /// Only records with this action, for example secret.updated.
    #[arg(long, value_name = "ACTION")]
    action: Option<String>,

    /// Only records for this project (name or ID).
    #[arg(long, value_name = "PROJECT_REF")]
    project: Option<String>,

    /// Only records for this environment (PROJECT/NAME or environment ID).
    #[arg(long, value_name = "ENVIRONMENT_REF")]
    environment: Option<String>,

    /// Only records for this actor (email or actor ID).
    #[arg(long, value_name = "ACTOR")]
    actor: Option<String>,

    /// Stop after this many records.
    #[arg(long, value_name = "N")]
    limit: Option<u64>,
  },
}

pub(crate) const HELP: &str = "\
Examples:
  dopbase audit verify
  dopbase audit export --output audit-2026-10-17.jsonl
  dopbase --json audit verify

The audit log is a hash chain: every record stores the hash of the record
before it, so a record that was modified, removed, or inserted after the
fact stands out. Administrators can also review events in the UI.
";
const VERIFY_HELP: &str = "\
Examples:
  dopbase audit verify
  dopbase --json audit verify

Requires an administrator account. Verification walks the records in
sequence order and stops at the first break, reporting how many records
were checked before it. No secret values are read or printed.
";
const EXPORT_HELP: &str = "\
Examples:
  dopbase audit export --output audit.jsonl
  dopbase audit export --action secret.updated --limit 500
  dopbase audit export --project production | jq 'select(.resourceType==\"secret\")'

Requires an administrator account. Each line is one JSON object exactly as
the audit list API returns it, including the chain fields seq, prevHash and
recordHash, so an exported copy can be checked and anchored outside Dopbase.
The whole record set is exported unless a filter or --limit applies, and no
secret values are read or printed. With --output the file is written
atomically with owner-only permissions, and --json reports the count as an
object instead of printing a summary line.
";
