use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum AuditCommand {
  /// Recompute the audit log's hash chain and report the first inconsistency.
  ///
  /// Exits with code 0 when the chain is intact and 2 when it is broken.
  #[command(after_help = VERIFY_HELP)]
  Verify,
}

pub(crate) const HELP: &str = "\
Examples:
  dopbase audit verify
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
