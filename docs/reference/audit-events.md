---
title: "Audit events"
description: "See which sensitive actions Dopbase records, who performed them, where they happened, and which secret data is excluded."
---

# Audit events

Audit records answer who performed a sensitive action, where it happened, and when. They describe the action without storing the secret value involved.

## Audit events in {{version}}

| Area                  | Events                                                                                                                                                                                          |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Secrets               | `secret.created`, `secret.updated`, `secret.deleted`, `secret.revealed`, `secret.rotated`, `secret.promoted`, `secret.retired`, `secret.imported`, `secret.exported`, `secret.runtime_accessed` |
| Projects              | `project.created`, `project.renamed`, `project.deleted`, `project.initialized`                                                                                                                  |
| Environments          | `environment.created`, `environment.renamed`, `environment.deleted`                                                                                                                             |
| Runner tokens         | `token.created`, `token.revoked`                                                                                                                                                                |
| Authentication        | `login.succeeded`, `login.failed`, `logout.succeeded`                                                                                                                                           |
| Administrator & users | `admin.bootstrapped`, `admin.created`, `admin.updated`, `admin.deleted`, `admin.reauthenticated`, `admin.password_changed`                                                                      |
| AI service accounts   | `service_account.created`, `service_account.deleted`, `service_account.token_created`, `service_account.token_revoked`                                                                          |
| Backups               | `backup.created`, `backup.downloaded`, `backup.uploaded`, `backup.restored`, `backup.deleted`, `master_key.downloaded`, `backup.restored_bootstrap`                                             |

The API schema defines the event names used by this release.

Rotations record `secret.rotated` with the new version, the version it replaced,
and the retire deadline. Rolling a rotation back records `secret.promoted`, and
ending a grace period records `secret.retired`. Rotation records name versions
and deadlines, never either value.

## Integrity and verification

Every audit record is part of a hash chain. It stores its position in the log,
the hash of the record before it, and the hash of its own stored contents, so
modifying, removing, or inserting a record leaves a trace at that point.

- `dopbase audit verify` recomputes every hash in sequence order, stops at the
  first break, and exits with code `0` when the chain is intact and `2` when it
  is broken. `--json` prints the head sequence and hash, which an operator can
  anchor in external, write-once storage.
- `GET /api/v1/audit-events/verify` serves the same check to scripts. It is
  restricted to administrators, like reading the log itself.
- Records written before the chain existed are sealed during the next startup,
  and a backup restored from an older release is sealed during the restore, so
  verification covers the whole log rather than only new records.

The chain proves that a record was not edited after it was written. It cannot
stop someone with write access to the database file from deleting the newest
records, so ship an export elsewhere when you need more than tamper evidence:
`dopbase audit export` streams records as JSON lines to standard output or a
file, chain fields included, for external, write-once storage.

## Record contents

Root and admin can review user, AI account, and backup history in the Audit page.

An audit record may contain:

```text
timestamp
actor
action
organization
project
environment
secret key
IP address
user agent
```

It must never contain the plaintext secret value, a usable authentication token, or a request body that carries credentials.

## Example

```text
2026-08-27 14:23
actor: alice@example.com
action: secret.updated
project: payment-service
environment: production
secret: DATABASE_URL
```

Retention, export, advanced filtering, and signed checkpoints remain roadmap work.
