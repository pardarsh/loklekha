# Architecture

```text
loklekha
  server.rs     assembles the app: API + UI, sessions, sign-in, CSRF
  api.rs        JSON API: bearer-token auth, rate limits, error mapping, security headers
  ui.rs         browser UI: askama templates (templates/), forms, flash messages
  auth.rs       axum-login backend (sign-in with handle + password)
  users.rs      web accounts in SQLite (Argon2 hashes via password-auth)
  service.rs    journeys and authorization (Ledger), shared by API and UI
  workflow.rs   issue statuses and transition permissions
  identity.rs   accounts, sessions, API token hashing
  vocab.rs      loklekha.* extension schemas, kinds, relations, tags
  config.rs     instance config and bootstrap of actor records
  cli.rs        clap commands: demo-config, serve, create-user, export, hash-token
      |
      |  Repository, Record, Event, Store, Viewer, graph, interchange
      v
pardarsh-core   (git submodule at ./pardarsh-core; never depends back)
```

## Web stack

| Concern | Library |
| --- | --- |
| HTTP server and routing | axum, tokio |
| Templates | askama |
| Sign-in flow | axum-login |
| Sessions | tower-sessions, stored in SQLite by tower-sessions-rusqlite-store |
| Password hashing | password-auth (Argon2) |
| CSRF protection | axum_csrf |
| Command line | clap |

See ADR 0004 for the reasons and settings.

## Dependency on pardarsh-core

`pardarsh-core` is a git submodule (`.gitmodules`) pinned to a specific
commit of https://github.com/pardarsh/pardarsh-core and used as a Cargo path
dependency (`path = "pardarsh-core"`). The submodule is not a member of this
package's workspace, so `cargo fmt`, `cargo clippy` and `cargo test` here only
cover Loklekha. To move to a newer core:

```bash
git submodule update --remote pardarsh-core
```

then run the tests and commit the updated submodule pointer. Changes to the
core itself are made in the pardarsh-core repository, never in the submodule
checkout.

## Model

Loklekha has no record model of its own. An issue is a core `issue` record
with the `loklekha.issue` extension (status, category, location_text,
locality, affected_service). Evidence, comments, proposals, decisions,
actions, claims and outcomes are core records linked with core relations
(`supports`, `contradicts`, `responds_to`, `disputes`, `decided_by`,
`issued_by`, `assigned_to`, `owned_by`, `duplicates`, `related_to`).
Moderation reports are the extension kind `loklekha:moderation_report`,
linked with the extension relation `loklekha:flags`. Accounts and
institutions are core `actor` records with the `loklekha.account` extension;
roles and tokens live only in the config.

All writes go through `pardarsh_core::repository::Repository`, so validation,
history, idempotency (keys are scoped per account) and optimistic concurrency
apply uniformly. All reads go through `pardarsh_core::access` with a viewer
derived from the session; records a viewer cannot see return 404 exactly like
missing ones.

Storage is SQLite (`pardarsh_core::storage::SqliteStore`). The service is
generic over `Store`, and the journey tests run on the in-memory store. The
ledger sits behind one mutex, which is adequate for a pilot and is the place
to change if write throughput matters.

## HTTP conventions

* JSON bodies; unknown fields are rejected (400). Malformed ids return 404.
* 401 without a valid bearer token on writes; 403 for role or assignment
  failures; 422 with `issues[{path, message}]` for validation failures; 409
  for version or idempotency conflicts; 429 when the per-account write limit
  (`writes_per_minute`) is hit.
* `Idempotency-Key` header supported on writes.
* Bodies are limited to 64 KiB. All responses carry a strict CSP, nosniff,
  no-referrer and frame denial.
