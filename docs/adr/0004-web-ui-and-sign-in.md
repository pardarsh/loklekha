# ADR 0004: Server-rendered web UI with standard sign-in libraries

Status: accepted (2026-10-10)

## Context
Residents need to report and follow issues in a browser, on cheap phones and
slow connections, without an API client. Sign-in, sessions and form security
are easy to get wrong, so they should come from maintained libraries rather
than our own code.

## Decision
* The UI lives in this repository and is rendered on the server with
  **askama** templates (`templates/`). It calls the same `Ledger` service as
  the JSON API, so permissions, validation and privacy filtering are shared.
  No JavaScript is required; the stylesheet is served from `/static/app.css`
  and the Content-Security-Policy allows only same-origin styles.
* **axum-login** handles the sign-in flow and **tower-sessions** handles
  session cookies, stored in SQLite via **tower-sessions-rusqlite-store**
  (pinned to 0.14.1, the release that matches pardarsh-core's rusqlite
  0.37). Expired sessions are deleted hourly.
* Passwords are hashed with Argon2 via **password-auth**. Sessions are bound to
  the password hash, so changing a password signs a user out everywhere.
  Sign-in checks always run a hash comparison so timing does not reveal
  which handles exist.
* Every form carries a token checked by **axum_csrf** (double-submit cookie,
  `SameSite=Strict`, encrypted with a per-process key). Session cookies are
  `HttpOnly`, `SameSite=Lax` and `Secure` unless `secure_cookies` is turned
  off for local development.
* Web users live in their own SQLite table (`lk_users`), never in the record
  store. Each user is linked to the public `actor` record with the same
  handle. Anyone can sign up as a member; responders, moderators and admins
  are created by an operator with `loklekha create-user`.
* After sign-in, redirects only go to local paths.

## Consequences
* loklekha's minimum Rust version is now 1.88 (needed for the patched `time`
  crate used by the cookie libraries). pardarsh-core stays at 1.85.
* Restarting the server invalidates open forms (new CSRF key) but not
  sessions.
* Forms for institutional and moderator actions are the next UI slice; the
  API already supports them.
