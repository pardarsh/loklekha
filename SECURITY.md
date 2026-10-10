# Security policy

## Reporting a vulnerability

Please do not open a public issue. Report privately through GitHub's
[private vulnerability reporting](https://github.com/pardarsh/loklekha/security/advisories/new),
with steps to reproduce, the affected commit and the impact. We aim to
acknowledge reports within a few days and will credit reporters who want it.

Vulnerabilities in the shared record model (identifiers, history, validation,
storage, export) should be reported to
[pardarsh-core](https://github.com/pardarsh/pardarsh-core/security/advisories/new).

## Supported versions

Loklekha is pre-release. Only the latest commit on the default branch receives
fixes.

## What is especially sensitive

Loklekha holds public reports that can involve people's homes, identities and
disputes with institutions. Please report anything that could:

* expose withheld reporter identities, private attachments, moderation
  reports or moderation notes;
* bypass sign-in, reuse another person's session, or forge a form
  submission (CSRF);
* let someone change an issue's status, assignment or decisions without the
  required role or assignment;
* bypass redaction (data still visible after a moderator redacts it);
* inject script into pages (XSS) or bypass request validation;
* leak API tokens or let tokens be guessed or replayed.

## Measures in place

* API tokens are stored only as SHA-256 hashes; reads are anonymous, API
  writes need a bearer token.
* Web passwords are hashed with Argon2 (password-auth); sign-in uses
  axum-login with tower-sessions. Session cookies are HttpOnly, SameSite=Lax
  and Secure (unless `secure_cookies` is off for local development), and are
  invalidated when the password changes. Redirects after sign-in only go to
  local paths.
* Every form is protected against cross-site request forgery with axum_csrf.
* Unknown request fields are rejected; request bodies are limited to 64 KiB;
  per-account write rate limiting.
* All record validation, history and redaction come from pardarsh-core.
* Hidden or restricted records return 404, the same as missing ones.
* HTML output is escaped; responses carry a strict Content-Security-Policy,
  `nosniff`, `no-referrer` and frame denial; only http(s) links are rendered.
* Dependencies are checked with `cargo deny` in CI and weekly.

## Deployment notes

Run behind TLS. Keep the configuration file (it lists accounts and token
hashes) and the SQLite database (records, web accounts and sessions)
readable only by the service user, back the
database up regularly, and rotate tokens if a configuration file leaks.
