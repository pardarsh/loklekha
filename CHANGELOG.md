# Changelog

## 0.1.0 (unreleased)

* Issue intake with categories, approximate location, suggested institution,
  withheld identity, private attachments and duplicate suggestions.
* Evidence, comments, proposals, institutional decisions, actions with due
  dates, completion claims and observed outcomes as pardarsh-core records.
* Status workflow with assignment-based permissions, reasons for contested
  transitions, disputes and reopening.
* Moderation: reports queue, hide/restore, redaction, private notes.
* Search and filters, issue detail with combined timeline, export bundles.
* JSON API (axum) and read-only HTML pages; config-defined accounts with
  hashed tokens; SQLite storage.
* pardarsh-core consumed as a git submodule.
* Project tooling: GitHub Actions CI, cargo-deny policy, pre-commit hooks,
  pinned toolchain, issue and PR templates, Dependabot,
  CONTRIBUTING, Code of Conduct and SECURITY.
* Command-line interface rebuilt on clap (`--help`, `--version`, validated
  arguments, `serve --bind`), in a testable `cli` module.
* Exhaustive tests: unit tests for every module plus endpoint, page and
  binary tests (about 99% line coverage).
* Web UI: issue list with open/closed tabs and filters, issue page with a
  conversation timeline and sidebar, forms to report issues, comment, add
  evidence, propose remedies, record observations, report to moderators and
  change status; sign-up, sign-in and sign-out. Built with askama,
  axum-login, tower-sessions (SQLite store), password-auth and axum_csrf.
* `create-user` command for web accounts; `secure_cookies` config option.
* Minimum supported Rust version is now 1.88.
* Logo in the header (rounded) and rounded PNG favicon and touch icon; served
  from `static/images/`.
* djLint formats and lints templates in pre-commit and CI.
