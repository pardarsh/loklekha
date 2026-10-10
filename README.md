# Loklekha

Loklekha is a public civic issue ledger: people record a public problem,
attach evidence, discuss remedies, and follow institutional responses,
decisions, actions and observed outcomes, with every change attributed and
kept in history. It is the first application built on
[`pardarsh-core`](https://github.com/pardarsh/pardarsh-core) (a git submodule at `pardarsh-core/`; clone with `git clone --recurse-submodules` or run `git submodule update --init`) and depends on it one way only.

## Screenshots

![Issue page](docs/screenshots/issue-page-signed-in.png)

See [docs/screenshots.md](docs/screenshots.md) for a tour of the UI: the issue
list, an issue's full history, the forms for signed-in users, reporting,
sign-in and dark mode.

## Run it

```bash
cargo run -- demo-config --out loklekha.json
```

This writes a demo configuration (two residents, a Ward 7 engineer, a
moderator, two demo institutions) and prints each account's API token once;
only SHA-256 hashes are stored. Create web sign-in accounts (each prints a
generated password once):

```bash
cargo run -- create-user asha --name "Asha K"
```

```bash
cargo run -- create-user ward7_eng --name "Ward 7 Engineer" --role responder --institution ward7_works
```

Then start the server:

```bash
cargo run -- serve --config loklekha.json
```

Open http://127.0.0.1:8080. The web UI has an issue list with open/closed
tabs and filters, an issue page with a conversation timeline and sidebar,
forms to report issues, comment, add evidence, propose remedies, record
observations, report to moderators and change status, plus sign-up, sign-in
and sign-out. Scripts and integrations use the JSON API under `/api` with
`Authorization: Bearer <token>`, for example:

```bash
curl -X POST http://127.0.0.1:8080/api/issues -H "Authorization: Bearer $TOKEN" -H "content-type: application/json" -d "{\"title\":\"Streetlight out on 4th Cross\",\"category\":\"streetlights\",\"locality\":\"Ward 7\"}"
```

`loklekha export <issue-id> --config loklekha.json` prints a public export
bundle; `loklekha hash-token <token>` prints a token hash for the config.

## Test

```bash
cargo test
```

Tests cover the full streetlight journey (report, duplicate suggestion,
evidence, proposal, assignment, acknowledgement, decision, action, completion
claim, resolution, observed outcome, dispute, reopen, export and re-import),
permissions, moderation and privacy, search filters, and HTTP behaviour
(auth, unknown-field rejection, status codes, escaping, security headers,
idempotency, rate limiting).

## Documentation

* `docs/screenshots.md`: a tour of the web UI
* `docs/product.md`: journeys, workflow and permissions, status versus outcome
* `docs/architecture.md`: boundary with pardarsh-core, modules, HTTP conventions
* `docs/privacy-and-moderation.md`: what is public, moderation tools
* `docs/adr/`: decisions specific to the application

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), the [Code of Conduct](CODE_OF_CONDUCT.md) and
[SECURITY.md](SECURITY.md). CI (`.github/workflows/ci.yml`) checks out the
pardarsh-core submodule and runs rustfmt, clippy, tests on Linux/Windows/macOS,
the MSRV (1.88) build, docs, a CLI smoke test, `cargo deny`, a submodule pin
check and pre-commit hygiene checks. Licensed under MIT (`LICENSE.txt`).

## Not implemented yet

* Web forms for institutional and moderator actions (assignments,
  decisions, actions, completion claims, moderation); these work through the
  API. Password reset, email verification and institutional single sign-on.
* File uploads and malware scanning (evidence is by link only).
* Notifications and subscriptions.
* A full-text search index (search filters in memory over all issues).
* Maps or precise geolocation (location is approximate free text by design).
* Appeals workflow for moderation decisions.
* Federation, legal/budget/procurement integrations, AI assistance.
* Deployment and backups.
