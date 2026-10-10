# Contributing to Loklekha

Thanks for helping build a public issue ledger. Please read
`docs/product.md` and `docs/architecture.md` first, and follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Ground rules

* **No competing record model.** Loklekha stores everything as
  [pardarsh-core](https://github.com/pardarsh/pardarsh-core) records. New data
  goes into `loklekha.*` extensions (see `src/vocab.rs`), not new tables or
  structs that bypass the core repository.
* **Authorization lives in `src/service.rs`.** Never trust client-supplied
  status, identity, roles or timestamps.
* **Status is not outcome.** Do not add labels or defaults that imply a problem
  was independently verified as fixed.
* **Privacy first.** Restricted, moderator-only and withheld data must never
  appear in public responses, pages or exports. Collect no personal data that
  a feature does not strictly need.
* **Neutrality.** Do not encode conclusions about who is right into statuses,
  labels or ranking.

## Setup

```bash
git clone --recurse-submodules https://github.com/pardarsh/loklekha
```

If you already cloned without submodules:

```bash
git submodule update --init
```

The toolchain is pinned in `rust-toolchain.toml`; `rustup` installs it on the
first `cargo` command. The minimum supported Rust version is `rust-version` in
`Cargo.toml` (currently 1.88) and is checked in CI.

Install the git hooks once (needs Python's `pre-commit`):

```bash
pre-commit install
```

This runs file-hygiene checks, the djLint template formatter and linter
(configured in `.djlintrc`), `cargo fmt --check`, clippy and `cargo deny` on
commit, and `cargo test` on push. Format templates with djLint rather than a
plain-HTML formatter, which can break `{% %}` and `{{ }}` tags:

```bash
pre-commit run djlint-reformat --all-files
```

## Working with pardarsh-core

`pardarsh-core/` is a git submodule pinned to one commit. Do not edit files in
it: changes to the shared record model go to the pardarsh-core repository
first. To move Loklekha to a newer core:

```bash
git submodule update --remote pardarsh-core
```

Run the full test suite, then commit the submodule pointer in its own commit
(for example `chore: bump pardarsh-core to <short sha>`). Only pin commits that
are on pardarsh-core's main branch; CI checks this.

## Before opening a pull request

```bash
cargo fmt --all
```

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

```bash
cargo test --all-features
```

```bash
cargo deny check
```

CI runs the same commands, plus tests on Linux, Windows and macOS, the MSRV
build, `cargo doc`, a CLI smoke test and the submodule check.

## What a change should include

* Tests. Unit tests live in a `#[cfg(test)] mod tests` block at the bottom of
  the file they test, so they can reach private helpers. Integration tests in `tests/` drive the public API:
  `journeys.rs` (end-to-end user journeys), `http.rs` and `endpoints.rs`
  (every HTTP endpoint, status codes, auth, headers), `pages.rs` (HTML
  rendering and escaping) and `binary.rs` (the compiled CLI). Keep line
  coverage at or above its current level (about 99%); check it with
  `cargo llvm-cov --all-features --summary-only`.
* Documentation: `docs/product.md` for journeys and permissions,
  `docs/privacy-and-moderation.md` for anything touching visibility, and an
  ADR in `docs/adr/` for decisions that shape the product.
* A `CHANGELOG.md` entry for user-visible changes.

## Commits and reviews

Use conventional commit prefixes (`feat:`, `fix:`, `docs:`, `chore:`, `ci:`,
`refactor:`, `test:`) with an imperative summary. Keep pull requests focused.
At least one maintainer review is required to merge.

## Security

Do not report vulnerabilities in public issues; see [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the MIT
License (see `LICENSE.txt`).
