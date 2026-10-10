## Summary

<!-- What changes for residents, institutions, moderators or API users? -->

## Motivation

<!-- Why is this change needed? Link the issue if there is one. -->

## Changes

<!-- Briefly describe the implementation. -->

## Testing

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --all-features`
- [ ] `cargo deny check`
- [ ] Journey or HTTP tests cover new behaviour (`tests/journeys.rs`, `tests/http.rs`)

## pardarsh-core

- [ ] No change to the submodule
- [ ] Submodule bumped to a commit that is on pardarsh-core's main branch (`git submodule status`)

## Checklist

- [ ] Permissions are checked in `service.rs`; nothing trusts client-supplied status, identity or timestamps
- [ ] Restricted and moderator-only data stays out of public responses and exports
- [ ] Labels do not imply independent verification (status is not outcome)
- [ ] No competing record model: new data uses `loklekha.*` extensions on core records
- [ ] Docs, ADRs and `CHANGELOG.md` updated where relevant

## Notes

<!-- Anything reviewers should pay particular attention to. -->
