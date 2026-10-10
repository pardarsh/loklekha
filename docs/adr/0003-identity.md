# ADR 0003: Config-defined accounts with hashed bearer tokens

Status: accepted (2026-10-09)

For the first pilot, accounts and institutions are listed in the instance
config with a role and the SHA-256 of an API token. Each account is backed by
a public `actor` record so contributions are attributable in the graph, but
roles and credentials never enter the record store. Anonymous visitors can
read; writing requires an account (pseudonymous handles are fine).

Follow-ups: self-service sign-up with abuse controls, browser sessions with
CSRF protection for write forms, and institutional authentication.
