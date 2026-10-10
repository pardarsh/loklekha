# ADR 0002: Workflow permissions tied to assignment

Status: accepted (2026-10-09)

Institutional transitions (acknowledge through resolve) require a responder
whose institution is assigned to the issue. Moderators triage, assign and
close but do not declare work done. Anyone signed in may dispute a
resolution; the reporter, moderators and assigned responders may reopen.
Terminal and contested transitions require a reason.

A reporter's suggested institution counts as an assignment (with `unverified`
certainty) so the named body can respond without waiting for triage. The
responder can confirm it, which replaces the suggestion with an asserted
assignment.

Alternatives considered: role-only permissions (too broad, since any
responder could close any issue) and moderator-only assignment (slow for a
pilot).
