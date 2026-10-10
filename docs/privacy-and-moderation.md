# Privacy and moderation

## What the public sees

Public issue records, their public sources, evidence, discussion, proposals,
decisions, actions, claims, outcomes and timelines. Reporters who chose to
withhold their identity appear as "identity withheld"; the reporter and
moderators still see it. Private attachments, moderation reports, moderation
notes and hidden records are never shown and never included in public exports.
A hidden record returns 404 like a missing one.

## Data minimisation

No email, phone number or precise coordinates are collected. Location is a
short, approximate free-text field plus a locality. The about page warns
users not to publish personal information.

## Moderation tools (moderators and admins)

* Queue of open reports (`GET /api/moderation/queue`).
* Hide and restore a record (a visibility change with a reason; the hide event
  is itself visible only to moderators).
* Redact the title, summary, body, location, locality or a source. Redaction
  removes the value from the record and from its stored history (see ADR 0006
  in pardarsh-core); the fact of the redaction remains.
* Private moderation notes.
* Resolve a report as `actioned` or `dismissed`.

Not built yet: appeals, published moderation statistics, abuse heuristics,
and persistent rate limiting (the current limit is per account and in memory).
