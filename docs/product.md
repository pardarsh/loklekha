# Product

## Journeys implemented

| Journey | API |
| --- | --- |
| Report an issue (category, approximate location, locality, affected service, optional suggested institution, optional withheld identity, links) | `POST /api/issues` (returns possible duplicates) |
| Find issues | `GET /api/issues?q=&status=&category=&locality=&institution=&from=&to=&open_only=`, `GET /` |
| Check for duplicates before reporting | `GET /api/issues/duplicates?title=` |
| Add evidence (supports or contradicts) | `POST /api/issues/{id}/evidence` |
| Comment, ask, object, respond | `POST /api/records/{id}/comments` |
| Propose a remedy | `POST /api/issues/{id}/proposals` |
| Link related or duplicate issues | `POST /api/issues/{id}/links` |
| Assign or accept responsibility | `POST /api/issues/{id}/assignments`, `DELETE /api/issues/{id}/assignments/{relation}?reason=` |
| Move the workflow | `POST /api/issues/{id}/transitions` |
| Decide on a proposal, with reasons | `POST /api/proposals/{id}/decisions` |
| Plan and update an action with a due date | `POST /api/issues/{id}/actions`, `POST /api/actions/{id}/progress` |
| Claim completion (responsible body) | `POST /api/issues/{id}/completion-claims` |
| Record an observed outcome (anyone) | `POST /api/issues/{id}/outcomes` |
| Read an issue with its timeline | `GET /api/issues/{id}`, `GET /issues/{id}`, `GET /api/records/{id}` |
| Export with provenance and history | `GET /api/issues/{id}/export` |
| Report a record; moderate | `POST /api/records/{id}/reports`, `POST /api/records/{id}/moderation`, `GET /api/moderation/queue` |

## Workflow

`submitted → needs_triage → acknowledged → under_review → action_planned → in_progress → resolved`,
plus `duplicate`, `redirected`, `not_actionable`, `closed_without_resolution`,
`disputed` and `reopened`.

| Transition | Who |
| --- | --- |
| submitted → needs_triage | moderator |
| submitted, needs_triage, reopened → acknowledged | assigned responder, moderator |
| needs_triage, acknowledged, reopened → under_review | assigned responder, moderator |
| earlier open states → action_planned, in_progress | assigned responder |
| action_planned, in_progress, disputed → resolved | assigned responder (reason required) |
| any open state → duplicate, redirected, not_actionable, closed_without_resolution | assigned responder, moderator (reason required; duplicate needs a `duplicates` link) |
| resolved → disputed | any signed-in member (reason required) |
| resolved, disputed or a closed state → reopened | reporter, moderator, assigned responder (reason required) |
| reopened → needs_triage | moderator |

"Assigned responder" means a responder whose institution has an active
`assigned_to` relation on the issue, including one the reporter suggested.
Moderators triage but cannot declare work done. Admins have moderator rights.

## Status is not outcome

The status is an administrative label recorded by the responsible body or by
moderators. `resolved` is shown as "Reported resolved (not independently
verified)". Completion claims (by the institution, as `claim` records) and
observed outcomes (by anyone, as `outcome` records with a finding) are kept
apart, and anyone can dispute a resolution. Status changes are events tagged
`loklekha:status_change` with the actor and reason.

## Defaults chosen

* General-purpose instance, configured per deployment (origin, institutions,
  accounts). The initial context is India, but nothing in the model is
  India-specific.
* Pseudonymous accounts; reporters may withhold their identity publicly.
* Public by default, except attachments marked private, moderation reports
  and moderation notes.
* Export format from day one: the pardarsh bundle (JSON).
