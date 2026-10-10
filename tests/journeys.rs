//! End-to-end user journeys at the service level.

use chrono::{NaiveDate, TimeZone, Utc};
use loklekha::error::AppError;
use loklekha::identity::{Account, Session};
use loklekha::service::*;
use loklekha::vocab;
use loklekha::workflow::{IssueStatus, Role};
use pardarsh_core::interchange::{self, ImportPolicy};
use pardarsh_core::prelude::*;

struct World {
    ledger: Ledger<MemoryStore>,
    clock: ManualClock,
    asha: Session,
    ravi: Session,
    engineer: Session,
    water_engineer: Session,
    moderator: Session,
    ward7: RecordId,
    water: RecordId,
}

fn world() -> World {
    let clock = ManualClock::new(Utc.with_ymd_and_hms(2026, 7, 1, 18, 0, 0).unwrap());
    let mut ledger = Ledger::new(MemoryStore::new(Origin::new("loklekha.test").unwrap())).with_clock(clock.clone());
    let ward7 = ledger.ensure_actor("ward7_works", "Ward 7 Public Works", "institution").unwrap();
    let water = ledger.ensure_actor("city_water", "City Water Board", "institution").unwrap();
    assert_eq!(
        ledger.ensure_actor("ward7_works", "Ward 7 Public Works", "institution").unwrap(),
        ward7,
        "bootstrap is idempotent"
    );
    let mut account = |handle: &str, role: Role, institution: Option<RecordId>| {
        let actor_id = ledger.ensure_actor(handle, handle, "person").unwrap();
        Session::User(Account { actor_id, handle: handle.into(), display_name: handle.into(), role, institution })
    };
    let asha = account("asha", Role::Citizen, None);
    let ravi = account("ravi", Role::Citizen, None);
    let engineer = account("ward7_engineer", Role::Responder, Some(ward7.clone()));
    let water_engineer = account("water_engineer", Role::Responder, Some(water.clone()));
    let moderator = account("moderator", Role::Moderator, None);
    World { ledger, clock, asha, ravi, engineer, water_engineer, moderator, ward7, water }
}

fn streetlight(w: &mut World) -> RecordId {
    let input = NewIssue {
        title: "Streetlight out on 4th Cross for two weeks".into(),
        description: Some(
            "The light near the bus stop has been off since mid-June. The road is dark after 7pm.".into(),
        ),
        category: "streetlights".into(),
        location_text: Some("4th Cross, near the bus stop".into()),
        locality: Some("Ward 7".into()),
        affected_service: Some("street lighting".into()),
        responsible_institution: Some(w.ward7.clone()),
        withhold_identity: true,
        sources: vec![NewSource {
            url: "https://photos.example.org/asha-house.jpg".into(),
            title: Some("photo from my gate".into()),
            private: true,
        }],
    };
    w.ledger.create_issue(&w.asha, input, Some("issue-1")).unwrap().issue.id
}

fn transition(
    w: &mut World,
    who: &Session,
    id: &RecordId,
    to: IssueStatus,
    reason: Option<&str>,
) -> Result<IssueSummary, AppError> {
    let s = who.clone();
    w.ledger.transition(
        &s,
        id,
        TransitionRequest { to, reason: reason.map(str::to_string), expected_version: None },
        None,
    )
}

#[test]
fn streetlight_from_report_to_disputed_resolution() {
    let mut w = world();
    let id = streetlight(&mut w);
    let (asha, ravi, engineer, moderator) = (w.asha.clone(), w.ravi.clone(), w.engineer.clone(), w.moderator.clone());

    // Idempotent retry of the same submission.
    let again = w
        .ledger
        .create_issue(
            &asha,
            NewIssue {
                title: "Streetlight out on 4th Cross for two weeks".into(),
                description: None,
                category: "streetlights".into(),
                location_text: None,
                locality: None,
                affected_service: None,
                responsible_institution: None,
                withhold_identity: true,
                sources: vec![],
            },
            Some("issue-1"),
        )
        .unwrap();
    assert_eq!(again.issue.id, id);

    // A neighbour finds a likely duplicate while reporting.
    let dup = w
        .ledger
        .create_issue(
            &ravi,
            NewIssue {
                title: "4th Cross streetlight not working".into(),
                description: Some("dark near bus stop".into()),
                category: "streetlights".into(),
                location_text: None,
                locality: Some("Ward 7".into()),
                affected_service: None,
                responsible_institution: None,
                withhold_identity: false,
                sources: vec![],
            },
            None,
        )
        .unwrap();
    assert!(dup.possible_duplicates.iter().any(|d| d.issue.id == id), "{:?}", dup.possible_duplicates);
    w.ledger
        .link_issues(
            &ravi,
            &dup.issue.id,
            LinkRequest { other: id.clone(), relation: "duplicates".into(), note: None },
            None,
        )
        .unwrap();

    // Community contributions.
    w.clock.advance(chrono::Duration::hours(1));
    w.ledger
        .add_evidence(
            &ravi,
            &id,
            NewEvidence {
                title: "Photo after dark".into(),
                description: None,
                url: Some("https://photos.example.org/dark-street.jpg".into()),
                observed_at: Some(w.clock.now() - chrono::Duration::hours(2)),
                private: false,
                relation: None,
            },
            None,
        )
        .unwrap();
    let proposal = w
        .ledger
        .propose(&ravi, &id, NewProposal { title: "Replace the fitting with an LED lamp".into(), body: None }, None)
        .unwrap();
    w.ledger
        .comment(
            &asha,
            &id,
            NewComment { kind: "question".into(), body: "Is there a maintenance contract for this road?".into() },
            None,
        )
        .unwrap();

    // The reporter's guess is unverified until the institution confirms it.
    let d = w.ledger.issue_detail(&Session::Anonymous, &id).unwrap();
    assert_eq!(d.responsible[0].certainty, Certainty::Unverified);
    w.ledger
        .assign(&engineer, &id, AssignRequest { institution: w.ward7.clone(), note: Some("our ward".into()) }, None)
        .unwrap();
    let d = w.ledger.issue_detail(&Session::Anonymous, &id).unwrap();
    assert_eq!(d.responsible.len(), 1);
    assert_eq!(d.responsible[0].certainty, Certainty::Asserted);

    // Institutional response and workflow.
    transition(&mut w, &engineer, &id, IssueStatus::Acknowledged, None).unwrap();
    w.ledger
        .comment(
            &engineer,
            &id,
            NewComment { kind: "response".into(), body: "Inspection scheduled this week.".into() },
            None,
        )
        .unwrap();
    transition(&mut w, &engineer, &id, IssueStatus::UnderReview, None).unwrap();
    let decision = w
        .ledger
        .decide(
            &engineer,
            &proposal.id,
            NewDecision { verdict: "accepted".into(), reason: "LED fittings are in this year's plan".into() },
            None,
        )
        .unwrap();
    assert_eq!(decision.kind, RecordKind::Decision);
    let action = w
        .ledger
        .plan_action(
            &engineer,
            &id,
            NewAction {
                title: "Replace fitting at 4th Cross".into(),
                description: None,
                due_date: Some(NaiveDate::from_ymd_opt(2026, 7, 10).unwrap()),
            },
            None,
        )
        .unwrap();
    transition(&mut w, &engineer, &id, IssueStatus::ActionPlanned, None).unwrap();
    transition(&mut w, &engineer, &id, IssueStatus::InProgress, None).unwrap();
    w.ledger
        .update_action(
            &engineer,
            &action.id,
            ActionUpdate { progress: "completed_claimed".into(), note: Some("fitting replaced".into()) },
        )
        .unwrap();
    w.ledger
        .claim_completion(
            &engineer,
            &id,
            NewClaim { statement: "LED fitting installed on 8 July.".into(), evidence_url: None },
            None,
        )
        .unwrap();
    assert!(transition(&mut w, &engineer, &id, IssueStatus::Resolved, None).is_err(), "resolving needs a reason");
    transition(&mut w, &engineer, &id, IssueStatus::Resolved, Some("fitting replaced")).unwrap();

    // A resident observes the outcome and disputes the resolution.
    w.clock.advance(chrono::Duration::days(9));
    w.ledger
        .record_outcome(
            &ravi,
            &id,
            NewOutcome {
                title: "Light flickers and goes off after 9pm".into(),
                finding: "partially_resolved".into(),
                body: None,
                observed_at: None,
                evidence_url: None,
            },
            None,
        )
        .unwrap();
    transition(&mut w, &ravi, &id, IssueStatus::Disputed, Some("light still goes off at night")).unwrap();

    let d = w.ledger.issue_detail(&Session::Anonymous, &id).unwrap();
    assert_eq!(d.summary.status, IssueStatus::Disputed);
    assert_eq!(d.evidence.len(), 1);
    assert_eq!(d.comments.len(), 2);
    assert_eq!(d.proposals[0].decisions.len(), 1);
    assert_eq!(d.actions.len(), 1);
    assert_eq!(d.completion_claims.len(), 1, "completion claim is kept apart from outcomes");
    assert_eq!(d.outcomes.len(), 1);
    assert!(d.related.iter().any(|r| r.id == dup.issue.id && r.direction == "incoming"));
    assert_eq!(d.reporter.as_deref(), Some("identity withheld"));
    assert!(d.status_notice.contains("not independent verification"));
    let status_changes: Vec<String> = d
        .activity
        .iter()
        .filter(|a| a.entry.tag.as_ref().is_some_and(|t| t.to_string() == "loklekha:status_change"))
        .map(|a| a.entry.changes[0].after.clone().unwrap())
        .collect();
    assert_eq!(
        status_changes,
        ["acknowledged", "under_review", "action_planned", "in_progress", "resolved", "disputed"]
    );
    let disputed = d.activity.iter().rev().find(|a| a.entry.tag.is_some()).unwrap();
    assert_eq!(disputed.actor, "ravi (@ravi)");
    assert_eq!(disputed.entry.reason.as_deref(), Some("light still goes off at night"));

    // The reporter (and moderators) can reopen.
    transition(&mut w, &asha, &id, IssueStatus::Reopened, Some("still dark")).unwrap();

    // Export preserves ids, provenance and history and can be imported elsewhere,
    // but only from a full (moderator) export; the public one is filtered.
    let public = w.ledger.export_issue(&Session::Anonymous, &id).unwrap();
    let json = public.to_json_pretty().unwrap();
    assert!(!json.contains("asha-house"), "private source leaked");
    assert!(!json.contains("\"asha\""), "withheld reporter leaked");
    let full = w.ledger.export_issue(&moderator, &id).unwrap();
    assert!(full.entries.len() >= 10, "issue plus surrounding records: {}", full.entries.len());
    let mut mirror =
        Repository::new(MemoryStore::new(Origin::new("mirror.test").unwrap()), Validator::new(vocab::registry()));
    interchange::import(&mut mirror, &full, &ImportPolicy::default()).unwrap();
    assert_eq!(mirror.history(&id).unwrap(), w.ledger.repo().history(&id).unwrap());
}

#[test]
fn permissions_are_enforced() {
    let mut w = world();
    let id = streetlight(&mut w);
    let (asha, ravi, engineer, water_engineer, moderator) =
        (w.asha.clone(), w.ravi.clone(), w.engineer.clone(), w.water_engineer.clone(), w.moderator.clone());

    // Anonymous visitors cannot write.
    let e =
        w.ledger.propose(&Session::Anonymous, &id, NewProposal { title: "x".into(), body: None }, None).unwrap_err();
    assert!(matches!(e, AppError::Unauthorized));
    // Citizens cannot move the workflow or speak for an institution.
    assert!(matches!(transition(&mut w, &ravi, &id, IssueStatus::Acknowledged, None), Err(AppError::Forbidden(_))));
    assert!(matches!(
        w.ledger.comment(&ravi, &id, NewComment { kind: "response".into(), body: "fixed".into() }, None),
        Err(AppError::Forbidden(_))
    ));
    // Responders of the institution the reporter suggested may respond to it.
    transition(&mut w, &engineer, &id, IssueStatus::Acknowledged, None).unwrap();
    // Another institution's responder cannot act or self-assign someone else.
    assert!(matches!(
        transition(&mut w, &water_engineer, &id, IssueStatus::UnderReview, None),
        Err(AppError::Forbidden(_))
    ));
    assert!(matches!(
        w.ledger.assign(&water_engineer, &id, AssignRequest { institution: w.ward7.clone(), note: None }, None),
        Err(AppError::Forbidden(_))
    ));
    assert!(matches!(
        w.ledger.plan_action(
            &water_engineer,
            &id,
            NewAction { title: "x".into(), description: None, due_date: None },
            None
        ),
        Err(AppError::Forbidden(_))
    ));
    // Moderators triage and assign but do not declare work done.
    w.ledger.assign(&moderator, &id, AssignRequest { institution: w.water.clone(), note: None }, None).unwrap();
    transition(&mut w, &water_engineer, &id, IssueStatus::UnderReview, None).unwrap();
    assert!(transition(&mut w, &moderator, &id, IssueStatus::Resolved, Some("done")).is_err());
    // Duplicate requires an explicit link first.
    let e = transition(&mut w, &moderator, &id, IssueStatus::Duplicate, Some("same as other")).unwrap_err();
    assert!(matches!(e, AppError::BadRequest(_)));
    // Invalid input is rejected by core validation.
    let e = w
        .ledger
        .create_issue(
            &asha,
            NewIssue {
                title: "x".into(),
                description: None,
                category: "potholes".into(),
                location_text: None,
                locality: None,
                affected_service: None,
                responsible_institution: None,
                withhold_identity: false,
                sources: vec![NewSource { url: "javascript:alert(1)".into(), title: None, private: false }],
            },
            None,
        )
        .unwrap_err();
    let issues = e.validation_issues().unwrap();
    assert!(issues.iter().any(|i| i.path.contains("category")));
    assert!(issues.iter().any(|i| i.path.contains("locator")));
    // Optimistic concurrency on transitions.
    let current = w.ledger.repo().get(&id).unwrap().version;
    let e = w
        .ledger
        .transition(
            &water_engineer,
            &id,
            TransitionRequest { to: IssueStatus::ActionPlanned, reason: None, expected_version: Some(current - 1) },
            None,
        )
        .unwrap_err();
    assert!(matches!(e, AppError::Core(Error::Conflict { .. })));
    // Assigning a non-institution is refused.
    let person = match &asha {
        Session::User(a) => a.actor_id.clone(),
        _ => unreachable!(),
    };
    assert!(w.ledger.assign(&moderator, &id, AssignRequest { institution: person, note: None }, None).is_err());
}

#[test]
fn moderation_and_privacy() {
    let mut w = world();
    let id = streetlight(&mut w);
    let (asha, ravi, moderator) = (w.asha.clone(), w.ravi.clone(), w.moderator.clone());
    let public = Session::Anonymous;

    // Withheld identity and private attachments.
    let d = w.ledger.issue_detail(&public, &id).unwrap();
    assert!(d.issue.sources.is_empty(), "private photo hidden from public");
    assert_eq!(d.reporter.as_deref(), Some("identity withheld"));
    let own = w.ledger.issue_detail(&asha, &id).unwrap();
    assert_eq!(own.reporter.as_deref(), Some("asha (@asha)"));
    let m = w.ledger.issue_detail(&moderator, &id).unwrap();
    assert_eq!(m.issue.sources.len(), 1);
    assert_eq!(m.reporter.as_deref(), Some("asha (@asha)"));

    // Reporting goes to a moderator-only queue.
    let report = w
        .ledger
        .report(
            &ravi,
            &id,
            NewReport { category: "personal_data".into(), details: Some("location names a house".into()) },
            None,
        )
        .unwrap();
    assert!(matches!(w.ledger.moderation_queue(&ravi), Err(AppError::Forbidden(_))));
    assert_eq!(w.ledger.moderation_queue(&moderator).unwrap().len(), 1);
    assert!(w.ledger.issue_detail(&public, &id).unwrap().reports.is_empty());
    assert_eq!(w.ledger.issue_detail(&moderator, &id).unwrap().reports.len(), 1);
    assert!(
        matches!(w.ledger.record(&ravi, &report), Err(AppError::NotFound)),
        "reporters do not see the report record"
    );

    // Redaction removes the value from the record and from history.
    w.ledger
        .moderate(
            &moderator,
            &id,
            ModerationAction::Redact {
                fields: vec![RedactField::LocationText],
                reason: "names a private house".into(),
            },
        )
        .unwrap();
    w.ledger.moderate(&moderator, &id, ModerationAction::Note { text: "reporter contacted".into() }).unwrap();
    w.ledger
        .moderate(
            &moderator,
            &id,
            ModerationAction::ResolveReport { report: report.clone(), state: "actioned".into(), note: None },
        )
        .unwrap();
    assert!(w.ledger.moderation_queue(&moderator).unwrap().is_empty());
    let history = serde_json::to_string(&w.ledger.repo().history(&id).unwrap()).unwrap();
    assert!(!history.contains("4th Cross, near the bus stop"), "redacted text left in history");
    let (_, public_timeline) = w.ledger.record(&public, &id).unwrap();
    assert!(!serde_json::to_string(&public_timeline).unwrap().contains("reporter contacted"), "moderation note leaked");
    let (_, mod_timeline) = w.ledger.record(&moderator, &id).unwrap();
    assert!(serde_json::to_string(&mod_timeline).unwrap().contains("reporter contacted"));

    // Hiding makes the issue disappear for the public (indistinguishable from absent).
    w.ledger.moderate(&moderator, &id, ModerationAction::Hide { reason: "under review".into() }).unwrap();
    assert!(matches!(w.ledger.issue_detail(&public, &id), Err(AppError::NotFound)));
    assert!(w.ledger.search(&public, &SearchQuery::default()).unwrap().is_empty());
    assert!(w.ledger.search(&moderator, &SearchQuery::default()).unwrap()[0].hidden);
    assert!(matches!(
        w.ledger.comment(&ravi, &id, NewComment { kind: "question".into(), body: "?".into() }, None),
        Err(AppError::NotFound)
    ));
    w.ledger.moderate(&moderator, &id, ModerationAction::Restore { reason: "ok after redaction".into() }).unwrap();
    assert!(w.ledger.issue_detail(&public, &id).is_ok());
    assert!(matches!(
        w.ledger.moderate(&ravi, &id, ModerationAction::Note { text: "x".into() }),
        Err(AppError::Forbidden(_))
    ));
}

#[test]
fn search_and_filters() {
    let mut w = world();
    let light = streetlight(&mut w);
    let asha = w.asha.clone();
    let engineer = w.engineer.clone();
    let water = w
        .ledger
        .create_issue(
            &asha,
            NewIssue {
                title: "No water supply in Block C".into(),
                description: Some("Taps dry for three days".into()),
                category: "water".into(),
                location_text: None,
                locality: Some("Ward 9".into()),
                affected_service: Some("piped water".into()),
                responsible_institution: Some(w.water.clone()),
                withhold_identity: false,
                sources: vec![],
            },
            None,
        )
        .unwrap()
        .issue
        .id;
    w.ledger.assign(&engineer, &light, AssignRequest { institution: w.ward7.clone(), note: None }, None).unwrap();
    transition(&mut w, &engineer, &light, IssueStatus::Acknowledged, None).unwrap();

    let s = |w: &World, q: SearchQuery| {
        w.ledger.search(&Session::Anonymous, &q).unwrap().into_iter().map(|i| i.id).collect::<Vec<_>>()
    };
    assert_eq!(s(&w, SearchQuery { q: Some("WATER block".into()), ..Default::default() }), vec![water.clone()]);
    assert_eq!(s(&w, SearchQuery { category: Some("streetlights".into()), ..Default::default() }), vec![light.clone()]);
    assert_eq!(
        s(&w, SearchQuery { status: Some(IssueStatus::Acknowledged), ..Default::default() }),
        vec![light.clone()]
    );
    assert_eq!(s(&w, SearchQuery { locality: Some("ward 9".into()), ..Default::default() }), vec![water.clone()]);
    assert_eq!(s(&w, SearchQuery { institution: Some(w.ward7.clone()), ..Default::default() }), vec![light.clone()]);
    assert_eq!(
        s(&w, SearchQuery { from: Some(NaiveDate::from_ymd_opt(2026, 7, 2).unwrap()), ..Default::default() }),
        Vec::<RecordId>::new()
    );
    assert_eq!(s(&w, SearchQuery::default()), vec![water, light], "newest first");
}
