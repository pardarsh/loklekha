//! Loklekha's application service: issue intake, contributions, responses,
//! workflow, moderation, search and export, implemented on the
//! pardarsh-core repository. All authorization decisions are made here; all
//! record validation and history are delegated to the core.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use chrono::NaiveDate;
use pardarsh_core::access::{Viewer, view_history, view_record};
use pardarsh_core::event::{Change, FieldPath};
use pardarsh_core::extension::ExtValue;
use pardarsh_core::graph::{self, Direction, TraversalOptions};
use pardarsh_core::id::{RecordId, RelationId, SourceId};
use pardarsh_core::interchange::{self, Bundle};
use pardarsh_core::model::{
    ActorRef, ActorRoleKind, Attribution, Lifecycle, Record, RecordDraft, RecordKind, Timestamp, Visibility,
};
use pardarsh_core::projection::{TimelineEntry, timeline};
use pardarsh_core::provenance::{SourceAuthority, SourceRef};
use pardarsh_core::relation::{Certainty, RelationDraft, RelationKind};
use pardarsh_core::repository::{Clock, Meta, Repository};
use pardarsh_core::storage::{RecordQuery, Store};
use pardarsh_core::validation::Validator;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::identity::{Account, Session};
use crate::vocab::{self, MODERATORS, V1};
use crate::workflow::{self, IssueStatus, Role};

// ---- inputs ---------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewSource {
    pub url: String,
    #[serde(default)]
    pub title: Option<String>,
    /// Visible only to moderators (e.g. a photo that shows a home).
    #[serde(default)]
    pub private: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewIssue {
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    pub category: String,
    #[serde(default)]
    pub location_text: Option<String>,
    #[serde(default)]
    pub locality: Option<String>,
    #[serde(default)]
    pub affected_service: Option<String>,
    /// The reporter's guess, recorded as an unverified assignment.
    #[serde(default)]
    pub responsible_institution: Option<RecordId>,
    /// Hide the reporter's identity from the public (kept for moderation).
    #[serde(default)]
    pub withhold_identity: bool,
    #[serde(default)]
    pub sources: Vec<NewSource>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewEvidence {
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub observed_at: Option<Timestamp>,
    #[serde(default)]
    pub private: bool,
    /// `supports` (default) or `contradicts`.
    #[serde(default)]
    pub relation: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewComment {
    pub kind: String,
    pub body: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewProposal {
    pub title: String,
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewDecision {
    pub verdict: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionRequest {
    pub to: IssueStatus,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub expected_version: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignRequest {
    pub institution: RecordId,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewAction {
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub due_date: Option<NaiveDate>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionUpdate {
    pub progress: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewClaim {
    pub statement: String,
    #[serde(default)]
    pub evidence_url: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewOutcome {
    pub title: String,
    pub finding: String,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub observed_at: Option<Timestamp>,
    #[serde(default)]
    pub evidence_url: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkRequest {
    pub other: RecordId,
    /// `related_to` or `duplicates` (this issue duplicates `other`).
    pub relation: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewReport {
    pub category: String,
    #[serde(default)]
    pub details: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "field", rename_all = "snake_case", deny_unknown_fields)]
pub enum RedactField {
    Title,
    Summary,
    Body,
    LocationText,
    Locality,
    Source { id: SourceId },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ModerationAction {
    /// Restrict the record to moderators.
    Hide {
        reason: String,
    },
    Restore {
        reason: String,
    },
    Redact {
        fields: Vec<RedactField>,
        reason: String,
    },
    /// Private note, visible to moderators only.
    Note {
        text: String,
    },
    /// Close a moderation report on this record.
    ResolveReport {
        report: RecordId,
        state: String,
        #[serde(default)]
        note: Option<String>,
    },
}

/// Query-string fields: empty values (as sent by HTML forms) mean "not set".
fn empty_as_none<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match Option::<String>::deserialize(d)? {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => s.trim().parse().map(Some).map_err(serde::de::Error::custom),
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchQuery {
    #[serde(default, deserialize_with = "empty_as_none")]
    pub q: Option<String>,
    #[serde(default, deserialize_with = "empty_as_none")]
    pub status: Option<IssueStatus>,
    #[serde(default, deserialize_with = "empty_as_none")]
    pub category: Option<String>,
    #[serde(default, deserialize_with = "empty_as_none")]
    pub locality: Option<String>,
    #[serde(default, deserialize_with = "empty_as_none")]
    pub institution: Option<RecordId>,
    #[serde(default, deserialize_with = "empty_as_none")]
    pub from: Option<NaiveDate>,
    #[serde(default, deserialize_with = "empty_as_none")]
    pub to: Option<NaiveDate>,
    #[serde(default)]
    pub open_only: bool,
    #[serde(default, deserialize_with = "empty_as_none")]
    pub limit: Option<usize>,
    #[serde(default, deserialize_with = "empty_as_none")]
    pub offset: Option<usize>,
}

// ---- outputs --------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct IssueSummary {
    pub id: RecordId,
    pub title: String,
    pub status: IssueStatus,
    pub status_label: &'static str,
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    pub recorded_at: Timestamp,
    pub updated_at: Timestamp,
    pub hidden: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Responsible {
    pub relation_id: RelationId,
    pub institution: RecordId,
    pub name: String,
    pub certainty: Certainty,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProposalView {
    pub proposal: Record,
    pub decisions: Vec<Record>,
    pub comments: Vec<Record>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RelatedIssue {
    pub id: RecordId,
    pub title: String,
    pub relation: RelationKind,
    /// `outgoing`: this issue → other; `incoming`: other → this issue.
    pub direction: &'static str,
    pub certainty: Certainty,
}

#[derive(Clone, Debug, Serialize)]
pub struct ActivityEntry {
    pub record_id: RecordId,
    pub record_kind: RecordKind,
    pub record_title: String,
    pub actor: String,
    #[serde(flatten)]
    pub entry: TimelineEntry,
}

#[derive(Clone, Debug, Serialize)]
pub struct IssueDetail {
    pub issue: Record,
    pub summary: IssueSummary,
    pub reporter: Option<String>,
    pub responsible: Vec<Responsible>,
    pub evidence: Vec<Record>,
    pub comments: Vec<Record>,
    pub proposals: Vec<ProposalView>,
    pub actions: Vec<Record>,
    pub completion_claims: Vec<Record>,
    pub outcomes: Vec<Record>,
    pub related: Vec<RelatedIssue>,
    /// Moderators only.
    pub reports: Vec<Record>,
    pub activity: Vec<ActivityEntry>,
    pub status_notice: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct CreatedIssue {
    pub issue: IssueSummary,
    pub possible_duplicates: Vec<DuplicateSuggestion>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DuplicateSuggestion {
    pub issue: IssueSummary,
    pub score: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Institution {
    pub id: RecordId,
    pub handle: String,
    pub name: String,
}

/// Reason recorded when an unverified assignment is replaced by a confirmed one.
pub const CONFIRMATION_REASON: &str = "replaced by a confirmed assignment";

pub const STATUS_NOTICE: &str = "Status is an administrative label recorded by the responsible body or moderators. \
\"Resolved\" means the responsible body reports the issue resolved; it is not independent verification. \
See observed outcomes and disputes for evidence about conditions on the ground.";

// ---- the service ----------------------------------------------------------

pub struct Ledger<S: Store> {
    repo: Repository<S>,
}

fn text(v: &str) -> ExtValue {
    ExtValue::Text(v.to_string())
}

fn enum_value(v: &str) -> ExtValue {
    ExtValue::Enum(v.to_string())
}

fn first_line(s: &str, max: usize) -> String {
    let line = s.lines().find(|l| !l.trim().is_empty()).unwrap_or("").trim();
    if line.chars().count() <= max {
        line.to_string()
    } else {
        let mut t: String = line.chars().take(max - 1).collect();
        t.push('…');
        t
    }
}

fn status_of(record: &Record) -> IssueStatus {
    record
        .extension_field(vocab::ISSUE, "status")
        .and_then(ExtValue::as_text)
        .and_then(|s| s.parse().ok())
        .unwrap_or(IssueStatus::Submitted)
}

fn ext_text(record: &Record, ns: &str, field: &str) -> Option<String> {
    record.extension_field(ns, field).and_then(ExtValue::as_text).map(str::to_string)
}

fn tokens(s: &str) -> HashSet<String> {
    const STOP: &[&str] =
        &["the", "and", "for", "near", "with", "not", "from", "this", "that", "are", "was", "has", "have"];
    s.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.chars().count() >= 3 && !STOP.contains(w))
        .map(str::to_string)
        .collect()
}

impl<S: Store> Ledger<S> {
    pub fn new(store: S) -> Self {
        Self { repo: Repository::new(store, Validator::new(vocab::registry())) }
    }

    pub fn with_clock(mut self, clock: impl Clock + 'static) -> Self {
        self.repo = self.repo.with_clock(clock);
        self
    }

    pub fn repo(&self) -> &Repository<S> {
        &self.repo
    }

    // ---- helpers ---------------------------------------------------------

    fn meta(&self, session: &Session, idempotency_key: Option<&str>) -> AppResult<Meta> {
        let account = session.require()?;
        let mut meta = Meta::by(session.attribution()?);
        if let Some(k) = idempotency_key {
            // Scope keys per account so users cannot collide with each other.
            meta = meta.idempotency_key(format!("{}:{k}", account.handle));
        }
        Ok(meta)
    }

    /// A record the viewer may see; otherwise `NotFound` (existence is not leaked).
    fn visible(&self, viewer: &Viewer, id: &RecordId) -> AppResult<Record> {
        let record = self.repo.find(id)?.ok_or(AppError::NotFound)?;
        view_record(&record, viewer).ok_or(AppError::NotFound)
    }

    fn visible_issue(&self, viewer: &Viewer, id: &RecordId) -> AppResult<Record> {
        let r = self.visible(viewer, id)?;
        if r.kind != RecordKind::Issue || !r.extensions.contains_key(vocab::ISSUE) {
            return Err(AppError::NotFound);
        }
        Ok(r)
    }

    /// An issue that accepts new contributions.
    fn open_for_contributions(&self, session: &Session, id: &RecordId) -> AppResult<Record> {
        let issue = self.visible_issue(&session.viewer(), id)?;
        if issue.lifecycle != Lifecycle::Active {
            return Err(AppError::Forbidden("this issue was retracted or superseded".into()));
        }
        Ok(issue)
    }

    fn assigned_institutions(issue: &Record) -> Vec<RecordId> {
        issue.active_relations().filter(|r| r.kind == RelationKind::AssignedTo).map(|r| r.target.clone()).collect()
    }

    fn is_assigned_responder(issue: &Record, account: &Account) -> bool {
        account.role == Role::Responder
            && account.institution.as_ref().is_some_and(|i| Self::assigned_institutions(issue).contains(i))
    }

    fn is_reporter(issue: &Record, account: &Account) -> bool {
        issue.actors_with_role(&ActorRoleKind::Reporter).any(|a| a.actor == account.actor_ref())
    }

    fn require_assigned_responder<'a>(&self, session: &'a Session, issue: &Record) -> AppResult<&'a Account> {
        let account = session.require()?;
        if Self::is_assigned_responder(issue, account) {
            Ok(account)
        } else {
            Err(AppError::Forbidden("only responders of an institution assigned to this issue may do this".into()))
        }
    }

    fn user_source(&self, session: &Session, url: &str, title: Option<String>, private: bool) -> AppResult<SourceRef> {
        let mut s =
            SourceRef::new(url.trim()).authority(SourceAuthority::UserSubmitted).submitted_by(session.attribution()?);
        s.title = title;
        if private {
            s.visibility = Visibility::restricted([MODERATORS]);
        }
        Ok(s)
    }

    fn institution(&self, id: &RecordId) -> AppResult<Record> {
        let r = self.repo.find(id)?.ok_or_else(|| AppError::BadRequest(format!("unknown institution {id}")))?;
        if ext_text(&r, vocab::ACCOUNT, "actor_type").as_deref() != Some("institution") {
            return Err(AppError::BadRequest(format!("{id} is not an institution")));
        }
        Ok(r)
    }

    /// Display name for an attribution as seen by the viewer.
    pub fn display_actor(&self, a: &Attribution) -> String {
        match &a.actor {
            ActorRef::Record { id } => self
                .repo
                .find(id)
                .ok()
                .flatten()
                .map(|r| match ext_text(&r, vocab::ACCOUNT, "handle") {
                    Some(h) => format!("{} (@{h})", r.title),
                    None => r.title,
                })
                .unwrap_or_else(|| id.to_string()),
            ActorRef::Anonymous => match a.disclosure {
                pardarsh_core::model::Disclosure::Withheld => "identity withheld".into(),
                pardarsh_core::model::Disclosure::Public => "anonymous".into(),
            },
            ActorRef::System { name } => format!("system ({name})"),
        }
    }

    fn summary(record: &Record) -> IssueSummary {
        let status = status_of(record);
        IssueSummary {
            id: record.id.clone(),
            title: record.title.clone(),
            status,
            status_label: status.label(),
            category: ext_text(record, vocab::ISSUE, "category").unwrap_or_default(),
            locality: ext_text(record, vocab::ISSUE, "locality"),
            recorded_at: record.times.recorded_at,
            updated_at: record.updated_at,
            hidden: !record.visibility.is_public(),
        }
    }

    // ---- bootstrap -------------------------------------------------------

    /// Find or create the actor record for an account or institution.
    pub fn ensure_actor(&mut self, handle: &str, name: &str, actor_type: &str) -> AppResult<RecordId> {
        let existing = self
            .repo
            .list(&RecordQuery { extension: Some(vocab::ACCOUNT.into()), ..RecordQuery::kind(RecordKind::Actor) })?;
        if let Some(r) = existing.iter().find(|r| ext_text(r, vocab::ACCOUNT, "handle").as_deref() == Some(handle)) {
            return Ok(r.id.clone());
        }
        let fields = BTreeMap::from([("handle".into(), text(handle)), ("actor_type".into(), enum_value(actor_type))]);
        let draft = RecordDraft::new(RecordKind::Actor, name).extension(vocab::ACCOUNT, V1, fields);
        Ok(self.repo.create(draft, Meta::by(Attribution::system("loklekha-bootstrap")))?.record.id)
    }

    pub fn institutions(&self) -> AppResult<Vec<Institution>> {
        let actors = self
            .repo
            .list(&RecordQuery { extension: Some(vocab::ACCOUNT.into()), ..RecordQuery::kind(RecordKind::Actor) })?;
        Ok(actors
            .into_iter()
            .filter(|r| ext_text(r, vocab::ACCOUNT, "actor_type").as_deref() == Some("institution"))
            .map(|r| Institution {
                handle: ext_text(&r, vocab::ACCOUNT, "handle").unwrap_or_default(),
                name: r.title,
                id: r.id,
            })
            .collect())
    }

    // ---- citizen journeys ------------------------------------------------

    pub fn create_issue(
        &mut self,
        session: &Session,
        input: NewIssue,
        idempotency_key: Option<&str>,
    ) -> AppResult<CreatedIssue> {
        let account = session.require()?.clone();
        let reporter = if input.withhold_identity {
            Attribution::withheld(account.actor_ref())
        } else {
            Attribution::public(account.actor_ref())
        };
        let mut fields = BTreeMap::from([
            ("status".to_string(), enum_value(IssueStatus::Submitted.as_str())),
            ("category".to_string(), enum_value(&input.category)),
        ]);
        for (k, v) in [
            ("location_text", &input.location_text),
            ("locality", &input.locality),
            ("affected_service", &input.affected_service),
        ] {
            if let Some(v) = v.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
                fields.insert(k.to_string(), text(v));
            }
        }
        let mut draft = RecordDraft::new(RecordKind::Issue, input.title.trim())
            .actor(ActorRoleKind::Reporter, reporter.clone())
            .extension(vocab::ISSUE, V1, fields);
        draft.body = input.description.filter(|d| !d.trim().is_empty());
        for s in input.sources {
            let mut src = self.user_source(session, &s.url, s.title, s.private)?;
            src.submitted_by = Some(reporter.clone());
            draft = draft.source(src);
        }
        if let Some(inst) = input.responsible_institution {
            self.institution(&inst)?;
            draft = draft.relation(
                RelationDraft::new(RelationKind::AssignedTo, inst)
                    .certainty(Certainty::Unverified)
                    .note("suggested by the reporter; not confirmed"),
            );
        }
        let mut meta = self.meta(session, idempotency_key)?;
        meta.attribution = reporter;
        let possible_duplicates =
            self.suggest_duplicates(session, &draft.title, draft.body.as_deref().unwrap_or(""))?;
        let committed = self.repo.create(draft, meta)?;
        let possible_duplicates =
            possible_duplicates.into_iter().filter(|d| d.issue.id != committed.record.id).collect();
        Ok(CreatedIssue { issue: Self::summary(&committed.record), possible_duplicates })
    }

    pub fn add_evidence(
        &mut self,
        session: &Session,
        issue_id: &RecordId,
        input: NewEvidence,
        key: Option<&str>,
    ) -> AppResult<Record> {
        let issue = self.open_for_contributions(session, issue_id)?;
        let kind = match input.relation.as_deref() {
            None | Some("supports") => RelationKind::Supports,
            Some("contradicts") => RelationKind::Contradicts,
            Some(other) => {
                return Err(AppError::BadRequest(format!("relation must be supports or contradicts, not {other}")));
            }
        };
        let mut draft = RecordDraft::new(RecordKind::Evidence, input.title.trim())
            .actor(ActorRoleKind::Contributor, session.attribution()?)
            .relation(RelationDraft::new(kind, issue.id.clone()));
        draft.body = input.description;
        draft.observed_at = input.observed_at;
        if let Some(url) = &input.url {
            draft = draft.source(self.user_source(session, url, None, input.private)?);
        }
        let meta = self.meta(session, key)?;
        Ok(self.repo.create(draft, meta)?.record)
    }

    /// Comment on an issue or on any visible record attached to it.
    pub fn comment(
        &mut self,
        session: &Session,
        target: &RecordId,
        input: NewComment,
        key: Option<&str>,
    ) -> AppResult<Record> {
        let account = session.require()?;
        let target_record = self.visible(&session.viewer(), target)?;
        if target_record.lifecycle != Lifecycle::Active {
            return Err(AppError::Forbidden("cannot comment on a retracted or superseded record".into()));
        }
        if input.kind == "response" && account.role != Role::Responder && !account.is_moderator() {
            return Err(AppError::Forbidden("only responders and moderators post institutional responses".into()));
        }
        let mut draft = RecordDraft::new(RecordKind::Comment, first_line(&input.body, 120))
            .body(input.body.clone())
            .actor(ActorRoleKind::Author, session.attribution()?)
            .relation(RelationDraft::new(RelationKind::RespondsTo, target.clone()))
            .extension(vocab::COMMENT, V1, BTreeMap::from([("kind".into(), enum_value(&input.kind))]));
        if input.kind == "objection" {
            draft = draft.relation(RelationDraft::new(RelationKind::Disputes, target.clone()));
        }
        if input.body.trim().is_empty() {
            return Err(AppError::BadRequest("comment body must not be empty".into()));
        }
        let meta = self.meta(session, key)?;
        Ok(self.repo.create(draft, meta)?.record)
    }

    pub fn propose(
        &mut self,
        session: &Session,
        issue_id: &RecordId,
        input: NewProposal,
        key: Option<&str>,
    ) -> AppResult<Record> {
        let issue = self.open_for_contributions(session, issue_id)?;
        let mut draft = RecordDraft::new(RecordKind::Proposal, input.title.trim())
            .actor(ActorRoleKind::Author, session.attribution()?)
            .relation(RelationDraft::new(RelationKind::RespondsTo, issue.id));
        draft.body = input.body;
        let meta = self.meta(session, key)?;
        Ok(self.repo.create(draft, meta)?.record)
    }

    pub fn link_issues(
        &mut self,
        session: &Session,
        issue_id: &RecordId,
        input: LinkRequest,
        key: Option<&str>,
    ) -> AppResult<Record> {
        let account = session.require()?.clone();
        let issue = self.open_for_contributions(session, issue_id)?;
        self.visible_issue(&session.viewer(), &input.other)?;
        let kind = match input.relation.as_str() {
            "related_to" => RelationKind::RelatedTo,
            "duplicates" => RelationKind::Duplicates,
            other => {
                return Err(AppError::BadRequest(format!("relation must be related_to or duplicates, not {other}")));
            }
        };
        // A community member's duplicate mark is a suggestion; moderators and
        // assigned responders assert it.
        let certainty = if account.is_moderator() || Self::is_assigned_responder(&issue, &account) {
            Certainty::Asserted
        } else {
            Certainty::Unverified
        };
        let mut draft = RelationDraft::new(kind, input.other).certainty(certainty);
        draft.note = input.note;
        let meta = self.meta(session, key)?;
        Ok(self.repo.link(&issue.id, draft, meta)?.record)
    }

    pub fn record_outcome(
        &mut self,
        session: &Session,
        issue_id: &RecordId,
        input: NewOutcome,
        key: Option<&str>,
    ) -> AppResult<Record> {
        let issue = self.open_for_contributions(session, issue_id)?;
        let mut draft = RecordDraft::new(RecordKind::Outcome, input.title.trim())
            .actor(ActorRoleKind::Author, session.attribution()?)
            .relation(RelationDraft::new(RelationKind::RespondsTo, issue.id))
            .extension(vocab::OUTCOME, V1, BTreeMap::from([("finding".into(), enum_value(&input.finding))]));
        draft.body = input.body;
        draft.observed_at = Some(input.observed_at.unwrap_or_else(|| self.repo.now()));
        if let Some(url) = &input.evidence_url {
            draft = draft.source(self.user_source(session, url, None, false)?);
        }
        let meta = self.meta(session, key)?;
        Ok(self.repo.create(draft, meta)?.record)
    }

    // ---- institutional journeys -----------------------------------------

    /// Assign an institution. Moderators may assign any institution;
    /// responders may only accept responsibility for their own.
    pub fn assign(
        &mut self,
        session: &Session,
        issue_id: &RecordId,
        input: AssignRequest,
        key: Option<&str>,
    ) -> AppResult<Record> {
        let account = session.require()?.clone();
        let issue = self.open_for_contributions(session, issue_id)?;
        self.institution(&input.institution)?;
        let own = account.role == Role::Responder && account.institution.as_ref() == Some(&input.institution);
        if !account.is_moderator() && !own {
            return Err(AppError::Forbidden(
                "only moderators, or responders accepting for their own institution, may assign".into(),
            ));
        }
        // Confirming an unverified suggestion replaces it.
        let mut meta = self.meta(session, key)?;
        meta.tag = Some(vocab::assignment_tag());
        if let Some(prev) =
            issue.active_relations().find(|r| r.kind == RelationKind::AssignedTo && r.target == input.institution)
        {
            if prev.certainty != Certainty::Unverified {
                return Err(AppError::BadRequest("institution is already assigned".into()));
            }
            let mut m = meta.clone();
            m.idempotency_key = None;
            self.repo.unlink(&issue.id, prev.id, m.reason(CONFIRMATION_REASON))?;
        }
        let mut draft = RelationDraft::new(RelationKind::AssignedTo, input.institution).certainty(Certainty::Asserted);
        draft.note = input.note;
        Ok(self.repo.link(&issue.id, draft, meta)?.record)
    }

    pub fn unassign(
        &mut self,
        session: &Session,
        issue_id: &RecordId,
        relation_id: RelationId,
        reason: &str,
    ) -> AppResult<Record> {
        let account = session.require()?.clone();
        let issue = self.open_for_contributions(session, issue_id)?;
        let rel = issue
            .active_relations()
            .find(|r| r.id == relation_id && r.kind == RelationKind::AssignedTo)
            .ok_or(AppError::NotFound)?;
        let own = account.role == Role::Responder && account.institution.as_ref() == Some(&rel.target);
        if !account.is_moderator() && !own {
            return Err(AppError::Forbidden(
                "only moderators or the assigned institution may remove an assignment".into(),
            ));
        }
        let meta = self.meta(session, None)?.reason(reason).tag(vocab::assignment_tag());
        Ok(self.repo.unlink(&issue.id, relation_id, meta)?.record)
    }

    /// Statuses the caller may move this issue to right now (for UI menus).
    pub fn allowed_transitions(&self, session: &Session, issue_id: &RecordId) -> AppResult<Vec<IssueStatus>> {
        let Some(account) = session.account() else { return Ok(Vec::new()) };
        let issue = self.visible_issue(&session.viewer(), issue_id)?;
        let from = status_of(&issue);
        let who = workflow::Actor {
            role: account.role,
            is_reporter: Self::is_reporter(&issue, account),
            is_assigned_responder: Self::is_assigned_responder(&issue, account),
        };
        Ok(IssueStatus::ALL.into_iter().filter(|to| workflow::check_transition(from, *to, who).is_ok()).collect())
    }

    pub fn transition(
        &mut self,
        session: &Session,
        issue_id: &RecordId,
        req: TransitionRequest,
        key: Option<&str>,
    ) -> AppResult<IssueSummary> {
        let account = session.require()?.clone();
        let issue = self.visible_issue(&session.viewer(), issue_id)?;
        let from = status_of(&issue);
        let who = workflow::Actor {
            role: account.role,
            is_reporter: Self::is_reporter(&issue, &account),
            is_assigned_responder: Self::is_assigned_responder(&issue, &account),
        };
        workflow::check_transition(from, req.to, who).map_err(AppError::Forbidden)?;
        let reason = req.reason.filter(|r| !r.trim().is_empty());
        if req.to.requires_reason() && reason.is_none() {
            return Err(AppError::BadRequest(format!("a reason is required to mark an issue {}", req.to)));
        }
        if req.to == IssueStatus::Duplicate && !issue.active_relations().any(|r| r.kind == RelationKind::Duplicates) {
            return Err(AppError::BadRequest("link the canonical issue with a `duplicates` relation first".into()));
        }
        let mut meta = self.meta(session, key)?.tag(vocab::status_change_tag());
        meta.reason = reason;
        meta.expected_version = req.expected_version;
        let c = self.repo.set_extension_field(
            &issue.id,
            vocab::ISSUE,
            "status",
            Some(enum_value(req.to.as_str())),
            meta,
        )?;
        Ok(Self::summary(&c.record))
    }

    pub fn decide(
        &mut self,
        session: &Session,
        proposal_id: &RecordId,
        input: NewDecision,
        key: Option<&str>,
    ) -> AppResult<Record> {
        let proposal = self.visible(&session.viewer(), proposal_id)?;
        if proposal.kind != RecordKind::Proposal {
            return Err(AppError::NotFound);
        }
        let issue_id = proposal
            .active_relations()
            .find(|r| r.kind == RelationKind::RespondsTo)
            .map(|r| r.target.clone())
            .ok_or_else(|| AppError::BadRequest("proposal is not attached to an issue".into()))?;
        let issue = self.visible_issue(&session.viewer(), &issue_id)?;
        let account = self.require_assigned_responder(session, &issue)?.clone();
        let institution = account.institution.clone().expect("assigned responders have an institution");
        if input.reason.trim().is_empty() {
            return Err(AppError::BadRequest("a decision needs a reason".into()));
        }
        let draft = RecordDraft::new(RecordKind::Decision, format!("{}: {}", input.verdict, proposal.title))
            .body(input.reason.clone())
            .actor(ActorRoleKind::Issuer, Attribution::public(ActorRef::Record { id: institution.clone() }))
            .actor(ActorRoleKind::Author, session.attribution()?)
            .relation(RelationDraft::new(RelationKind::IssuedBy, institution))
            .relation(RelationDraft::new(RelationKind::RespondsTo, proposal.id.clone()))
            .extension(vocab::DECISION, V1, BTreeMap::from([("verdict".into(), enum_value(&input.verdict))]));
        let meta = self.meta(session, key)?;
        let decision = self.repo.create(draft, meta)?;
        if decision.replayed {
            return Ok(decision.record);
        }
        let link_meta = self.meta(session, None)?;
        self.repo.link(
            &proposal.id,
            RelationDraft::new(RelationKind::DecidedBy, decision.record.id.clone()),
            link_meta,
        )?;
        Ok(decision.record)
    }

    pub fn plan_action(
        &mut self,
        session: &Session,
        issue_id: &RecordId,
        input: NewAction,
        key: Option<&str>,
    ) -> AppResult<Record> {
        let issue = self.open_for_contributions(session, issue_id)?;
        let account = self.require_assigned_responder(session, &issue)?.clone();
        let institution = account.institution.clone().expect("assigned responders have an institution");
        let mut fields = BTreeMap::from([("progress".to_string(), enum_value("planned"))]);
        if let Some(d) = input.due_date {
            fields.insert("due_date".into(), ExtValue::Date(d));
        }
        let mut draft = RecordDraft::new(RecordKind::Action, input.title.trim())
            .actor(ActorRoleKind::Responsible, Attribution::public(ActorRef::Record { id: institution.clone() }))
            .relation(RelationDraft::new(RelationKind::RespondsTo, issue.id))
            .relation(RelationDraft::new(RelationKind::OwnedBy, institution))
            .extension(vocab::ACTION, V1, fields);
        draft.body = input.description;
        let meta = self.meta(session, key)?;
        Ok(self.repo.create(draft, meta)?.record)
    }

    pub fn update_action(&mut self, session: &Session, action_id: &RecordId, input: ActionUpdate) -> AppResult<Record> {
        let account = session.require()?.clone();
        let action = self.visible(&session.viewer(), action_id)?;
        if action.kind != RecordKind::Action {
            return Err(AppError::NotFound);
        }
        let owner = action.active_relations().find(|r| r.kind == RelationKind::OwnedBy).map(|r| r.target.clone());
        if account.role != Role::Responder || account.institution.is_none() || account.institution != owner {
            return Err(AppError::Forbidden("only the owning institution may update an action".into()));
        }
        let mut meta = self.meta(session, None)?;
        meta.reason = input.note;
        Ok(self
            .repo
            .set_extension_field(&action.id, vocab::ACTION, "progress", Some(enum_value(&input.progress)), meta)?
            .record)
    }

    /// A responder's claim that work is complete. Recorded as a claim, never
    /// as an observed outcome.
    pub fn claim_completion(
        &mut self,
        session: &Session,
        issue_id: &RecordId,
        input: NewClaim,
        key: Option<&str>,
    ) -> AppResult<Record> {
        let issue = self.open_for_contributions(session, issue_id)?;
        let account = self.require_assigned_responder(session, &issue)?.clone();
        let institution = account.institution.clone().expect("assigned responders have an institution");
        let mut draft = RecordDraft::new(RecordKind::Claim, first_line(&input.statement, 120))
            .body(input.statement.clone())
            .actor(ActorRoleKind::Issuer, Attribution::public(ActorRef::Record { id: institution }))
            .actor(ActorRoleKind::Author, session.attribution()?)
            .relation(RelationDraft::new(RelationKind::RespondsTo, issue.id))
            .extension(vocab::CLAIM, V1, BTreeMap::from([("claim_type".into(), enum_value("completion"))]));
        if let Some(url) = &input.evidence_url {
            draft = draft.source(self.user_source(session, url, None, false)?);
        }
        let meta = self.meta(session, key)?;
        Ok(self.repo.create(draft, meta)?.record)
    }

    // ---- moderation ------------------------------------------------------

    pub fn report(
        &mut self,
        session: &Session,
        target: &RecordId,
        input: NewReport,
        key: Option<&str>,
    ) -> AppResult<RecordId> {
        let target = self.visible(&session.viewer(), target)?;
        let fields =
            BTreeMap::from([("category".into(), enum_value(&input.category)), ("state".into(), enum_value("open"))]);
        let mut draft = RecordDraft::new(
            vocab::moderation_report_kind(),
            format!("Report ({}): {}", input.category, first_line(&target.title, 80)),
        )
        .visibility(Visibility::restricted([MODERATORS]))
        .relation(RelationDraft::new(vocab::flags_relation(), target.id))
        .extension(vocab::REPORT, V1, fields);
        draft.body = input.details;
        let meta = self.meta(session, key)?.visibility(Visibility::restricted([MODERATORS]));
        Ok(self.repo.create(draft, meta)?.record.id)
    }

    pub fn moderation_queue(&self, session: &Session) -> AppResult<Vec<Record>> {
        session.require_moderator()?;
        let reports = self.repo.list(&RecordQuery::kind(vocab::moderation_report_kind()))?;
        Ok(reports.into_iter().filter(|r| ext_text(r, vocab::REPORT, "state").as_deref() == Some("open")).collect())
    }

    pub fn moderate(&mut self, session: &Session, target: &RecordId, action: ModerationAction) -> AppResult<Record> {
        session.require_moderator()?;
        self.repo.find(target)?.ok_or(AppError::NotFound)?;
        let private = Visibility::restricted([MODERATORS]);
        let meta = self.meta(session, None)?.tag(vocab::moderation_tag());
        let committed = match action {
            ModerationAction::Hide { reason } => self.repo.amend(
                target,
                vec![Change::Visibility(private.clone())],
                meta.reason(reason).visibility(private),
            )?,
            ModerationAction::Restore { reason } => {
                self.repo.amend(target, vec![Change::Visibility(Visibility::Public)], meta.reason(reason))?
            }
            ModerationAction::Redact { fields, reason } => {
                let paths = fields
                    .into_iter()
                    .map(|f| match f {
                        RedactField::Title => FieldPath::Title,
                        RedactField::Summary => FieldPath::Summary,
                        RedactField::Body => FieldPath::Body,
                        RedactField::LocationText => {
                            FieldPath::Extension { namespace: vocab::ISSUE.into(), field: "location_text".into() }
                        }
                        RedactField::Locality => {
                            FieldPath::Extension { namespace: vocab::ISSUE.into(), field: "locality".into() }
                        }
                        RedactField::Source { id } => FieldPath::Source { id },
                    })
                    .collect();
                self.repo.redact(target, paths, meta.reason(reason))?
            }
            ModerationAction::Note { text: note } => self.repo.annotate(
                target,
                vocab::moderation_note(),
                BTreeMap::from([("text".into(), ExtValue::Text(note))]),
                meta.visibility(private),
            )?,
            ModerationAction::ResolveReport { report, state, note } => {
                let r = self.repo.find(&report)?.ok_or(AppError::NotFound)?;
                if r.kind != vocab::moderation_report_kind() || !r.active_relations().any(|x| &x.target == target) {
                    return Err(AppError::BadRequest("report does not concern this record".into()));
                }
                let mut meta = meta.visibility(private);
                meta.reason = note;
                self.repo.set_extension_field(&report, vocab::REPORT, "state", Some(enum_value(&state)), meta)?
            }
        };
        Ok(committed.record)
    }

    // ---- reading ---------------------------------------------------------

    pub fn search(&self, session: &Session, q: &SearchQuery) -> AppResult<Vec<IssueSummary>> {
        let viewer = session.viewer();
        let words: Vec<String> =
            q.q.as_deref().unwrap_or("").to_lowercase().split_whitespace().map(str::to_string).collect();
        let limit = q.limit.unwrap_or(50).min(200);
        let issues = self
            .repo
            .list(&RecordQuery { extension: Some(vocab::ISSUE.into()), ..RecordQuery::kind(RecordKind::Issue) })?;
        Ok(issues
            .iter()
            .filter_map(|r| view_record(r, &viewer))
            .filter(|r| {
                let status = status_of(r);
                let haystack = format!(
                    "{} {} {} {} {}",
                    r.title,
                    r.summary.as_deref().unwrap_or(""),
                    r.body.as_deref().unwrap_or(""),
                    ext_text(r, vocab::ISSUE, "location_text").unwrap_or_default(),
                    ext_text(r, vocab::ISSUE, "affected_service").unwrap_or_default(),
                )
                .to_lowercase();
                let date = r.times.recorded_at.date_naive();
                words.iter().all(|w| haystack.contains(w.as_str()))
                    && q.status.is_none_or(|s| s == status)
                    && (!q.open_only || status.is_open())
                    && q.category.as_ref().is_none_or(|c| ext_text(r, vocab::ISSUE, "category").as_ref() == Some(c))
                    && q.locality.as_ref().is_none_or(|l| {
                        ext_text(r, vocab::ISSUE, "locality").is_some_and(|x| x.to_lowercase() == l.to_lowercase())
                    })
                    && q.institution.as_ref().is_none_or(|i| Self::assigned_institutions(r).contains(i))
                    && q.from.is_none_or(|f| date >= f)
                    && q.to.is_none_or(|t| date <= t)
            })
            .skip(q.offset.unwrap_or(0))
            .take(limit)
            .map(|r| Self::summary(&r))
            .collect())
    }

    pub fn suggest_duplicates(
        &self,
        session: &Session,
        title: &str,
        description: &str,
    ) -> AppResult<Vec<DuplicateSuggestion>> {
        let viewer = session.viewer();
        let probe = tokens(&format!("{title} {description}"));
        if probe.is_empty() {
            return Ok(Vec::new());
        }
        let issues = self
            .repo
            .list(&RecordQuery { extension: Some(vocab::ISSUE.into()), ..RecordQuery::kind(RecordKind::Issue) })?;
        let mut out: Vec<DuplicateSuggestion> = issues
            .iter()
            .filter_map(|r| view_record(r, &viewer))
            .filter(|r| status_of(r).is_open())
            .filter_map(|r| {
                let t = tokens(&format!("{} {}", r.title, r.body.as_deref().unwrap_or("")));
                let inter = probe.intersection(&t).count() as f64;
                let union = probe.union(&t).count() as f64;
                let score = if union == 0.0 { 0.0 } else { inter / union };
                (score >= 0.25)
                    .then(|| DuplicateSuggestion { issue: Self::summary(&r), score: (score * 100.0).round() / 100.0 })
            })
            .collect();
        out.sort_by(|a, b| b.score.total_cmp(&a.score));
        out.truncate(5);
        Ok(out)
    }

    fn attached(&self, viewer: &Viewer, target: &RecordId) -> AppResult<Vec<(RelationKind, Certainty, Record)>> {
        let mut out = Vec::new();
        for edge in self.repo.incoming(target)? {
            if edge.relation.retracted {
                continue;
            }
            let Some(r) = self.repo.find(&edge.source)? else { continue };
            if r.lifecycle != Lifecycle::Active {
                continue;
            }
            if let Some(r) = view_record(&r, viewer) {
                out.push((edge.relation.kind, edge.relation.certainty, r));
            }
        }
        out.sort_by_key(|(_, _, r)| r.times.recorded_at);
        Ok(out)
    }

    fn activity_of(&self, viewer: &Viewer, record: &Record, out: &mut Vec<ActivityEntry>) -> AppResult<()> {
        let history = view_history(&self.repo.history(&record.id)?, viewer);
        for entry in timeline(&history) {
            out.push(ActivityEntry {
                record_id: record.id.clone(),
                record_kind: record.kind.clone(),
                record_title: record.title.clone(),
                actor: self.display_actor(&entry.attribution),
                entry,
            });
        }
        Ok(())
    }

    pub fn issue_detail(&self, session: &Session, id: &RecordId) -> AppResult<IssueDetail> {
        let viewer = session.viewer();
        let issue = self.visible_issue(&viewer, id)?;
        let mut d = IssueDetail {
            summary: Self::summary(&issue),
            reporter: issue.actors_with_role(&ActorRoleKind::Reporter).next().map(|a| self.display_actor(a)),
            responsible: Vec::new(),
            evidence: Vec::new(),
            comments: Vec::new(),
            proposals: Vec::new(),
            actions: Vec::new(),
            completion_claims: Vec::new(),
            outcomes: Vec::new(),
            related: Vec::new(),
            reports: Vec::new(),
            activity: Vec::new(),
            status_notice: STATUS_NOTICE,
            issue: issue.clone(),
        };
        for rel in issue.active_relations() {
            match rel.kind {
                RelationKind::AssignedTo => d.responsible.push(Responsible {
                    relation_id: rel.id,
                    institution: rel.target.clone(),
                    name: self.repo.find(&rel.target)?.map(|r| r.title).unwrap_or_else(|| rel.target.to_string()),
                    certainty: rel.certainty,
                }),
                RelationKind::RelatedTo | RelationKind::Duplicates => {
                    if let Ok(other) = self.visible_issue(&viewer, &rel.target) {
                        d.related.push(RelatedIssue {
                            id: other.id,
                            title: other.title,
                            relation: rel.kind.clone(),
                            direction: "outgoing",
                            certainty: rel.certainty,
                        });
                    }
                }
                _ => {}
            }
        }
        let mut activity = Vec::new();
        self.activity_of(&viewer, &issue, &mut activity)?;
        for (kind, certainty, r) in self.attached(&viewer, &issue.id)? {
            match &r.kind {
                RecordKind::Evidence => d.evidence.push(r.clone()),
                RecordKind::Comment => d.comments.push(r.clone()),
                RecordKind::Action => d.actions.push(r.clone()),
                RecordKind::Claim => d.completion_claims.push(r.clone()),
                RecordKind::Outcome => d.outcomes.push(r.clone()),
                RecordKind::Proposal => {
                    let mut pv = ProposalView { proposal: r.clone(), decisions: Vec::new(), comments: Vec::new() };
                    for (_, _, child) in self.attached(&viewer, &r.id)? {
                        match child.kind {
                            RecordKind::Decision => pv.decisions.push(child.clone()),
                            RecordKind::Comment => pv.comments.push(child.clone()),
                            _ => continue,
                        }
                        self.activity_of(&viewer, &child, &mut activity)?;
                    }
                    d.proposals.push(pv);
                }
                RecordKind::Issue => d.related.push(RelatedIssue {
                    id: r.id.clone(),
                    title: r.title.clone(),
                    relation: kind,
                    direction: "incoming",
                    certainty,
                }),
                k if *k == vocab::moderation_report_kind() => d.reports.push(r.clone()),
                _ => continue,
            }
            if r.kind != RecordKind::Issue {
                self.activity_of(&viewer, &r, &mut activity)?;
            }
        }
        activity.sort_by(|a, b| {
            a.entry.recorded_at.cmp(&b.entry.recorded_at).then(a.entry.sequence.cmp(&b.entry.sequence))
        });
        d.activity = activity;
        Ok(d)
    }

    /// A single visible record with its (viewer-filtered) timeline.
    pub fn record(&self, session: &Session, id: &RecordId) -> AppResult<(Record, Vec<TimelineEntry>)> {
        let viewer = session.viewer();
        let r = self.visible(&viewer, id)?;
        let history = view_history(&self.repo.history(id)?, &viewer);
        Ok((r, timeline(&history)))
    }

    /// Export an issue and the records around it, with history and
    /// provenance, as the viewer may see them.
    pub fn export_issue(&self, session: &Session, id: &RecordId) -> AppResult<Bundle> {
        let viewer = session.viewer();
        let issue = self.visible_issue(&viewer, id)?;
        let t = graph::traverse(
            self.repo.store(),
            &issue.id,
            &TraversalOptions { direction: Direction::Both, max_depth: 2, max_nodes: 500, ..Default::default() },
        )?;
        let mut ids = vec![issue.id.clone()];
        let mut seen = BTreeSet::from([issue.id.clone()]);
        for (id, _) in t.nodes {
            if seen.insert(id.clone()) {
                ids.push(id);
            }
        }
        Ok(interchange::export(&self.repo, &ids, &viewer)?)
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the application service, including paths that can only be
    //! reached by changing records underneath the service (retraction,
    //! supersession, foreign record kinds).

    use chrono::{NaiveDate, TimeZone, Utc};
    use pardarsh_core::id::Origin;
    use pardarsh_core::model::Disclosure;
    use pardarsh_core::repository::ManualClock;
    use pardarsh_core::storage::MemoryStore;

    use super::*;
    use crate::identity::Account;

    struct World {
        ledger: Ledger<MemoryStore>,
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
        let mut ledger = Ledger::new(MemoryStore::new(Origin::new("unit.test").unwrap())).with_clock(clock);
        let ward7 = ledger.ensure_actor("ward7_works", "Ward 7 Public Works", "institution").unwrap();
        let water = ledger.ensure_actor("city_water", "City Water Board", "institution").unwrap();
        let mut account = |handle: &str, role: Role, institution: Option<RecordId>| {
            let actor_id = ledger.ensure_actor(handle, handle, "person").unwrap();
            Session::User(Account { actor_id, handle: handle.into(), display_name: handle.into(), role, institution })
        };
        World {
            asha: account("asha", Role::Citizen, None),
            ravi: account("ravi", Role::Citizen, None),
            engineer: account("ward7_engineer", Role::Responder, Some(ward7.clone())),
            water_engineer: account("water_engineer", Role::Responder, Some(water.clone())),
            moderator: account("moderator", Role::Moderator, None),
            ledger,
            ward7,
            water,
        }
    }

    fn new_issue(title: &str, institution: Option<RecordId>) -> NewIssue {
        NewIssue {
            title: title.into(),
            description: Some("Taps dry since Monday morning".into()),
            category: "water".into(),
            location_text: Some("Block C".into()),
            locality: Some("Ward 9".into()),
            affected_service: Some("  ".into()),
            responsible_institution: institution,
            withhold_identity: false,
            sources: vec![],
        }
    }

    fn issue(w: &mut World, institution: Option<RecordId>) -> RecordId {
        let asha = w.asha.clone();
        w.ledger.create_issue(&asha, new_issue("No water supply in Block C", institution), None).unwrap().issue.id
    }

    fn sys() -> Meta {
        Meta::by(Attribution::system("test"))
    }

    // ---- pure helpers ---------------------------------------------------------

    #[test]
    fn first_line_skips_blank_lines_and_truncates() {
        assert_eq!(first_line("\n\n  Hello world  \nsecond", 120), "Hello world");
        assert_eq!(first_line("abcdef", 4), "abc…");
        assert_eq!(first_line("abcd", 4), "abcd");
        assert_eq!(first_line("", 10), "");
        assert_eq!(first_line("ಕನ್ನಡ ಪಠ್ಯ", 3).chars().count(), 3, "counts characters, not bytes");
    }

    #[test]
    fn tokens_ignore_short_and_stop_words() {
        let t = tokens("The streetlight near the BUS stop is out, for 2 weeks!");
        let mut v: Vec<_> = t.into_iter().collect();
        v.sort();
        assert_eq!(v, ["bus", "out", "stop", "streetlight", "weeks"]);
    }

    #[test]
    fn status_defaults_to_submitted_when_missing_or_unknown() {
        let mut w = world();
        let id = issue(&mut w, None);
        let mut r = w.ledger.repo.get(&id).unwrap();
        assert_eq!(status_of(&r), IssueStatus::Submitted);
        r.extensions.get_mut(vocab::ISSUE).unwrap().fields.insert("status".into(), ExtValue::Enum("bogus".into()));
        assert_eq!(status_of(&r), IssueStatus::Submitted);
        r.extensions.clear();
        assert_eq!(status_of(&r), IssueStatus::Submitted);
    }

    #[test]
    fn search_query_treats_empty_and_null_as_unset() {
        let q: SearchQuery =
            serde_json::from_str(r#"{"q":"","status":null,"category":" ","limit":"5","open_only":true}"#).unwrap();
        assert!(q.q.is_none() && q.status.is_none() && q.category.is_none());
        assert_eq!(q.limit, Some(5));
        assert!(q.open_only);
        assert!(serde_json::from_str::<SearchQuery>(r#"{"status":"nonsense"}"#).is_err());
        assert!(serde_json::from_str::<SearchQuery>(r#"{"unknown":"x"}"#).is_err());
        let q: SearchQuery = serde_json::from_str(r#"{"status":" resolved ","from":"2026-07-01"}"#).unwrap();
        assert_eq!(q.status, Some(IssueStatus::Resolved));
        assert_eq!(q.from, Some(NaiveDate::from_ymd_opt(2026, 7, 1).unwrap()));
    }

    // ---- display ----------------------------------------------------------------

    #[test]
    fn display_actor_variants() {
        let w = world();
        let asha = w.asha.account().unwrap().actor_ref();
        assert_eq!(w.ledger.display_actor(&Attribution::public(asha)), "asha (@asha)");
        let ward = ActorRef::Record { id: w.ward7.clone() };
        assert_eq!(w.ledger.display_actor(&Attribution::public(ward)), "Ward 7 Public Works (@ward7_works)");
        let ghost = RecordId::generate(&Origin::new("elsewhere.example").unwrap());
        assert_eq!(
            w.ledger.display_actor(&Attribution::public(ActorRef::Record { id: ghost.clone() })),
            ghost.to_string()
        );
        assert_eq!(w.ledger.display_actor(&Attribution::anonymous()), "anonymous");
        let withheld = Attribution { actor: ActorRef::Anonymous, disclosure: Disclosure::Withheld };
        assert_eq!(w.ledger.display_actor(&withheld), "identity withheld");
        assert_eq!(w.ledger.display_actor(&Attribution::system("importer")), "system (importer)");
    }

    #[test]
    fn display_actor_without_handle_uses_title() {
        let mut w = world();
        let id =
            w.ledger.repo.create(RecordDraft::new(RecordKind::Actor, "Unnamed Contractor"), sys()).unwrap().record.id;
        assert_eq!(w.ledger.display_actor(&Attribution::public(ActorRef::Record { id })), "Unnamed Contractor");
    }

    // ---- intake and contributions ------------------------------------------------

    #[test]
    fn create_issue_trims_and_drops_blank_fields() {
        let mut w = world();
        let id = {
            let inst = w.water.clone();
            issue(&mut w, Some(inst))
        };
        let r = w.ledger.repo.get(&id).unwrap();
        assert_eq!(ext_text(&r, vocab::ISSUE, "affected_service"), None, "whitespace-only fields are dropped");
        assert_eq!(ext_text(&r, vocab::ISSUE, "locality").as_deref(), Some("Ward 9"));
        let rel = r.relations.iter().find(|x| x.kind == RelationKind::AssignedTo).unwrap();
        assert_eq!(rel.certainty, Certainty::Unverified);

        let asha = w.asha.clone();
        let mut blank = new_issue("Blank description", None);
        blank.description = Some("   ".into());
        let r = w.ledger.create_issue(&asha, blank, None).unwrap();
        assert!(w.ledger.repo.get(&r.issue.id).unwrap().body.is_none());

        let person = w.asha.account().unwrap().actor_id.clone();
        let e = w.ledger.create_issue(&asha, new_issue("x", Some(person)), None).unwrap_err();
        assert!(matches!(e, AppError::BadRequest(m) if m.contains("not an institution")));
        let ghost = RecordId::generate(&Origin::new("unit.test").unwrap());
        let e = w.ledger.create_issue(&asha, new_issue("x", Some(ghost)), None).unwrap_err();
        assert!(matches!(e, AppError::BadRequest(m) if m.contains("unknown institution")));
    }

    #[test]
    fn sources_are_marked_user_submitted_and_private_ones_restricted() {
        let mut w = world();
        let asha = w.asha.clone();
        let mut input = new_issue("Leak", None);
        input.withhold_identity = true;
        input.sources = vec![
            NewSource { url: " https://example.org/public.jpg ".into(), title: Some("street".into()), private: false },
            NewSource { url: "https://example.org/home.jpg".into(), title: None, private: true },
        ];
        let id = w.ledger.create_issue(&asha, input, None).unwrap().issue.id;
        let r = w.ledger.repo.get(&id).unwrap();
        assert_eq!(r.sources[0].locator, "https://example.org/public.jpg", "locators are trimmed");
        assert!(r.sources.iter().all(|s| s.authority == pardarsh_core::provenance::SourceAuthority::UserSubmitted));
        assert!(r.sources.iter().all(|s| s.submitted_by.as_ref().unwrap().disclosure == Disclosure::Withheld));
        assert!(r.sources[0].visibility.is_public());
        assert!(!r.sources[1].visibility.is_public());
    }

    #[test]
    fn evidence_relation_choices() {
        let mut w = world();
        let id = issue(&mut w, None);
        let ravi = w.ravi.clone();
        let ev = |relation: Option<&str>| NewEvidence {
            title: "Meter reading".into(),
            description: Some("reads zero".into()),
            url: None,
            observed_at: None,
            private: false,
            relation: relation.map(str::to_string),
        };
        let c = w.ledger.add_evidence(&ravi, &id, ev(Some("contradicts")), None).unwrap();
        assert_eq!(c.relations[0].kind, RelationKind::Contradicts);
        assert!(c.sources.is_empty());
        let s = w.ledger.add_evidence(&ravi, &id, ev(Some("supports")), None).unwrap();
        assert_eq!(s.relations[0].kind, RelationKind::Supports);
        let e = w.ledger.add_evidence(&ravi, &id, ev(Some("proves")), None).unwrap_err();
        assert!(matches!(e, AppError::BadRequest(m) if m.contains("supports or contradicts")));
        let mut private = ev(None);
        private.url = Some("https://example.org/private.jpg".into());
        private.private = true;
        let p = w.ledger.add_evidence(&ravi, &id, private, None).unwrap();
        assert!(!p.sources[0].visibility.is_public());
    }

    #[test]
    fn contributions_require_a_visible_active_issue() {
        let mut w = world();
        let id = issue(&mut w, None);
        let ravi = w.ravi.clone();
        let other = issue(&mut w, None);

        // Not an issue (an evidence record) is NotFound for issue-only actions.
        let ev = w
            .ledger
            .add_evidence(
                &ravi,
                &id,
                NewEvidence {
                    title: "x".into(),
                    description: None,
                    url: None,
                    observed_at: None,
                    private: false,
                    relation: None,
                },
                None,
            )
            .unwrap();
        let e = w.ledger.propose(&ravi, &ev.id, NewProposal { title: "x".into(), body: None }, None).unwrap_err();
        assert!(matches!(e, AppError::NotFound));

        // Retracted issues accept no new contributions.
        w.ledger.repo.retract(&id, sys().reason("filed in error")).unwrap();
        let e = w.ledger.propose(&ravi, &id, NewProposal { title: "x".into(), body: None }, None).unwrap_err();
        assert!(matches!(e, AppError::Forbidden(m) if m.contains("retracted or superseded")));
        let e =
            w.ledger.comment(&ravi, &id, NewComment { kind: "question".into(), body: "?".into() }, None).unwrap_err();
        assert!(matches!(e, AppError::Forbidden(m) if m.contains("retracted or superseded")));
        // A retracted issue is hidden from detail's attached list when it links elsewhere.
        let _ = other;
    }

    #[test]
    fn comments_objections_and_responses() {
        let mut w = world();
        let id = issue(&mut w, None);
        let (ravi, engineer, moderator) = (w.ravi.clone(), w.engineer.clone(), w.moderator.clone());
        let objection = w
            .ledger
            .comment(
                &ravi,
                &id,
                NewComment { kind: "objection".into(), body: "This is not the board's pipe".into() },
                None,
            )
            .unwrap();
        let kinds: Vec<_> = objection.relations.iter().map(|r| r.kind.clone()).collect();
        assert_eq!(kinds, [RelationKind::RespondsTo, RelationKind::Disputes]);
        assert_eq!(objection.title, "This is not the board's pipe");

        let e =
            w.ledger.comment(&ravi, &id, NewComment { kind: "question".into(), body: "   ".into() }, None).unwrap_err();
        assert!(matches!(e, AppError::BadRequest(m) if m.contains("must not be empty")));
        let e = w.ledger.comment(&ravi, &id, NewComment { kind: "shout".into(), body: "x".into() }, None).unwrap_err();
        assert!(e.validation_issues().is_some(), "unknown comment kinds fail validation");
        w.ledger
            .comment(&engineer, &id, NewComment { kind: "response".into(), body: "Checking".into() }, None)
            .unwrap();
        w.ledger
            .comment(&moderator, &id, NewComment { kind: "response".into(), body: "Triaged".into() }, None)
            .unwrap();
        // Replies to comments are allowed.
        w.ledger
            .comment(&ravi, &objection.id, NewComment { kind: "argument".into(), body: "It is".into() }, None)
            .unwrap();
        // Comments on hidden records are NotFound.
        let ghost = RecordId::generate(&Origin::new("unit.test").unwrap());
        assert!(matches!(
            w.ledger.comment(&ravi, &ghost, NewComment { kind: "question".into(), body: "?".into() }, None),
            Err(AppError::NotFound)
        ));
    }

    #[test]
    fn links_between_issues() {
        let mut w = world();
        let a = {
            let inst = w.ward7.clone();
            issue(&mut w, Some(inst))
        };
        let b = issue(&mut w, None);
        let (ravi, moderator, engineer) = (w.ravi.clone(), w.moderator.clone(), w.engineer.clone());
        let link = |relation: &str| LinkRequest {
            other: b.clone(),
            relation: relation.into(),
            note: Some("same pipe".into()),
        };
        let e = w.ledger.link_issues(&ravi, &a, link("causes"), None).unwrap_err();
        assert!(matches!(e, AppError::BadRequest(m) if m.contains("related_to or duplicates")));
        let r = w.ledger.link_issues(&ravi, &a, link("related_to"), None).unwrap();
        assert_eq!(r.relations.last().unwrap().certainty, Certainty::Unverified, "community links are suggestions");
        let r = w.ledger.link_issues(&moderator, &a, link("duplicates"), None).unwrap();
        assert_eq!(r.relations.last().unwrap().certainty, Certainty::Asserted);
        let c = issue(&mut w, None);
        let r = w
            .ledger
            .link_issues(&engineer, &a, LinkRequest { other: c, relation: "related_to".into(), note: None }, None)
            .unwrap();
        assert_eq!(r.relations.last().unwrap().certainty, Certainty::Asserted, "assigned responders assert");
        let ghost = RecordId::generate(&Origin::new("unit.test").unwrap());
        assert!(matches!(
            w.ledger.link_issues(
                &ravi,
                &a,
                LinkRequest { other: ghost, relation: "related_to".into(), note: None },
                None
            ),
            Err(AppError::NotFound)
        ));

        // Outgoing links show on the linking issue, incoming on the target.
        let d = w.ledger.issue_detail(&Session::Anonymous, &a).unwrap();
        assert!(
            d.related.iter().any(|x| x.id == b && x.direction == "outgoing" && x.relation == RelationKind::Duplicates)
        );
        let d = w.ledger.issue_detail(&Session::Anonymous, &b).unwrap();
        assert!(d.related.iter().any(|x| x.id == a && x.direction == "incoming"));
    }

    #[test]
    fn outcomes_with_evidence_and_default_observation_time() {
        let mut w = world();
        let id = issue(&mut w, None);
        let ravi = w.ravi.clone();
        let o = w
            .ledger
            .record_outcome(
                &ravi,
                &id,
                NewOutcome {
                    title: "Water back".into(),
                    finding: "problem_resolved".into(),
                    body: None,
                    observed_at: None,
                    evidence_url: Some("https://example.org/tap.mp4".into()),
                },
                None,
            )
            .unwrap();
        assert_eq!(o.times.observed_at, Some(w.ledger.repo.now()));
        assert_eq!(o.sources.len(), 1);
        let e = w
            .ledger
            .record_outcome(
                &ravi,
                &id,
                NewOutcome {
                    title: "x".into(),
                    finding: "fixed!".into(),
                    body: None,
                    observed_at: None,
                    evidence_url: None,
                },
                None,
            )
            .unwrap_err();
        assert!(e.validation_issues().is_some());
    }

    // ---- institutions ---------------------------------------------------------------

    #[test]
    fn assignment_rules() {
        let mut w = world();
        let id = issue(&mut w, None);
        let (ravi, engineer, water_engineer, moderator) =
            (w.ravi.clone(), w.engineer.clone(), w.water_engineer.clone(), w.moderator.clone());
        let req = |i: &RecordId| AssignRequest { institution: i.clone(), note: None };

        assert!(matches!(w.ledger.assign(&ravi, &id, req(&w.ward7), None), Err(AppError::Forbidden(_))));
        assert!(matches!(w.ledger.assign(&water_engineer, &id, req(&w.ward7), None), Err(AppError::Forbidden(_))));
        w.ledger.assign(&engineer, &id, req(&w.ward7), None).unwrap();
        let e = w.ledger.assign(&moderator, &id, req(&w.ward7), None).unwrap_err();
        assert!(matches!(e, AppError::BadRequest(m) if m.contains("already assigned")));
        w.ledger.assign(&moderator, &id, req(&w.water), None).unwrap();

        let detail = w.ledger.issue_detail(&Session::Anonymous, &id).unwrap();
        assert_eq!(detail.responsible.len(), 2);
        let ward_rel = detail.responsible.iter().find(|r| r.institution == w.ward7).unwrap().relation_id;
        let water_rel = detail.responsible.iter().find(|r| r.institution == w.water).unwrap().relation_id;

        // Unassignment: only moderators or the institution itself.
        assert!(matches!(w.ledger.unassign(&ravi, &id, ward_rel, "no"), Err(AppError::Forbidden(_))));
        assert!(matches!(w.ledger.unassign(&water_engineer, &id, ward_rel, "no"), Err(AppError::Forbidden(_))));
        w.ledger.unassign(&engineer, &id, ward_rel, "not our road").unwrap();
        assert!(matches!(w.ledger.unassign(&engineer, &id, ward_rel, "again"), Err(AppError::NotFound)));
        w.ledger.unassign(&moderator, &id, water_rel, "wrong body").unwrap();
        assert!(w.ledger.issue_detail(&Session::Anonymous, &id).unwrap().responsible.is_empty());
        let random = pardarsh_core::id::RelationId::generate();
        assert!(matches!(w.ledger.unassign(&moderator, &id, random, "x"), Err(AppError::NotFound)));
        let timeline = w.ledger.repo.timeline(&id).unwrap();
        assert_eq!(timeline.last().unwrap().reason.as_deref(), Some("wrong body"));
    }

    #[test]
    fn decisions() {
        let mut w = world();
        let id = {
            let inst = w.ward7.clone();
            issue(&mut w, Some(inst))
        };
        let (ravi, engineer, water_engineer) = (w.ravi.clone(), w.engineer.clone(), w.water_engineer.clone());
        let proposal = w
            .ledger
            .propose(&ravi, &id, NewProposal { title: "New pipe".into(), body: Some("replace".into()) }, None)
            .unwrap();
        let decision = |verdict: &str, reason: &str| NewDecision { verdict: verdict.into(), reason: reason.into() };

        assert!(
            matches!(w.ledger.decide(&engineer, &id, decision("accepted", "ok"), None), Err(AppError::NotFound)),
            "only proposals"
        );
        assert!(matches!(
            w.ledger.decide(&water_engineer, &proposal.id, decision("accepted", "ok"), None),
            Err(AppError::Forbidden(_))
        ));
        assert!(matches!(
            w.ledger.decide(&ravi, &proposal.id, decision("accepted", "ok"), None),
            Err(AppError::Forbidden(_))
        ));
        let e = w.ledger.decide(&engineer, &proposal.id, decision("accepted", "  "), None).unwrap_err();
        assert!(matches!(e, AppError::BadRequest(m) if m.contains("needs a reason")));

        let first =
            w.ledger.decide(&engineer, &proposal.id, decision("rejected", "budget exhausted"), Some("d1")).unwrap();
        let retry =
            w.ledger.decide(&engineer, &proposal.id, decision("rejected", "budget exhausted"), Some("d1")).unwrap();
        assert_eq!(first.id, retry.id, "retries do not duplicate decisions or links");
        let p = w.ledger.repo.get(&proposal.id).unwrap();
        assert_eq!(p.relations.iter().filter(|r| r.kind == RelationKind::DecidedBy).count(), 1);
        assert_eq!(first.title, "rejected: New pipe");
        assert_eq!(first.body.as_deref(), Some("budget exhausted"));

        // A proposal detached from its issue cannot be decided.
        let rel = p.relations.iter().find(|r| r.kind == RelationKind::RespondsTo).unwrap().id;
        w.ledger.repo.unlink(&proposal.id, rel, sys()).unwrap();
        let e = w.ledger.decide(&engineer, &proposal.id, decision("accepted", "ok"), None).unwrap_err();
        assert!(matches!(e, AppError::BadRequest(m) if m.contains("not attached")));
    }

    #[test]
    fn actions_and_claims() {
        let mut w = world();
        let id = {
            let inst = w.ward7.clone();
            issue(&mut w, Some(inst))
        };
        let (ravi, engineer, water_engineer) = (w.ravi.clone(), w.engineer.clone(), w.water_engineer.clone());
        let action = w
            .ledger
            .plan_action(
                &engineer,
                &id,
                NewAction { title: "Fix valve".into(), description: Some("valve 3".into()), due_date: None },
                None,
            )
            .unwrap();
        assert!(action.extension_field(vocab::ACTION, "due_date").is_none());
        assert_eq!(action.extension_field(vocab::ACTION, "progress"), Some(&ExtValue::Enum("planned".into())));

        let update = |p: &str| ActionUpdate { progress: p.into(), note: None };
        assert!(matches!(
            w.ledger.update_action(&ravi, &action.id, update("in_progress")),
            Err(AppError::Forbidden(_))
        ));
        assert!(matches!(
            w.ledger.update_action(&water_engineer, &action.id, update("in_progress")),
            Err(AppError::Forbidden(_))
        ));
        assert!(
            matches!(w.ledger.update_action(&engineer, &id, update("in_progress")), Err(AppError::NotFound)),
            "only actions"
        );
        assert!(
            w.ledger
                .update_action(&engineer, &action.id, update("teleported"))
                .unwrap_err()
                .validation_issues()
                .is_some()
        );
        w.ledger.update_action(&engineer, &action.id, update("in_progress")).unwrap();

        assert!(matches!(
            w.ledger.claim_completion(&ravi, &id, NewClaim { statement: "done".into(), evidence_url: None }, None),
            Err(AppError::Forbidden(_))
        ));
        let claim = w
            .ledger
            .claim_completion(
                &engineer,
                &id,
                NewClaim {
                    statement: "Valve replaced".into(),
                    evidence_url: Some("https://example.org/report.pdf".into()),
                },
                None,
            )
            .unwrap();
        assert_eq!(claim.kind, RecordKind::Claim);
        assert_eq!(claim.sources.len(), 1);
        assert_eq!(
            claim.actors_with_role(&ActorRoleKind::Issuer).next().unwrap().actor,
            ActorRef::Record { id: w.ward7.clone() }
        );
    }

    #[test]
    fn transitions_reject_unknown_issues_and_stale_versions() {
        let mut w = world();
        let id = {
            let inst = w.ward7.clone();
            issue(&mut w, Some(inst))
        };
        let engineer = w.engineer.clone();
        let req = |to, v| TransitionRequest { to, reason: Some("  ".into()), expected_version: v };
        let ghost = RecordId::generate(&Origin::new("unit.test").unwrap());
        assert!(matches!(
            w.ledger.transition(&engineer, &ghost, req(IssueStatus::Acknowledged, None), None),
            Err(AppError::NotFound)
        ));
        assert!(matches!(
            w.ledger.transition(&Session::Anonymous, &id, req(IssueStatus::Acknowledged, None), None),
            Err(AppError::Unauthorized)
        ));
        w.ledger.transition(&engineer, &id, req(IssueStatus::Acknowledged, Some(1)), None).unwrap();
        let e = w.ledger.transition(&engineer, &id, req(IssueStatus::Redirected, None), None).unwrap_err();
        assert!(matches!(e, AppError::BadRequest(m) if m.contains("reason is required")), "blank reasons do not count");
    }

    // ---- moderation -----------------------------------------------------------------

    #[test]
    fn every_redactable_field() {
        let mut w = world();
        let asha = w.asha.clone();
        let moderator = w.moderator.clone();
        let mut input = new_issue("Call Asha on 98xxxxxx01", None);
        input.sources =
            vec![NewSource { url: "https://example.org/asha-house.jpg".into(), title: None, private: false }];
        let id = w.ledger.create_issue(&asha, input, None).unwrap().issue.id;
        w.ledger.repo.amend(&id, vec![Change::Summary(Some("summary with name".into()))], sys()).unwrap();
        let source = w.ledger.repo.get(&id).unwrap().sources[0].id;
        let fields = vec![
            RedactField::Title,
            RedactField::Summary,
            RedactField::Body,
            RedactField::LocationText,
            RedactField::Locality,
            RedactField::Source { id: source },
        ];
        let r = w
            .ledger
            .moderate(&moderator, &id, ModerationAction::Redact { fields, reason: "personal data".into() })
            .unwrap();
        assert_eq!(r.title, "[redacted]");
        assert_eq!(r.summary.as_deref(), Some("[redacted]"));
        assert_eq!(r.body.as_deref(), Some("[redacted]"));
        assert_eq!(r.extension_field(vocab::ISSUE, "location_text"), Some(&ExtValue::Redacted));
        assert_eq!(r.extension_field(vocab::ISSUE, "locality"), Some(&ExtValue::Redacted));
        assert!(r.sources[0].locator.starts_with("urn:redacted:"));
        let history = serde_json::to_string(&w.ledger.repo.history(&id).unwrap()).unwrap();
        for secret in ["98xxxxxx01", "summary with name", "asha-house", "Block C", "Ward 9"] {
            assert!(!history.contains(secret), "{secret} left in history");
        }
    }

    #[test]
    fn moderation_guards() {
        let mut w = world();
        let id = issue(&mut w, None);
        let other = issue(&mut w, None);
        let (ravi, moderator) = (w.ravi.clone(), w.moderator.clone());
        let ghost = RecordId::generate(&Origin::new("unit.test").unwrap());
        assert!(matches!(
            w.ledger.moderate(&moderator, &ghost, ModerationAction::Note { text: "x".into() }),
            Err(AppError::NotFound)
        ));
        assert!(matches!(
            w.ledger.report(&ravi, &ghost, NewReport { category: "spam".into(), details: None }, None),
            Err(AppError::NotFound)
        ));

        let report = w.ledger.report(&ravi, &id, NewReport { category: "spam".into(), details: None }, None).unwrap();
        let resolve = |report: RecordId| ModerationAction::ResolveReport {
            report,
            state: "dismissed".into(),
            note: Some("not spam".into()),
        };
        // Resolving against the wrong record, a non-report, or a missing report fails.
        let e = w.ledger.moderate(&moderator, &other, resolve(report.clone())).unwrap_err();
        assert!(matches!(e, AppError::BadRequest(m) if m.contains("does not concern")));
        let e = w.ledger.moderate(&moderator, &id, resolve(other.clone())).unwrap_err();
        assert!(matches!(e, AppError::BadRequest(_)));
        assert!(matches!(w.ledger.moderate(&moderator, &id, resolve(ghost)), Err(AppError::NotFound)));
        w.ledger.moderate(&moderator, &id, resolve(report.clone())).unwrap();
        let r = w.ledger.repo.get(&report).unwrap();
        assert_eq!(r.extension_field(vocab::REPORT, "state"), Some(&ExtValue::Enum("dismissed".into())));
        assert!(
            w.ledger
                .report(&ravi, &id, NewReport { category: "rude".into(), details: None }, None)
                .unwrap_err()
                .validation_issues()
                .is_some()
        );
    }

    // ---- reading ----------------------------------------------------------------------

    #[test]
    fn detail_skips_retracted_links_and_inactive_or_foreign_records() {
        let mut w = world();
        let id = issue(&mut w, None);
        let ravi = w.ravi.clone();
        let mk_ev = |w: &mut World| {
            w.ledger
                .add_evidence(
                    &ravi,
                    &id,
                    NewEvidence {
                        title: "Photo".into(),
                        description: None,
                        url: None,
                        observed_at: None,
                        private: false,
                        relation: None,
                    },
                    None,
                )
                .unwrap()
        };
        let kept = mk_ev(&mut w);
        let unlinked = mk_ev(&mut w);
        let retracted = mk_ev(&mut w);
        let rel = unlinked.relations[0].id;
        w.ledger.repo.unlink(&unlinked.id, rel, sys()).unwrap();
        w.ledger.repo.retract(&retracted.id, sys().reason("wrong photo")).unwrap();
        // A record kind Loklekha does not display (a source) that points at the issue.
        w.ledger
            .repo
            .create(
                RecordDraft::new(RecordKind::Source, "Gazette")
                    .relation(RelationDraft::new(RelationKind::Cites, id.clone())),
                sys(),
            )
            .unwrap();
        // A proposal with a reply comment and an unrelated child kind.
        let proposal =
            w.ledger.propose(&ravi, &id, NewProposal { title: "New pipe".into(), body: None }, None).unwrap();
        w.ledger
            .comment(&ravi, &proposal.id, NewComment { kind: "argument".into(), body: "Cheaper".into() }, None)
            .unwrap();
        w.ledger
            .repo
            .create(
                RecordDraft::new(RecordKind::Source, "Estimate")
                    .relation(RelationDraft::new(RelationKind::Cites, proposal.id.clone())),
                sys(),
            )
            .unwrap();

        let d = w.ledger.issue_detail(&Session::Anonymous, &id).unwrap();
        assert_eq!(d.evidence.iter().map(|r| r.id.clone()).collect::<Vec<_>>(), vec![kept.id]);
        assert_eq!(d.proposals.len(), 1);
        assert_eq!(d.proposals[0].comments.len(), 1);
        assert!(d.proposals[0].decisions.is_empty());
        assert!(
            d.activity.iter().any(|a| a.record_id == d.proposals[0].comments[0].id),
            "reply comments appear in the timeline"
        );
        assert!(d.activity.windows(2).all(|p| p[0].entry.recorded_at <= p[1].entry.recorded_at), "timeline is ordered");
        assert!(!d.activity.iter().any(|a| a.record_title == "Gazette"));
    }

    #[test]
    fn search_paging_and_filters() {
        let mut w = world();
        let ids: Vec<_> = (0..5).map(|_| issue(&mut w, None)).collect();
        let s = |w: &World, q: SearchQuery| {
            w.ledger.search(&Session::Anonymous, &q).unwrap().into_iter().map(|i| i.id).collect::<Vec<_>>()
        };
        assert_eq!(s(&w, SearchQuery { limit: Some(2), ..Default::default() }), vec![ids[4].clone(), ids[3].clone()]);
        assert_eq!(s(&w, SearchQuery { limit: Some(2), offset: Some(4), ..Default::default() }), vec![ids[0].clone()]);
        assert_eq!(
            s(&w, SearchQuery { limit: Some(10_000), ..Default::default() }).len(),
            5,
            "limit is capped, not an error"
        );
        assert_eq!(s(&w, SearchQuery { open_only: true, ..Default::default() }).len(), 5);
        assert_eq!(
            s(&w, SearchQuery { q: Some("block c".into()), ..Default::default() }).len(),
            5,
            "location text is searched"
        );
        assert!(s(&w, SearchQuery { q: Some("block z".into()), ..Default::default() }).is_empty());
        assert!(
            s(&w, SearchQuery { to: Some(NaiveDate::from_ymd_opt(2026, 6, 30).unwrap()), ..Default::default() })
                .is_empty()
        );
        assert_eq!(
            s(&w, SearchQuery { to: Some(NaiveDate::from_ymd_opt(2026, 7, 1).unwrap()), ..Default::default() }).len(),
            5
        );
        assert!(s(&w, SearchQuery { locality: Some("Ward 1".into()), ..Default::default() }).is_empty());
    }

    #[test]
    fn duplicate_suggestions() {
        let mut w = world();
        let id = issue(&mut w, None);
        let asha = w.asha.clone();
        assert!(w.ledger.suggest_duplicates(&asha, "a an to", "").unwrap().is_empty(), "nothing to compare");
        let s = w.ledger.suggest_duplicates(&asha, "Water supply missing in Block C", "").unwrap();
        assert_eq!(s[0].issue.id, id);
        assert!(s[0].score > 0.25 && s[0].score <= 1.0);
        assert!(w.ledger.suggest_duplicates(&asha, "Pothole on Ring Road", "").unwrap().is_empty());
        // Closed issues are not suggested.
        let moderator = w.moderator.clone();
        w.ledger
            .transition(
                &moderator,
                &id,
                TransitionRequest {
                    to: IssueStatus::NotActionable,
                    reason: Some("private land".into()),
                    expected_version: None,
                },
                None,
            )
            .unwrap();
        assert!(w.ledger.suggest_duplicates(&asha, "Water supply missing in Block C", "").unwrap().is_empty());
    }

    #[test]
    fn record_view_and_export_visibility() {
        let mut w = world();
        let id = issue(&mut w, None);
        let (record, timeline) = w.ledger.record(&Session::Anonymous, &id).unwrap();
        assert_eq!(record.id, id);
        assert_eq!(timeline.len(), 1);
        let ghost = RecordId::generate(&Origin::new("unit.test").unwrap());
        assert!(matches!(w.ledger.record(&Session::Anonymous, &ghost), Err(AppError::NotFound)));
        assert!(matches!(w.ledger.export_issue(&Session::Anonymous, &ghost), Err(AppError::NotFound)));
        let bundle = w.ledger.export_issue(&w.moderator.clone(), &id).unwrap();
        assert_eq!(bundle.completeness, pardarsh_core::interchange::Completeness::Complete);
    }

    #[test]
    fn institutions_list_only_institutions() {
        let w = world();
        let mut names: Vec<_> = w.ledger.institutions().unwrap().into_iter().map(|i| (i.handle, i.name)).collect();
        names.sort();
        assert_eq!(
            names,
            [
                ("city_water".to_string(), "City Water Board".to_string()),
                ("ward7_works".to_string(), "Ward 7 Public Works".to_string())
            ]
        );
    }
}
