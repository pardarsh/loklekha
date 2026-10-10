//! Loklekha's vocabulary, expressed as pardarsh-core extensions.
//!
//! Loklekha does not define its own record model: issues, evidence,
//! comments, proposals, decisions, actions, claims and outcomes are core
//! records. App-specific fields live in the `loklekha.*` extension namespaces
//! registered here, and app-specific events are tagged `loklekha:*`.

use pardarsh_core::extension::{ExtensionRegistry, ExtensionSchema, FieldSpec, FieldType};
use pardarsh_core::id::NamespacedName;
use pardarsh_core::model::RecordKind;
use pardarsh_core::relation::RelationKind;
use pardarsh_core::schema::SchemaVersion;

use crate::workflow::IssueStatus;

pub const V1: SchemaVersion = SchemaVersion::new(1, 0);

pub const ISSUE: &str = "loklekha.issue";
pub const COMMENT: &str = "loklekha.comment";
pub const DECISION: &str = "loklekha.decision";
pub const ACTION: &str = "loklekha.action";
pub const CLAIM: &str = "loklekha.claim";
pub const OUTCOME: &str = "loklekha.outcome";
pub const ACCOUNT: &str = "loklekha.account";
pub const REPORT: &str = "loklekha.report";

/// Audience that moderators hold.
pub const MODERATORS: &str = "moderators";

pub const CATEGORIES: &[&str] = &[
    "roads",
    "streetlights",
    "water",
    "sanitation",
    "waste",
    "drainage",
    "public_transport",
    "parks",
    "health",
    "education",
    "safety",
    "other",
];
pub const COMMENT_KINDS: &[&str] = &["question", "argument", "objection", "response", "review", "information_request"];
pub const VERDICTS: &[&str] = &["accepted", "rejected", "deferred", "redirected"];
pub const ACTION_PROGRESS: &[&str] = &["planned", "in_progress", "completed_claimed"];
pub const FINDINGS: &[&str] = &["problem_resolved", "problem_persists", "partially_resolved", "unclear"];
pub const REPORT_CATEGORIES: &[&str] = &["spam", "abuse", "personal_data", "misinformation", "off_topic", "other"];
pub const REPORT_STATES: &[&str] = &["open", "actioned", "dismissed"];

fn name(s: &str) -> NamespacedName {
    s.parse().expect("static name")
}

pub fn moderation_report_kind() -> RecordKind {
    RecordKind::Extension(name("loklekha:moderation_report"))
}

/// Extension relation from a moderation report to the record it flags.
pub fn flags_relation() -> RelationKind {
    RelationKind::Extension(name("loklekha:flags"))
}

pub fn status_change_tag() -> NamespacedName {
    name("loklekha:status_change")
}

pub fn moderation_tag() -> NamespacedName {
    name("loklekha:moderation")
}

pub fn moderation_note() -> NamespacedName {
    name("loklekha:moderation_note")
}

pub fn assignment_tag() -> NamespacedName {
    name("loklekha:assignment")
}

fn enumeration(values: &[&str]) -> FieldType {
    FieldType::Enum { values: values.iter().map(|s| s.to_string()).collect() }
}

pub fn registry() -> ExtensionRegistry {
    let statuses: Vec<&str> = IssueStatus::ALL.iter().map(|s| s.as_str()).collect();
    let mut r = ExtensionRegistry::new();
    let schemas = [
        ExtensionSchema::new(ISSUE, V1)
            .applies_to([RecordKind::Issue])
            .describe("Loklekha issue fields")
            .field(
                "status",
                FieldSpec::required(
                    enumeration(&statuses),
                    "administrative workflow status (a projection, not an outcome)",
                ),
            )
            .field("category", FieldSpec::required(enumeration(CATEGORIES), "issue category"))
            .field(
                "location_text",
                FieldSpec::optional(FieldType::Text { max_len: 200 }, "approximate location; never a home address"),
            )
            .field("locality", FieldSpec::optional(FieldType::Text { max_len: 100 }, "ward, village or neighbourhood"))
            .field(
                "affected_service",
                FieldSpec::optional(FieldType::Text { max_len: 200 }, "affected public service"),
            ),
        ExtensionSchema::new(COMMENT, V1)
            .applies_to([RecordKind::Comment])
            .field("kind", FieldSpec::required(enumeration(COMMENT_KINDS), "kind of contribution")),
        ExtensionSchema::new(DECISION, V1)
            .applies_to([RecordKind::Decision])
            .field("verdict", FieldSpec::required(enumeration(VERDICTS), "decision on a proposal")),
        ExtensionSchema::new(ACTION, V1)
            .applies_to([RecordKind::Action])
            .field("progress", FieldSpec::required(enumeration(ACTION_PROGRESS), "reported progress"))
            .field("due_date", FieldSpec::optional(FieldType::Date, "expected completion date")),
        ExtensionSchema::new(CLAIM, V1)
            .applies_to([RecordKind::Claim])
            .field("claim_type", FieldSpec::required(enumeration(&["completion", "other"]), "type of claim")),
        ExtensionSchema::new(OUTCOME, V1)
            .applies_to([RecordKind::Outcome])
            .field("finding", FieldSpec::required(enumeration(FINDINGS), "what the observer found")),
        ExtensionSchema::new(ACCOUNT, V1)
            .applies_to([RecordKind::Actor])
            .field("handle", FieldSpec::required(FieldType::Text { max_len: 40 }, "public handle"))
            .field("actor_type", FieldSpec::required(enumeration(&["person", "institution"]), "type of actor")),
        ExtensionSchema::new(REPORT, V1)
            .applies_to([moderation_report_kind()])
            .field("category", FieldSpec::required(enumeration(REPORT_CATEGORIES), "reason for the report"))
            .field("state", FieldSpec::required(enumeration(REPORT_STATES), "report handling state")),
    ];
    for s in schemas {
        r.register(s).expect("valid loklekha schema");
    }
    r
}
