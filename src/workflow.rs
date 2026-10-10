//! Issue status workflow and who may move an issue between states.
//!
//! The status is an *administrative* label derived from history. It records
//! what the responsible body or moderators said, not what is true in the
//! world: `resolved` means "the responsible body reports it resolved", and
//! observed outcomes are recorded separately (see `docs/product.md`).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueStatus {
    Submitted,
    NeedsTriage,
    Acknowledged,
    UnderReview,
    ActionPlanned,
    InProgress,
    Resolved,
    Duplicate,
    Redirected,
    NotActionable,
    Disputed,
    Reopened,
    ClosedWithoutResolution,
}

impl IssueStatus {
    pub const ALL: [IssueStatus; 13] = [
        Self::Submitted,
        Self::NeedsTriage,
        Self::Acknowledged,
        Self::UnderReview,
        Self::ActionPlanned,
        Self::InProgress,
        Self::Resolved,
        Self::Duplicate,
        Self::Redirected,
        Self::NotActionable,
        Self::Disputed,
        Self::Reopened,
        Self::ClosedWithoutResolution,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::NeedsTriage => "needs_triage",
            Self::Acknowledged => "acknowledged",
            Self::UnderReview => "under_review",
            Self::ActionPlanned => "action_planned",
            Self::InProgress => "in_progress",
            Self::Resolved => "resolved",
            Self::Duplicate => "duplicate",
            Self::Redirected => "redirected",
            Self::NotActionable => "not_actionable",
            Self::Disputed => "disputed",
            Self::Reopened => "reopened",
            Self::ClosedWithoutResolution => "closed_without_resolution",
        }
    }

    /// Plain-language label that does not overstate what the status means.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Submitted => "Submitted",
            Self::NeedsTriage => "Awaiting triage",
            Self::Acknowledged => "Acknowledged by responsible body",
            Self::UnderReview => "Under review",
            Self::ActionPlanned => "Action planned",
            Self::InProgress => "Work reported in progress",
            Self::Resolved => "Reported resolved (not independently verified)",
            Self::Duplicate => "Marked duplicate",
            Self::Redirected => "Redirected to another body",
            Self::NotActionable => "Marked not actionable",
            Self::Disputed => "Resolution disputed",
            Self::Reopened => "Reopened",
            Self::ClosedWithoutResolution => "Closed without resolution",
        }
    }

    /// Open issues are still expected to move.
    pub fn is_open(&self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::NeedsTriage
                | Self::Acknowledged
                | Self::UnderReview
                | Self::ActionPlanned
                | Self::InProgress
                | Self::Disputed
                | Self::Reopened
        )
    }

    /// Transitions into these states must carry a reason.
    pub fn requires_reason(&self) -> bool {
        matches!(
            self,
            Self::Resolved
                | Self::Duplicate
                | Self::Redirected
                | Self::NotActionable
                | Self::Disputed
                | Self::Reopened
                | Self::ClosedWithoutResolution
        )
    }
}

impl fmt::Display for IssueStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for IssueStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL.iter().copied().find(|x| x.as_str() == s).ok_or_else(|| format!("unknown status {s:?}"))
    }
}

/// Application roles. Permissions are app policy, not core concepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Any registered member of the public.
    Citizen,
    /// A member of a responsible institution.
    Responder,
    /// Triage and moderation.
    Moderator,
    Admin,
}

/// Who is asking to move an issue, relative to that issue.
#[derive(Clone, Copy, Debug)]
pub struct Actor {
    pub role: Role,
    /// The actor reported the issue.
    pub is_reporter: bool,
    /// The actor belongs to an institution the issue is assigned to.
    pub is_assigned_responder: bool,
}

/// Check a transition. Returns a human-readable refusal.
pub fn check_transition(from: IssueStatus, to: IssueStatus, who: Actor) -> Result<(), String> {
    use IssueStatus::*;
    if from == to {
        return Err(format!("issue is already {from}"));
    }
    let responder = who.role == Role::Responder && who.is_assigned_responder;
    let moderator = matches!(who.role, Role::Moderator | Role::Admin);
    let any_member = true;
    let reporter = who.is_reporter;

    let progress = [Submitted, NeedsTriage, Acknowledged, UnderReview, ActionPlanned, InProgress, Reopened, Disputed];
    let allowed = match (from, to) {
        (Submitted, NeedsTriage) => moderator,
        (Submitted | NeedsTriage | Reopened, Acknowledged) => responder || moderator,
        (NeedsTriage | Acknowledged | Reopened, UnderReview) => responder || moderator,
        (Acknowledged | UnderReview | Reopened, ActionPlanned) => responder,
        (Acknowledged | UnderReview | ActionPlanned | Reopened, InProgress) => responder,
        (ActionPlanned | InProgress | Disputed, Resolved) => responder,
        (f, Duplicate | Redirected | NotActionable | ClosedWithoutResolution) if progress.contains(&f) => {
            responder || moderator
        }
        // Anyone may dispute a reported resolution; disagreement is recorded, not adjudicated.
        (Resolved, Disputed) => any_member,
        (Resolved | Disputed | NotActionable | ClosedWithoutResolution | Redirected | Duplicate, Reopened) => {
            reporter || moderator || responder
        }
        (Reopened, NeedsTriage) => moderator,
        _ => return Err(format!("cannot move an issue from {from} to {to}")),
    };
    if allowed { Ok(()) } else { Err(format!("your role may not move this issue from {from} to {to}")) }
}

#[cfg(test)]
mod tests {
    use super::IssueStatus::*;
    use super::*;

    const CITIZEN: Actor = Actor { role: Role::Citizen, is_reporter: false, is_assigned_responder: false };
    const REPORTER: Actor = Actor { role: Role::Citizen, is_reporter: true, is_assigned_responder: false };
    const RESPONDER: Actor = Actor { role: Role::Responder, is_reporter: false, is_assigned_responder: true };
    const OTHER_RESPONDER: Actor = Actor { role: Role::Responder, is_reporter: false, is_assigned_responder: false };
    const MODERATOR: Actor = Actor { role: Role::Moderator, is_reporter: false, is_assigned_responder: false };
    const ADMIN: Actor = Actor { role: Role::Admin, is_reporter: false, is_assigned_responder: false };
    const EVERYONE: [Actor; 6] = [CITIZEN, REPORTER, RESPONDER, OTHER_RESPONDER, MODERATOR, ADMIN];

    #[test]
    fn happy_path() {
        let path = [Submitted, Acknowledged, UnderReview, ActionPlanned, InProgress, Resolved];
        for w in path.windows(2) {
            check_transition(w[0], w[1], RESPONDER).unwrap();
        }
    }

    #[test]
    fn citizens_cannot_resolve_or_triage() {
        assert!(check_transition(InProgress, Resolved, CITIZEN).is_err());
        assert!(check_transition(Submitted, Acknowledged, REPORTER).is_err());
        assert!(check_transition(Submitted, NeedsTriage, CITIZEN).is_err());
    }

    #[test]
    fn only_assigned_responders_act() {
        assert!(check_transition(Submitted, Acknowledged, OTHER_RESPONDER).is_err());
        assert!(check_transition(InProgress, Resolved, MODERATOR).is_err(), "moderators do not declare work done");
    }

    #[test]
    fn disputes_and_reopening() {
        check_transition(Resolved, Disputed, CITIZEN).unwrap();
        assert!(check_transition(Resolved, Reopened, CITIZEN).is_err());
        check_transition(Resolved, Reopened, REPORTER).unwrap();
        check_transition(Duplicate, Reopened, MODERATOR).unwrap();
        check_transition(Disputed, Resolved, RESPONDER).unwrap();
        check_transition(Resolved, Reopened, RESPONDER).unwrap();
        assert!(check_transition(Resolved, Reopened, OTHER_RESPONDER).is_err());
        assert!(check_transition(Submitted, Resolved, RESPONDER).is_err(), "no skipping straight to resolved");
    }

    #[test]
    fn display_parse_and_serde() {
        for s in IssueStatus::ALL {
            assert_eq!(s.as_str().parse::<IssueStatus>().unwrap(), s);
            assert_eq!(s.to_string(), s.as_str());
            assert_eq!(serde_json::to_value(s).unwrap(), serde_json::Value::String(s.as_str().into()));
            assert!(!s.label().is_empty());
        }
        assert!("Resolved".parse::<IssueStatus>().is_err());
        assert!("".parse::<IssueStatus>().is_err());
        assert_eq!(serde_json::from_value::<Role>("moderator".into()).unwrap(), Role::Moderator);
        assert!(serde_json::from_value::<Role>("superuser".into()).is_err());
    }

    #[test]
    fn labels_do_not_overclaim() {
        assert!(Resolved.label().contains("not independently verified"));
        assert!(InProgress.label().contains("reported"));
    }

    #[test]
    fn open_and_reason_sets() {
        let open: Vec<_> = IssueStatus::ALL.iter().filter(|s| s.is_open()).map(|s| s.as_str()).collect();
        assert_eq!(
            open,
            [
                "submitted",
                "needs_triage",
                "acknowledged",
                "under_review",
                "action_planned",
                "in_progress",
                "disputed",
                "reopened"
            ]
        );
        let reason: Vec<_> = IssueStatus::ALL.iter().filter(|s| s.requires_reason()).map(|s| s.as_str()).collect();
        assert_eq!(
            reason,
            [
                "resolved",
                "duplicate",
                "redirected",
                "not_actionable",
                "disputed",
                "reopened",
                "closed_without_resolution"
            ]
        );
    }

    #[test]
    fn nobody_stays_in_place_or_leaves_a_closed_state_except_by_reopening() {
        let closed = [Resolved, Duplicate, Redirected, NotActionable, ClosedWithoutResolution];
        for who in EVERYONE {
            for s in IssueStatus::ALL {
                assert!(check_transition(s, s, who).unwrap_err().contains("already"));
            }
            for from in closed {
                for to in IssueStatus::ALL {
                    if to != Reopened && !(from == Resolved && to == Disputed) {
                        assert!(check_transition(from, to, who).is_err(), "{from} -> {to}");
                    }
                }
            }
        }
    }

    #[test]
    fn nothing_returns_to_submitted() {
        for who in EVERYONE {
            for from in IssueStatus::ALL {
                assert!(check_transition(from, Submitted, who).is_err());
            }
        }
    }

    #[test]
    fn admin_matches_moderator_everywhere() {
        for from in IssueStatus::ALL {
            for to in IssueStatus::ALL {
                assert_eq!(
                    check_transition(from, to, ADMIN).is_ok(),
                    check_transition(from, to, MODERATOR).is_ok(),
                    "{from} -> {to}"
                );
            }
        }
    }

    #[test]
    fn citizens_can_only_dispute_and_reporters_can_also_reopen() {
        for from in IssueStatus::ALL {
            for to in IssueStatus::ALL {
                let citizen = check_transition(from, to, CITIZEN).is_ok();
                assert_eq!(citizen, from == Resolved && to == Disputed, "citizen {from} -> {to}");
                if check_transition(from, to, REPORTER).is_ok() {
                    assert!(to == Disputed || to == Reopened, "reporter {from} -> {to}");
                }
            }
        }
    }

    #[test]
    fn closing_transitions() {
        for from in [Submitted, NeedsTriage, Acknowledged, UnderReview, ActionPlanned, InProgress, Reopened, Disputed] {
            for to in [Duplicate, Redirected, NotActionable, ClosedWithoutResolution] {
                check_transition(from, to, RESPONDER).unwrap();
                check_transition(from, to, MODERATOR).unwrap();
                assert!(check_transition(from, to, CITIZEN).is_err());
                assert!(check_transition(from, to, REPORTER).is_err());
                assert!(check_transition(from, to, OTHER_RESPONDER).is_err());
            }
        }
    }

    #[test]
    fn triage_and_reopen_paths() {
        check_transition(Submitted, NeedsTriage, MODERATOR).unwrap();
        assert!(check_transition(Submitted, NeedsTriage, RESPONDER).is_err());
        check_transition(Reopened, NeedsTriage, MODERATOR).unwrap();
        assert!(check_transition(Reopened, NeedsTriage, REPORTER).is_err());
        for to in [Acknowledged, UnderReview] {
            check_transition(Reopened, to, MODERATOR).unwrap();
            check_transition(Reopened, to, RESPONDER).unwrap();
        }
        for to in [ActionPlanned, InProgress] {
            check_transition(Reopened, to, RESPONDER).unwrap();
            assert!(check_transition(Reopened, to, MODERATOR).is_err());
        }
        // Error messages distinguish impossible moves from missing permission.
        assert!(check_transition(Submitted, Resolved, ADMIN).unwrap_err().contains("cannot move"));
        assert!(check_transition(Submitted, NeedsTriage, CITIZEN).unwrap_err().contains("your role"));
    }
}
