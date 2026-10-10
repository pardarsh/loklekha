//! Browser UI: server-rendered pages (askama templates) with forms.
//!
//! Sign-in uses `axum-login` sessions; every form is protected by
//! `axum_csrf`. Pages call the same [`Ledger`] service as the JSON API, so
//! permissions, validation and privacy filtering are identical.

use std::collections::BTreeSet;
use std::sync::Arc;

use askama::Template;
use axum::extract::{DefaultBodyLimit, FromRef, Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router, middleware};
use axum_csrf::{CsrfConfig, CsrfToken};
use pardarsh_core::id::RecordId;
use pardarsh_core::model::{ActorRoleKind, Record, RecordKind, Timestamp};
use pardarsh_core::provenance::SourceRef;
use pardarsh_core::relation::{Certainty, RelationKind};
use pardarsh_core::storage::Store;
use serde::Deserialize;

use crate::api::{AppState, security_headers};
use crate::auth::{AuthSession, Credentials, safe_next};
use crate::error::AppError;
use crate::identity::Session;
use crate::service::*;
use crate::users::{MIN_PASSWORD_LEN, NewUser, UserStore};
use crate::vocab;
use crate::workflow::{IssueStatus, Role};

const CSS: &str = include_str!("../static/app.css");
const LOGO: &[u8] = include_bytes!("../static/images/logo.jpg");
/// Favicons are pre-rounded PNGs: CSS cannot round a browser tab icon.
const FAVICON: &[u8] = include_bytes!("../static/images/favicon.png");
const TOUCH_ICON: &[u8] = include_bytes!("../static/images/apple-touch-icon.png");
const FLASH_KEY: &str = "loklekha.flash";

/// State for the UI routes.
pub struct UiState<S: Store> {
    pub app: Arc<AppState<S>>,
    pub users: UserStore,
    pub csrf: CsrfConfig,
}

impl<S: Store> Clone for UiState<S> {
    fn clone(&self) -> Self {
        Self { app: self.app.clone(), users: self.users.clone(), csrf: self.csrf.clone() }
    }
}

impl<S: Store> FromRef<UiState<S>> for CsrfConfig {
    fn from_ref(state: &UiState<S>) -> Self {
        state.csrf.clone()
    }
}

type St<S> = State<UiState<S>>;

pub fn router<S: Store + 'static>(state: UiState<S>) -> Router {
    Router::new()
        .route("/", get(issues_page::<S>))
        .route("/issues", get(issues_page::<S>))
        .route("/issues/new", get(new_issue_page::<S>).post(create_issue::<S>))
        .route("/issues/{id}", get(issue_page::<S>))
        .route("/issues/{id}/comments", post(post_comment::<S>))
        .route("/issues/{id}/evidence", post(post_evidence::<S>))
        .route("/issues/{id}/proposals", post(post_proposal::<S>))
        .route("/issues/{id}/outcomes", post(post_outcome::<S>))
        .route("/issues/{id}/reports", post(post_report::<S>))
        .route("/issues/{id}/status", post(post_status::<S>))
        .route("/login", get(login_page).post(login::<S>))
        .route("/signup", get(signup_page).post(signup::<S>))
        .route("/logout", post(logout))
        .route("/about", get(about_page))
        .route("/static/app.css", get(stylesheet))
        .route("/static/images/logo.jpg", get(logo))
        .route("/static/images/favicon.png", get(favicon))
        .route("/static/images/apple-touch-icon.png", get(touch_icon))
        .route("/favicon.ico", get(favicon))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

// ---- shared page parts -------------------------------------------------------

pub struct Flash {
    pub message: String,
    pub error: bool,
}

pub struct NavUser {
    pub handle: String,
    pub role: &'static str,
}

/// Header data every page needs.
#[derive(Default)]
pub struct Nav {
    pub user: Option<NavUser>,
    pub csrf: String,
    pub q: String,
    pub flash: Option<Flash>,
}

fn role_label(role: Role) -> &'static str {
    match role {
        Role::Citizen => "member",
        Role::Responder => "responder",
        Role::Moderator => "moderator",
        Role::Admin => "admin",
    }
}

async fn nav(auth: &AuthSession, token: &CsrfToken, q: &str) -> Nav {
    let flash = auth
        .session
        .remove::<(String, bool)>(FLASH_KEY)
        .await
        .ok()
        .flatten()
        .map(|(message, error)| Flash { message, error });
    Nav {
        user: auth.user.as_ref().map(|u| NavUser { handle: u.handle.clone(), role: role_label(u.role) }),
        csrf: token.authenticity_token().unwrap_or_default(),
        q: q.to_string(),
        flash,
    }
}

async fn flash(auth: &AuthSession, message: impl Into<String>, error: bool) {
    let _ = auth.session.insert(FLASH_KEY, (message.into(), error)).await;
}

fn session_of(auth: &AuthSession) -> Session {
    auth.user.as_ref().map_or(Session::Anonymous, |u| Session::User(u.account()))
}

/// Percent-encode a query value or path segment.
pub fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

pub fn issue_url(id: &RecordId) -> String {
    format!("/issues/{}", enc(&id.to_string()))
}

/// Short, readable reference for an issue (last 7 hex digits of its id).
pub fn short_id(id: &RecordId) -> String {
    let s = id.local().simple().to_string();
    s[s.len() - 7..].to_string()
}

fn date(t: &Timestamp) -> String {
    t.format("%b %-d, %Y").to_string()
}

fn when(t: &Timestamp) -> String {
    t.format("%b %-d, %Y %H:%M UTC").to_string()
}

fn pretty(value: &str) -> String {
    let s = value.replace('_', " ");
    let mut c = s.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
}

pub struct Choice {
    pub value: String,
    pub label: String,
    pub selected: bool,
}

fn choices(values: &[&str], selected: Option<&str>) -> Vec<Choice> {
    values.iter().map(|v| Choice { value: v.to_string(), label: pretty(v), selected: selected == Some(*v) }).collect()
}

fn render(t: &impl Template) -> Result<Html<String>, UiError> {
    t.render().map(Html).map_err(|e| UiError::Internal(e.to_string()))
}

/// Errors shown as an HTML page.
#[derive(Debug)]
pub enum UiError {
    App(AppError),
    Internal(String),
}

impl From<AppError> for UiError {
    fn from(e: AppError) -> Self {
        UiError::App(e)
    }
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage {
    nav: Nav,
    heading: String,
    message: String,
}

impl IntoResponse for UiError {
    fn into_response(self) -> Response {
        let (status, heading, message) = match &self {
            UiError::App(AppError::NotFound) | UiError::App(AppError::Core(pardarsh_core::Error::NotFound(_))) => (
                StatusCode::NOT_FOUND,
                "Not found",
                "This page does not exist, or you do not have access to it.".to_string(),
            ),
            UiError::App(AppError::Forbidden(m)) => (StatusCode::FORBIDDEN, "Not allowed", m.clone()),
            UiError::App(AppError::Unauthorized) => {
                (StatusCode::UNAUTHORIZED, "Sign in required", "Please sign in.".into())
            }
            UiError::App(AppError::BadRequest(m)) => (StatusCode::BAD_REQUEST, "Bad request", m.clone()),
            UiError::App(AppError::RateLimited) => (
                StatusCode::TOO_MANY_REQUESTS,
                "Slow down",
                "Too many changes in a short time. Try again in a minute.".into(),
            ),
            other => {
                eprintln!("ui error: {other:?}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong", "Please try again later.".into())
            }
        };
        let page = ErrorPage { nav: Nav::default(), heading: heading.into(), message };
        let body = page.render().unwrap_or_else(|_| heading.to_string());
        (status, Html(body)).into_response()
    }
}

/// A user-facing message for a failed action.
fn describe(e: &AppError) -> String {
    match e {
        AppError::Core(pardarsh_core::Error::Validation(v)) => {
            let parts: Vec<String> = v.issues.iter().map(|i| format!("{}: {}", i.path, i.message)).collect();
            format!("Please check the form. {}", parts.join("; "))
        }
        AppError::Core(pardarsh_core::Error::Conflict { .. }) => {
            "Someone else changed this issue while you were looking at it. Review the latest version and try again."
                .into()
        }
        AppError::RateLimited => "Too many changes in a short time. Try again in a minute.".into(),
        AppError::Unauthorized => "Please sign in.".into(),
        AppError::NotFound | AppError::Core(pardarsh_core::Error::NotFound(_)) => {
            "That record is not available.".into()
        }
        AppError::Forbidden(m) | AppError::BadRequest(m) => {
            let mut m = m.clone();
            if let Some(f) = m.get_mut(0..1) {
                f.make_ascii_uppercase();
            }
            m
        }
        other => {
            eprintln!("ui action error: {other:?}");
            "Something went wrong. Please try again.".into()
        }
    }
}

fn opt(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn login_redirect(next: &str) -> Response {
    Redirect::to(&format!("/login?next={}", enc(next))).into_response()
}

async fn logo() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "image/jpeg"), (header::CACHE_CONTROL, "public, max-age=86400")], LOGO)
}

/// Also answers `/favicon.ico`, which browsers request on their own.
async fn favicon() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "image/png"), (header::CACHE_CONTROL, "public, max-age=86400")], FAVICON)
}

async fn touch_icon() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "image/png"), (header::CACHE_CONTROL, "public, max-age=86400")], TOUCH_ICON)
}

async fn stylesheet() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8"), (header::CACHE_CONTROL, "public, max-age=3600")], CSS)
}

// ---- issue list ------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct ListQuery {
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    locality: Option<String>,
}

pub struct Row {
    pub url: String,
    pub title: String,
    pub open: bool,
    pub status_label: &'static str,
    pub category: String,
    pub locality: Option<String>,
    pub short_id: String,
    pub opened: String,
    pub hidden: bool,
}

#[derive(Template)]
#[template(path = "issues.html")]
struct IssuesPage {
    nav: Nav,
    rows: Vec<Row>,
    state: String,
    open_count: usize,
    closed_count: usize,
    open_url: String,
    closed_url: String,
    categories: Vec<Choice>,
    statuses: Vec<Choice>,
    locality: String,
}

async fn issues_page<S: Store + 'static>(
    State(st): St<S>,
    auth: AuthSession,
    token: CsrfToken,
    Query(q): Query<ListQuery>,
) -> Result<Response, UiError> {
    let session = session_of(&auth);
    let text = opt(q.q.clone()).unwrap_or_default();
    let category = opt(q.category.clone()).filter(|c| vocab::CATEGORIES.contains(&c.as_str()));
    let status = opt(q.status.clone()).and_then(|s| s.parse::<IssueStatus>().ok());
    let locality = opt(q.locality.clone());
    let state = if q.state.as_deref() == Some("closed") { "closed" } else { "open" };
    let search = SearchQuery {
        q: opt(q.q),
        status,
        category: category.clone(),
        locality: locality.clone(),
        limit: Some(200),
        ..Default::default()
    };
    let all = st.app.ledger().search(&session, &search)?;
    let (open, closed): (Vec<_>, Vec<_>) = all.into_iter().partition(|i| i.status.is_open());
    let (open_count, closed_count) = (open.len(), closed.len());
    let selected = if state == "open" { open } else { closed };
    let rows = selected
        .into_iter()
        .map(|i| Row {
            url: issue_url(&i.id),
            short_id: short_id(&i.id),
            opened: date(&i.recorded_at),
            open: i.status.is_open(),
            status_label: i.status.label(),
            category: pretty(&i.category),
            locality: i.locality,
            hidden: i.hidden,
            title: i.title,
        })
        .collect();
    let filters = |state: &str| {
        let mut parts = vec![format!("state={state}")];
        for (k, v) in [("q", Some(text.clone())), ("category", category.clone()), ("locality", locality.clone())] {
            if let Some(v) = v.filter(|v| !v.is_empty()) {
                parts.push(format!("{k}={}", enc(&v)));
            }
        }
        if let Some(s) = status {
            parts.push(format!("status={}", s.as_str()));
        }
        format!("/issues?{}", parts.join("&"))
    };
    let statuses: Vec<&str> = IssueStatus::ALL.iter().map(|s| s.as_str()).collect();
    let page = IssuesPage {
        nav: nav(&auth, &token, &text).await,
        rows,
        state: state.into(),
        open_count,
        closed_count,
        open_url: filters("open"),
        closed_url: filters("closed"),
        categories: choices(vocab::CATEGORIES, category.as_deref()),
        statuses: IssueStatus::ALL
            .iter()
            .zip(statuses)
            .map(|(s, v)| Choice { value: v.into(), label: s.label().into(), selected: status == Some(*s) })
            .collect(),
        locality: locality.unwrap_or_default(),
    };
    Ok((token, render(&page)?).into_response())
}

// ---- issue page ---------------------------------------------------------------------

pub struct LinkView {
    pub url: String,
    pub label: String,
    pub web: bool,
    pub note: String,
}

fn links(sources: &[SourceRef]) -> Vec<LinkView> {
    sources
        .iter()
        .map(|s| {
            let lower = s.locator.to_ascii_lowercase();
            LinkView {
                web: lower.starts_with("https://") || lower.starts_with("http://"),
                url: s.locator.clone(),
                label: s.title.clone().unwrap_or_else(|| s.locator.clone()),
                note: pretty(
                    &format!("{:?}", s.authority)
                        .to_lowercase()
                        .replace("thirdparty", "third_party")
                        .replace("usersubmitted", "user_submitted"),
                ),
            }
        })
        .collect()
}

/// One entry in the conversation: a card (a record) or a small event row.
pub struct Item {
    pub card: bool,
    pub nested: bool,
    pub anchor: String,
    pub actor: String,
    pub verb: String,
    pub label: String,
    pub when: String,
    pub title: String,
    pub show_title: bool,
    pub body: Option<String>,
    pub links: Vec<LinkView>,
    pub reason: Option<String>,
}

impl Item {
    fn event(actor: String, verb: String, at: &Timestamp, reason: Option<String>) -> Self {
        Item {
            card: false,
            nested: false,
            anchor: String::new(),
            actor,
            verb,
            label: String::new(),
            when: when(at),
            title: String::new(),
            show_title: false,
            body: None,
            links: Vec::new(),
            reason,
        }
    }
}

pub struct ResponsibleView {
    pub name: String,
    pub certainty: &'static str,
}

pub struct DetailView {
    pub label: &'static str,
    pub value: String,
}

pub struct RelatedView {
    pub url: String,
    pub title: String,
    pub note: &'static str,
}

#[derive(Template)]
#[template(path = "issue.html")]
struct IssuePage {
    nav: Nav,
    id: String,
    id_encoded: String,
    url: String,
    url_encoded: String,
    title: String,
    short_id: String,
    open: bool,
    status_label: &'static str,
    status_notice: &'static str,
    reporter: String,
    opened: String,
    body: Option<String>,
    sources: Vec<LinkView>,
    items: Vec<Item>,
    version: u64,
    transitions: Vec<Choice>,
    responsible: Vec<ResponsibleView>,
    category: String,
    details: Vec<DetailView>,
    related: Vec<RelatedView>,
    participants: Vec<String>,
    can_contribute: bool,
    comment_kinds: Vec<Choice>,
    findings: Vec<Choice>,
    report_categories: Vec<Choice>,
}

fn certainty_label(c: Certainty) -> &'static str {
    match c {
        Certainty::Unverified => "unverified",
        Certainty::Asserted => "asserted",
        Certainty::Sourced => "sourced",
        Certainty::Disputed => "disputed",
    }
}

fn ext(r: &Record, ns: &str, field: &str) -> Option<String> {
    r.extension_field(ns, field).map(|v| v.display())
}

/// The person who wrote a record (author, contributor or reporter role first).
fn author<S: Store>(ledger: &Ledger<S>, r: &Record) -> String {
    let preferred = [ActorRoleKind::Author, ActorRoleKind::Contributor, ActorRoleKind::Reporter];
    r.actors
        .iter()
        .find(|a| preferred.contains(&a.role))
        .or_else(|| r.actors.first())
        .map(|a| ledger.display_actor(&a.attribution))
        .unwrap_or_else(|| "someone".into())
}

fn card<S: Store>(ledger: &Ledger<S>, r: &Record, verb: &str, label: String, nested: bool) -> Item {
    let body = r.body.clone().filter(|b| b.trim() != r.title.trim());
    Item {
        card: true,
        nested,
        anchor: short_id(&r.id),
        actor: author(ledger, r),
        verb: verb.into(),
        label,
        when: when(&r.times.recorded_at),
        show_title: !matches!(r.kind, RecordKind::Comment | RecordKind::Claim) || body.is_none(),
        title: r.title.clone(),
        body,
        links: links(&r.sources),
        reason: None,
    }
}

/// Title of a record if the viewer may see it.
fn visible_title<S: Store>(ledger: &Ledger<S>, session: &Session, id: &RecordId) -> String {
    ledger.record(session, id).map(|(r, _)| format!("“{}”", r.title)).unwrap_or_else(|_| "a record".into())
}

fn issue_items<S: Store>(ledger: &Ledger<S>, session: &Session, d: &IssueDetail) -> Vec<Item> {
    let mut groups: Vec<(Timestamp, Vec<Item>)> = Vec::new();
    for r in &d.evidence {
        let contradicts = r.active_relations().any(|x| x.kind == RelationKind::Contradicts);
        let label = if contradicts { "contradicting evidence" } else { "evidence" };
        groups.push((r.times.recorded_at, vec![card(ledger, r, "added", label.into(), false)]));
    }
    for r in &d.comments {
        let kind = ext(r, vocab::COMMENT, "kind").unwrap_or_else(|| "comment".into());
        groups.push((r.times.recorded_at, vec![card(ledger, r, "commented", pretty(&kind).to_lowercase(), false)]));
    }
    for p in &d.proposals {
        let mut items = vec![card(ledger, &p.proposal, "proposed", "proposal".into(), false)];
        let mut children: Vec<(Timestamp, Item)> = p
            .decisions
            .iter()
            .map(|dec| {
                let verdict = ext(dec, vocab::DECISION, "verdict").unwrap_or_default();
                (dec.times.recorded_at, card(ledger, dec, "decided", format!("decision: {verdict}"), true))
            })
            .chain(p.comments.iter().map(|c| {
                let kind = ext(c, vocab::COMMENT, "kind").unwrap_or_else(|| "comment".into());
                (c.times.recorded_at, card(ledger, c, "replied", pretty(&kind).to_lowercase(), true))
            }))
            .collect();
        children.sort_by_key(|(t, _)| *t);
        items.extend(children.into_iter().map(|(_, i)| i));
        groups.push((p.proposal.times.recorded_at, items));
    }
    for r in &d.actions {
        let progress = ext(r, vocab::ACTION, "progress").unwrap_or_default();
        let mut item = card(ledger, r, "planned", format!("action · {}", pretty(&progress).to_lowercase()), false);
        if let Some(due) = ext(r, vocab::ACTION, "due_date") {
            item.body = Some(format!("{}Due {due}", item.body.map(|b| b + "\n").unwrap_or_default()));
        }
        groups.push((r.times.recorded_at, vec![item]));
    }
    for r in &d.completion_claims {
        groups.push((r.times.recorded_at, vec![card(ledger, r, "claimed", "completion claim".into(), false)]));
    }
    for r in &d.outcomes {
        let finding = ext(r, vocab::OUTCOME, "finding").unwrap_or_default();
        let label = format!("observation · {}", pretty(&finding).to_lowercase());
        groups.push((r.times.recorded_at, vec![card(ledger, r, "observed", label, false)]));
    }
    for a in &d.activity {
        let e = &a.entry;
        let at = e.recorded_at;
        let verb = if a.record_id == d.issue.id {
            issue_event(ledger, session, &e.event, e.tag.as_ref().map(|t| t.to_string()).as_deref(), &e.changes)
        } else if e.event == "amended" {
            e.changes.iter().find(|c| c.field == "loklekha.action.progress").map(|c| {
                format!(
                    "updated {} to {}",
                    format_args!("“{}”", a.record_title),
                    pretty(c.after.as_deref().unwrap_or("")).to_lowercase()
                )
            })
        } else {
            None
        };
        // Confirming a suggested assignment is shown once, as "assigned".
        let confirmation = e.event == "relation_retracted" && e.reason.as_deref() == Some(CONFIRMATION_REASON);
        if let Some(verb) = verb.filter(|_| !confirmation) {
            groups.push((at, vec![Item::event(a.actor.clone(), verb, &at, e.reason.clone())]));
        }
    }
    groups.sort_by_key(|(t, _)| *t);
    groups.into_iter().flat_map(|(_, items)| items).collect()
}

fn issue_event<S: Store>(
    ledger: &Ledger<S>,
    session: &Session,
    event: &str,
    tag: Option<&str>,
    changes: &[pardarsh_core::projection::FieldDiff],
) -> Option<String> {
    let status_label = |v: Option<&String>| {
        v.and_then(|s| s.parse::<IssueStatus>().ok()).map(|s| s.label().to_string()).unwrap_or_else(|| "unknown".into())
    };
    let relation = |text: &str| -> (String, String) {
        let (kind, target) = text.split_once(' ').unwrap_or((text, ""));
        let name = target.parse::<RecordId>().map(|id| visible_title(ledger, session, &id)).unwrap_or_default();
        (kind.to_string(), name)
    };
    match event {
        "created" => None,
        _ if tag == Some("loklekha:status_change") => {
            let c = changes.iter().find(|c| c.field == "loklekha.issue.status")?;
            Some(format!(
                "changed the status from {} to {}",
                status_label(c.before.as_ref()),
                status_label(c.after.as_ref())
            ))
        }
        "relation_added" => {
            let c = changes.iter().find(|c| c.field == "relations" && c.before.is_none())?;
            let (kind, name) = relation(c.after.as_deref()?);
            Some(match kind.as_str() {
                "assigned_to" => format!("assigned {name}"),
                "duplicates" => format!("marked this as a duplicate of {name}"),
                "related_to" => format!("linked this to {name}"),
                other => format!("added a {} link to {name}", pretty(other).to_lowercase()),
            })
        }
        "relation_retracted" => {
            let c = changes.iter().find(|c| c.field == "relations")?;
            let (kind, name) = relation(c.before.as_deref()?);
            Some(match kind.as_str() {
                "assigned_to" => format!("removed the assignment to {name}"),
                other => format!("removed a {} link to {name}", pretty(other).to_lowercase()),
            })
        }
        "redacted" => Some("redacted some content".into()),
        "annotated" => Some("added a moderation note".into()),
        "retracted" => Some("retracted this issue".into()),
        "superseded" => Some("marked this issue as superseded".into()),
        "amended" | "corrected" => {
            if let Some(v) = changes.iter().find(|c| c.field == "visibility") {
                return Some(if v.after.as_deref() == Some("public") {
                    "made this issue public again".into()
                } else {
                    "hid this issue".into()
                });
            }
            let fields: BTreeSet<&str> =
                changes.iter().map(|c| c.field.rsplit('.').next().unwrap_or(&c.field)).collect();
            let verb = if event == "corrected" { "corrected" } else { "edited" };
            Some(format!("{verb} {}", fields.into_iter().collect::<Vec<_>>().join(", ").replace('_', " ")))
        }
        _ => None,
    }
}

async fn issue_page<S: Store + 'static>(
    State(st): St<S>,
    auth: AuthSession,
    token: CsrfToken,
    Path(raw): Path<String>,
) -> Result<Response, UiError> {
    let id: RecordId = raw.parse().map_err(|_| AppError::NotFound)?;
    let session = session_of(&auth);
    let page = {
        let ledger = st.app.ledger();
        let d = ledger.issue_detail(&session, &id)?;
        let transitions = ledger.allowed_transitions(&session, &id)?;
        let items = issue_items(&ledger, &session, &d);
        let mut participants: Vec<String> = Vec::new();
        for a in &d.activity {
            if !a.actor.starts_with("system (") && !participants.contains(&a.actor) {
                participants.push(a.actor.clone());
            }
        }
        let i = &d.issue;
        let details = [
            ("Location", ext(i, vocab::ISSUE, "location_text")),
            ("Locality", ext(i, vocab::ISSUE, "locality")),
            ("Affected service", ext(i, vocab::ISSUE, "affected_service")),
        ]
        .into_iter()
        .filter_map(|(label, v)| v.map(|value| DetailView { label, value }))
        .collect();
        let related = d
            .related
            .iter()
            .map(|r| RelatedView {
                url: issue_url(&r.id),
                title: r.title.clone(),
                note: match (&r.relation, r.direction) {
                    (RelationKind::Duplicates, "outgoing") => "this is a duplicate of it",
                    (RelationKind::Duplicates, _) => "duplicate of this",
                    _ => "related",
                },
            })
            .collect();
        let responder_or_mod = session.account().is_some_and(|a| a.role != Role::Citizen);
        let mut kinds = vec!["question", "argument", "objection", "information_request"];
        if responder_or_mod {
            kinds.insert(0, "response");
        }
        let url = issue_url(&id);
        IssuePage {
            id: id.to_string(),
            id_encoded: enc(&id.to_string()),
            url_encoded: enc(&url),
            url,
            title: i.title.clone(),
            short_id: short_id(&id),
            open: d.summary.status.is_open(),
            status_label: d.summary.status_label,
            status_notice: d.status_notice,
            reporter: d.reporter.clone().unwrap_or_else(|| "someone".into()),
            opened: date(&i.times.recorded_at),
            body: i.body.clone(),
            sources: links(&i.sources),
            items,
            version: i.version,
            transitions: transitions
                .into_iter()
                .map(|s| Choice { value: s.as_str().into(), label: s.label().into(), selected: false })
                .collect(),
            responsible: d
                .responsible
                .iter()
                .map(|r| ResponsibleView { name: r.name.clone(), certainty: certainty_label(r.certainty) })
                .collect(),
            category: pretty(&d.summary.category),
            details,
            related,
            participants,
            can_contribute: session.account().is_some() && i.lifecycle == pardarsh_core::model::Lifecycle::Active,
            comment_kinds: choices(&kinds, None),
            findings: choices(vocab::FINDINGS, None),
            report_categories: choices(vocab::REPORT_CATEGORIES, None),
            nav: Nav::default(),
        }
    };
    let page = IssuePage { nav: nav(&auth, &token, "").await, ..page };
    Ok((token, render(&page)?).into_response())
}

// ---- issue actions (forms) --------------------------------------------------------------

/// Common steps for a form post on an issue: CSRF, sign-in, rate limit,
/// then run the action and redirect back with a message.
async fn act<S: Store + 'static>(
    st: &UiState<S>,
    auth: &AuthSession,
    token: &CsrfToken,
    form_token: &str,
    raw_id: &str,
    success: &str,
    action: impl FnOnce(&mut Ledger<S>, &Session, &RecordId) -> Result<(), AppError>,
) -> Response {
    let Ok(id) = raw_id.parse::<RecordId>() else { return UiError::App(AppError::NotFound).into_response() };
    let url = issue_url(&id);
    let Some(user) = auth.user.as_ref() else { return login_redirect(&url) };
    if token.verify(form_token).is_err() {
        flash(auth, "Your form expired. Please try again.", true).await;
        return Redirect::to(&url).into_response();
    }
    let session = Session::User(user.account());
    let result = st.app.rate_limit(&user.handle).and_then(|_| {
        let mut ledger = st.app.ledger();
        action(&mut ledger, &session, &id)
    });
    match result {
        Ok(()) => flash(auth, success, false).await,
        Err(e) => flash(auth, describe(&e), true).await,
    }
    Redirect::to(&url).into_response()
}

#[derive(Deserialize)]
pub struct CommentForm {
    authenticity_token: String,
    body: String,
    kind: String,
}

async fn post_comment<S: Store + 'static>(
    State(st): St<S>,
    auth: AuthSession,
    token: CsrfToken,
    Path(raw): Path<String>,
    Form(f): Form<CommentForm>,
) -> Response {
    act(&st, &auth, &token, &f.authenticity_token, &raw, "Comment added.", |l, s, id| {
        l.comment(s, id, NewComment { kind: f.kind, body: f.body }, None).map(|_| ())
    })
    .await
}

#[derive(Deserialize)]
pub struct EvidenceForm {
    authenticity_token: String,
    title: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    relation: Option<String>,
    #[serde(default)]
    private: Option<String>,
}

async fn post_evidence<S: Store + 'static>(
    State(st): St<S>,
    auth: AuthSession,
    token: CsrfToken,
    Path(raw): Path<String>,
    Form(f): Form<EvidenceForm>,
) -> Response {
    act(&st, &auth, &token, &f.authenticity_token, &raw, "Evidence added.", |l, s, id| {
        let input = NewEvidence {
            title: f.title,
            description: opt(f.description),
            url: opt(f.url),
            observed_at: None,
            private: f.private.is_some(),
            relation: opt(f.relation),
        };
        l.add_evidence(s, id, input, None).map(|_| ())
    })
    .await
}

#[derive(Deserialize)]
pub struct ProposalForm {
    authenticity_token: String,
    title: String,
    #[serde(default)]
    body: Option<String>,
}

async fn post_proposal<S: Store + 'static>(
    State(st): St<S>,
    auth: AuthSession,
    token: CsrfToken,
    Path(raw): Path<String>,
    Form(f): Form<ProposalForm>,
) -> Response {
    act(&st, &auth, &token, &f.authenticity_token, &raw, "Proposal added.", |l, s, id| {
        l.propose(s, id, NewProposal { title: f.title, body: opt(f.body) }, None).map(|_| ())
    })
    .await
}

#[derive(Deserialize)]
pub struct OutcomeForm {
    authenticity_token: String,
    title: String,
    finding: String,
    #[serde(default)]
    evidence_url: Option<String>,
}

async fn post_outcome<S: Store + 'static>(
    State(st): St<S>,
    auth: AuthSession,
    token: CsrfToken,
    Path(raw): Path<String>,
    Form(f): Form<OutcomeForm>,
) -> Response {
    act(&st, &auth, &token, &f.authenticity_token, &raw, "Observation recorded.", |l, s, id| {
        let input = NewOutcome {
            title: f.title,
            finding: f.finding,
            body: None,
            observed_at: None,
            evidence_url: opt(f.evidence_url),
        };
        l.record_outcome(s, id, input, None).map(|_| ())
    })
    .await
}

#[derive(Deserialize)]
pub struct ReportForm {
    authenticity_token: String,
    category: String,
    #[serde(default)]
    details: Option<String>,
}

async fn post_report<S: Store + 'static>(
    State(st): St<S>,
    auth: AuthSession,
    token: CsrfToken,
    Path(raw): Path<String>,
    Form(f): Form<ReportForm>,
) -> Response {
    act(&st, &auth, &token, &f.authenticity_token, &raw, "Thanks. Moderators will review your report.", |l, s, id| {
        l.report(s, id, NewReport { category: f.category, details: opt(f.details) }, None).map(|_| ())
    })
    .await
}

#[derive(Deserialize)]
pub struct StatusForm {
    authenticity_token: String,
    to: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    expected_version: Option<String>,
}

async fn post_status<S: Store + 'static>(
    State(st): St<S>,
    auth: AuthSession,
    token: CsrfToken,
    Path(raw): Path<String>,
    Form(f): Form<StatusForm>,
) -> Response {
    act(&st, &auth, &token, &f.authenticity_token, &raw, "Status changed.", |l, s, id| {
        let to = f.to.parse::<IssueStatus>().map_err(AppError::BadRequest)?;
        let expected_version = opt(f.expected_version).and_then(|v| v.parse().ok());
        l.transition(s, id, TransitionRequest { to, reason: opt(f.reason), expected_version }, None).map(|_| ())
    })
    .await
}

// ---- new issue --------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct NewIssueForm {
    #[serde(default)]
    authenticity_token: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    location_text: String,
    #[serde(default)]
    locality: String,
    #[serde(default)]
    affected_service: String,
    #[serde(default)]
    institution: String,
    #[serde(default)]
    source_url: String,
    #[serde(default)]
    source_private: Option<String>,
    #[serde(default)]
    withhold_identity: Option<String>,
}

pub struct NewIssueValues {
    pub title: String,
    pub description: String,
    pub location_text: String,
    pub locality: String,
    pub affected_service: String,
    pub source_url: String,
    pub source_private: bool,
    pub withhold_identity: bool,
}

#[derive(Template)]
#[template(path = "new_issue.html")]
struct NewIssuePage {
    nav: Nav,
    form: NewIssueValues,
    categories: Vec<Choice>,
    institutions: Vec<Choice>,
}

fn new_issue_view<S: Store>(st: &UiState<S>, nav: Nav, f: &NewIssueForm) -> Result<NewIssuePage, UiError> {
    let institutions = st
        .app
        .ledger()
        .institutions()?
        .into_iter()
        .map(|i| Choice { selected: f.institution == i.id.to_string(), value: i.id.to_string(), label: i.name })
        .collect();
    Ok(NewIssuePage {
        nav,
        categories: choices(vocab::CATEGORIES, Some(f.category.as_str()).filter(|c| !c.is_empty())),
        institutions,
        form: NewIssueValues {
            title: f.title.clone(),
            description: f.description.clone(),
            location_text: f.location_text.clone(),
            locality: f.locality.clone(),
            affected_service: f.affected_service.clone(),
            source_url: f.source_url.clone(),
            source_private: f.source_private.is_some(),
            withhold_identity: f.withhold_identity.is_some(),
        },
    })
}

async fn new_issue_page<S: Store + 'static>(
    State(st): St<S>,
    auth: AuthSession,
    token: CsrfToken,
) -> Result<Response, UiError> {
    if auth.user.is_none() {
        return Ok(login_redirect("/issues/new"));
    }
    let page = new_issue_view(&st, nav(&auth, &token, "").await, &NewIssueForm::default())?;
    Ok((token, render(&page)?).into_response())
}

async fn create_issue<S: Store + 'static>(
    State(st): St<S>,
    auth: AuthSession,
    token: CsrfToken,
    Form(f): Form<NewIssueForm>,
) -> Result<Response, UiError> {
    let Some(user) = auth.user.clone() else { return Ok(login_redirect("/issues/new")) };
    let rerender = |message: String, f: &NewIssueForm, nav: Nav| -> Result<Response, UiError> {
        let mut page = new_issue_view(&st, nav, f)?;
        page.nav.flash = Some(Flash { message, error: true });
        Ok((StatusCode::UNPROCESSABLE_ENTITY, render(&page)?).into_response())
    };
    if token.verify(&f.authenticity_token).is_err() {
        let nav = nav(&auth, &token, "").await;
        return rerender("Your form expired. Please submit it again.".into(), &f, nav)
            .map(|r| (token, r).into_response());
    }
    let institution = if f.institution.trim().is_empty() {
        None
    } else {
        match f.institution.parse::<RecordId>() {
            Ok(id) => Some(id),
            Err(_) => {
                let nav = nav(&auth, &token, "").await;
                return rerender("Choose a responsible body from the list.".into(), &f, nav)
                    .map(|r| (token, r).into_response());
            }
        }
    };
    let source_url = f.source_url.trim().to_string();
    let input = NewIssue {
        title: f.title.trim().to_string(),
        description: opt(Some(f.description.clone())),
        category: f.category.clone(),
        location_text: opt(Some(f.location_text.clone())),
        locality: opt(Some(f.locality.clone())),
        affected_service: opt(Some(f.affected_service.clone())),
        responsible_institution: institution,
        withhold_identity: f.withhold_identity.is_some(),
        sources: if source_url.is_empty() {
            vec![]
        } else {
            vec![NewSource { url: source_url, title: None, private: f.source_private.is_some() }]
        },
    };
    let session = Session::User(user.account());
    let result = st.app.rate_limit(&user.handle).and_then(|_| st.app.ledger().create_issue(&session, input, None));
    match result {
        Ok(created) => {
            let mut message = "Issue created.".to_string();
            if !created.possible_duplicates.is_empty() {
                let titles: Vec<String> =
                    created.possible_duplicates.iter().map(|d| format!("“{}”", d.issue.title)).collect();
                message
                    .push_str(&format!(" It may duplicate {}; if so, link it from the issue page.", titles.join(", ")));
            }
            flash(&auth, message, false).await;
            Ok(Redirect::to(&issue_url(&created.issue.id)).into_response())
        }
        Err(e) => {
            let nav = nav(&auth, &token, "").await;
            rerender(describe(&e), &f, nav).map(|r| (token, r).into_response())
        }
    }
}

// ---- sign in, sign up, sign out -------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct NextQuery {
    #[serde(default)]
    next: Option<String>,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    nav: Nav,
    next: String,
    handle: String,
}

async fn login_page(auth: AuthSession, token: CsrfToken, Query(q): Query<NextQuery>) -> Result<Response, UiError> {
    if auth.user.is_some() {
        return Ok(Redirect::to(&safe_next(q.next.as_deref())).into_response());
    }
    let page =
        LoginPage { nav: nav(&auth, &token, "").await, next: safe_next(q.next.as_deref()), handle: String::new() };
    Ok((token, render(&page)?).into_response())
}

async fn login<S: Store + 'static>(
    State(_st): St<S>,
    mut auth: AuthSession,
    token: CsrfToken,
    Form(creds): Form<Credentials>,
) -> Result<Response, UiError> {
    let next = safe_next(creds.next.as_deref());
    let fail = |message: &str, nav: Nav, handle: String, status: StatusCode| -> Result<Response, UiError> {
        let mut page = LoginPage { nav, next: next.clone(), handle };
        page.nav.flash = Some(Flash { message: message.into(), error: true });
        Ok((status, render(&page)?).into_response())
    };
    if token.verify(&creds.authenticity_token).is_err() {
        let nav = nav(&auth, &token, "").await;
        return fail("Your form expired. Please sign in again.", nav, creds.handle.clone(), StatusCode::FORBIDDEN)
            .map(|r| (token, r).into_response());
    }
    let handle = creds.handle.clone();
    match auth.authenticate(creds).await {
        Ok(Some(user)) => {
            auth.login(&user).await.map_err(|e| UiError::Internal(e.to_string()))?;
            Ok(Redirect::to(&next).into_response())
        }
        Ok(None) => {
            let nav = nav(&auth, &token, "").await;
            fail("Incorrect handle or password.", nav, handle, StatusCode::UNAUTHORIZED)
                .map(|r| (token, r).into_response())
        }
        Err(e) => Err(UiError::Internal(e.to_string())),
    }
}

#[derive(Template)]
#[template(path = "signup.html")]
struct SignupPage {
    nav: Nav,
    handle: String,
    display_name: String,
    min_password: usize,
}

#[derive(Deserialize)]
pub struct SignupForm {
    #[serde(default)]
    authenticity_token: String,
    handle: String,
    display_name: String,
    password: String,
    confirm: String,
}

async fn signup_page(auth: AuthSession, token: CsrfToken) -> Result<Response, UiError> {
    if auth.user.is_some() {
        return Ok(Redirect::to("/").into_response());
    }
    let page = SignupPage {
        nav: nav(&auth, &token, "").await,
        handle: String::new(),
        display_name: String::new(),
        min_password: MIN_PASSWORD_LEN,
    };
    Ok((token, render(&page)?).into_response())
}

async fn signup<S: Store + 'static>(
    State(st): St<S>,
    mut auth: AuthSession,
    token: CsrfToken,
    Form(f): Form<SignupForm>,
) -> Result<Response, UiError> {
    let handle = f.handle.trim().to_string();
    let fail = |message: String, nav: Nav| -> Result<Response, UiError> {
        let mut page = SignupPage {
            nav,
            handle: handle.clone(),
            display_name: f.display_name.clone(),
            min_password: MIN_PASSWORD_LEN,
        };
        page.nav.flash = Some(Flash { message, error: true });
        Ok((StatusCode::UNPROCESSABLE_ENTITY, render(&page)?).into_response())
    };
    if token.verify(&f.authenticity_token).is_err() {
        let nav = nav(&auth, &token, "").await;
        return fail("Your form expired. Please submit it again.".into(), nav).map(|r| (token, r).into_response());
    }
    if f.password != f.confirm {
        let nav = nav(&auth, &token, "").await;
        return fail("The passwords do not match.".into(), nav).map(|r| (token, r).into_response());
    }
    let created = {
        let users = st.users.clone();
        let mut ledger = st.app.ledger();
        users.create(
            &mut ledger,
            NewUser {
                handle: &handle,
                display_name: &f.display_name,
                password: &f.password,
                role: Role::Citizen,
                institution: None,
            },
        )
    };
    match created {
        Ok(user) => {
            auth.login(&user).await.map_err(|e| UiError::Internal(e.to_string()))?;
            flash(&auth, format!("Welcome, @{}!", user.handle), false).await;
            Ok(Redirect::to("/").into_response())
        }
        Err(e) => {
            let nav = nav(&auth, &token, "").await;
            fail(describe(&e), nav).map(|r| (token, r).into_response())
        }
    }
}

#[derive(Deserialize)]
pub struct LogoutForm {
    #[serde(default)]
    authenticity_token: String,
}

async fn logout(mut auth: AuthSession, token: CsrfToken, Form(f): Form<LogoutForm>) -> Result<Response, UiError> {
    if token.verify(&f.authenticity_token).is_err() {
        return Err(UiError::App(AppError::Forbidden("your form expired; reload the page and try again".into())));
    }
    auth.logout().await.map_err(|e| UiError::Internal(e.to_string()))?;
    Ok(Redirect::to("/").into_response())
}

// ---- about --------------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "about.html")]
struct AboutPage {
    nav: Nav,
}

async fn about_page(auth: AuthSession, token: CsrfToken) -> Result<Response, UiError> {
    let page = AboutPage { nav: nav(&auth, &token, "").await };
    Ok((token, render(&page)?).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pardarsh_core::id::Origin;

    #[test]
    fn helpers() {
        assert_eq!(enc("pd:a.b:1 2/é"), "pd%3Aa.b%3A1%202%2F%C3%A9");
        let id = RecordId::generate(&Origin::new("ui.test").unwrap());
        assert_eq!(short_id(&id).len(), 7);
        assert!(id.local().simple().to_string().ends_with(&short_id(&id)));
        assert_eq!(issue_url(&id), format!("/issues/{}", enc(&id.to_string())));
        assert_eq!(pretty("information_request"), "Information request");
        assert_eq!(pretty(""), "");
        assert_eq!(opt(Some("  x ".into())), Some("x".into()));
        assert_eq!(opt(Some("   ".into())), None);
        assert_eq!(opt(None), None);
        let c = choices(&["a_b", "c"], Some("c"));
        assert_eq!((c[0].label.as_str(), c[0].selected, c[1].selected), ("A b", false, true));
        for (role, label) in [
            (Role::Citizen, "member"),
            (Role::Responder, "responder"),
            (Role::Moderator, "moderator"),
            (Role::Admin, "admin"),
        ] {
            assert_eq!(role_label(role), label);
        }
        for (c, l) in [
            (Certainty::Unverified, "unverified"),
            (Certainty::Asserted, "asserted"),
            (Certainty::Sourced, "sourced"),
            (Certainty::Disputed, "disputed"),
        ] {
            assert_eq!(certainty_label(c), l);
        }
    }

    #[test]
    fn source_links_only_link_the_web() {
        let mut user = SourceRef::new("https://example.org/a.jpg").title("photo");
        user.authority = pardarsh_core::provenance::SourceAuthority::UserSubmitted;
        let v = links(&[user, SourceRef::new("urn:isbn:1"), SourceRef::new("javascript:alert(1)")]);
        assert!(v[0].web && v[0].label == "photo" && v[0].note == "User submitted");
        assert!(!v[1].web && v[1].label == "urn:isbn:1" && v[1].note == "Unknown");
        assert!(!v[2].web);
    }

    #[test]
    fn action_errors_become_readable_messages() {
        let v = pardarsh_core::validation::ValidationErrors::single("title", "must not be empty");
        assert_eq!(describe(&AppError::Core(v.into())), "Please check the form. title: must not be empty");
        assert!(describe(&AppError::Forbidden("only responders may".into())).starts_with("Only responders"));
        assert!(describe(&AppError::BadRequest("".into())).is_empty());
        assert!(describe(&AppError::RateLimited).contains("Try again"));
        assert!(describe(&AppError::Unauthorized).contains("sign in"));
        assert!(describe(&AppError::NotFound).contains("not available"));
        let id = RecordId::generate(&Origin::new("ui.test").unwrap());
        assert!(
            describe(&AppError::Core(pardarsh_core::Error::Conflict { id, expected: 1, actual: 2 }))
                .contains("Someone else")
        );
        assert!(
            describe(&AppError::Core(pardarsh_core::Error::Storage("disk".into()))).contains("Something went wrong")
        );
    }

    #[test]
    fn error_pages_have_the_right_status() {
        let cases = [
            (UiError::App(AppError::NotFound), StatusCode::NOT_FOUND),
            (UiError::App(AppError::Forbidden("no".into())), StatusCode::FORBIDDEN),
            (UiError::App(AppError::Unauthorized), StatusCode::UNAUTHORIZED),
            (UiError::App(AppError::BadRequest("bad".into())), StatusCode::BAD_REQUEST),
            (UiError::App(AppError::RateLimited), StatusCode::TOO_MANY_REQUESTS),
            (UiError::Internal("boom".into()), StatusCode::INTERNAL_SERVER_ERROR),
        ];
        for (e, status) in cases {
            assert_eq!(e.into_response().status(), status);
        }
    }
}
