//! The browser UI end to end: sessions, sign-up/in/out, CSRF, forms,
//! permissions, escaping and every section of the issue page.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use chrono::NaiveDate;
use http_body_util::BodyExt;
use loklekha::api::AppState;
use loklekha::config::{Config, bootstrap};
use loklekha::identity::Session;
use loklekha::server::{WebConfig, app};
use loklekha::service::*;
use loklekha::ui::{enc, issue_url};
use loklekha::users::{NewUser, UserStore};
use loklekha::workflow::{IssueStatus, Role};
use pardarsh_core::prelude::*;
use tower::ServiceExt;

const PASSWORD: &str = "correct horse battery";

struct World {
    state: Arc<AppState<MemoryStore>>,
    router: axum::Router,
    ward7: RecordId,
}

fn world(writes_per_minute: u32) -> World {
    let (config, _) = Config::demo();
    let mut ledger = Ledger::new(MemoryStore::new(Origin::new(config.origin.clone()).unwrap()));
    let accounts = bootstrap(&mut ledger, &config).unwrap();
    let users = UserStore::open_in_memory().unwrap();
    for (handle, role, institution) in [
        ("asha", Role::Citizen, None),
        ("ravi", Role::Citizen, None),
        ("eng", Role::Responder, Some("ward7_works")),
        ("mod1", Role::Moderator, None),
    ] {
        users
            .create(&mut ledger, NewUser { handle, display_name: handle, password: PASSWORD, role, institution })
            .unwrap();
    }
    let ward7 = ledger.institutions().unwrap().into_iter().find(|i| i.handle == "ward7_works").unwrap().id;
    let state = AppState::new(ledger, accounts, writes_per_minute);
    let router = app(
        state.clone(),
        users,
        tower_sessions::MemoryStore::default(),
        &WebConfig { secure_cookies: false, session_days: 1 },
    );
    World { state, router, ward7 }
}

/// A user of the service: a session for the ledger plus a cookie-keeping browser.
fn session(w: &World, handle: &str) -> Session {
    // Accounts created through the UserStore are looked up via the ledger's actor records.
    let ledger = w.state.ledger.lock().unwrap();
    let actor = ledger
        .repo()
        .list(&RecordQuery::kind(RecordKind::Actor))
        .unwrap()
        .into_iter()
        .find(|r| r.extension_field(loklekha::vocab::ACCOUNT, "handle").and_then(|v| v.as_text()) == Some(handle));
    let role = match handle {
        "eng" => Role::Responder,
        "mod1" => Role::Moderator,
        _ => Role::Citizen,
    };
    Session::User(loklekha::identity::Account {
        actor_id: actor.unwrap().id,
        handle: handle.into(),
        display_name: handle.into(),
        role,
        institution: (handle == "eng").then(|| w.ward7.clone()),
    })
}

fn seed_issue(w: &World, title: &str) -> RecordId {
    let asha = session(w, "asha");
    let mut ledger = w.state.ledger.lock().unwrap();
    let input = NewIssue {
        title: title.into(),
        description: Some("Dark after 7pm\nnear the bus stop".into()),
        category: "streetlights".into(),
        location_text: Some("4th Cross".into()),
        locality: Some("Ward 7".into()),
        affected_service: Some("street lighting".into()),
        responsible_institution: Some(w.ward7.clone()),
        withhold_identity: false,
        sources: vec![NewSource {
            url: "https://example.org/photo.jpg".into(),
            title: Some("photo".into()),
            private: false,
        }],
    };
    ledger.create_issue(&asha, input, None).unwrap().issue.id
}

struct Browser {
    router: axum::Router,
    cookies: HashMap<String, String>,
}

struct Page {
    status: StatusCode,
    headers: HeaderMap,
    html: String,
}

impl Page {
    fn location(&self) -> &str {
        self.headers.get(header::LOCATION).map(|v| v.to_str().unwrap()).unwrap_or("")
    }

    fn token(&self) -> String {
        let marker = "name=\"authenticity_token\" value=\"";
        let start = self.html.find(marker).expect("page has a form token") + marker.len();
        let end = self.html[start..].find('"').unwrap();
        self.html[start..start + end]
            .replace("&#x2b;", "+")
            .replace("&#x2f;", "/")
            .replace("&#x3d;", "=")
            .replace("&#43;", "+")
            .replace("&#61;", "=")
            .replace("&#47;", "/")
    }
}

impl Browser {
    fn new(w: &World) -> Self {
        Self { router: w.router.clone(), cookies: HashMap::new() }
    }

    async fn send(&mut self, req: axum::http::request::Builder, body: Body) -> Page {
        let cookie = self.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
        let req = if cookie.is_empty() { req } else { req.header(header::COOKIE, cookie) };
        let resp = self.router.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        for v in resp.headers().get_all(header::SET_COOKIE) {
            let pair = v.to_str().unwrap().split(';').next().unwrap();
            let (k, val) = pair.split_once('=').unwrap();
            if val.is_empty() {
                self.cookies.remove(k);
            } else {
                self.cookies.insert(k.to_string(), val.to_string());
            }
        }
        let status = resp.status();
        let headers = resp.headers().clone();
        let html = String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).into_owned();
        Page { status, headers, html }
    }

    async fn get(&mut self, path: &str) -> Page {
        self.send(Request::builder().method("GET").uri(path), Body::empty()).await
    }

    async fn post(&mut self, path: &str, fields: &[(&str, &str)]) -> Page {
        let body = fields.iter().map(|(k, v)| format!("{}={}", enc(k), enc(v))).collect::<Vec<_>>().join("&");
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        self.send(req, Body::from(body)).await
    }

    /// Submit a form found on `page_path`, adding its CSRF token.
    async fn submit(&mut self, page_path: &str, action: &str, fields: &[(&str, &str)]) -> Page {
        let token = self.get(page_path).await.token();
        let mut all = vec![("authenticity_token", token.as_str())];
        all.extend_from_slice(fields);
        self.post(action, &all).await
    }

    async fn login(&mut self, handle: &str) {
        let p = self.submit("/login", "/login", &[("handle", handle), ("password", PASSWORD), ("next", "/")]).await;
        assert_eq!(p.status, StatusCode::SEE_OTHER, "login failed: {}", p.html);
    }
}

#[tokio::test]
async fn anonymous_browsing() {
    let w = world(100);
    let id = seed_issue(&w, "Light out <script>alert(1)</script>");
    let mut b = Browser::new(&w);

    let home = b.get("/").await;
    assert_eq!(home.status, StatusCode::OK);
    assert!(home.html.contains("1 Open") && home.html.contains("0 Closed"));
    assert!(home.html.contains("Light out &#60;script&#62;"), "titles are escaped");
    assert!(!home.html.contains("<script>alert"));
    assert!(home.html.contains("Sign in") && !home.html.contains("href=\"/issues/new\""));
    let csp = home.headers.get(header::CONTENT_SECURITY_POLICY).unwrap().to_str().unwrap();
    assert!(csp.contains("default-src 'none'") && csp.contains("style-src 'self'"));

    assert!(home.html.contains("class=\"selected\">1 Open"), "the open tab is highlighted");
    let closed = b.get("/issues?state=closed&category=streetlights").await;
    assert!(closed.html.contains("No issues match."));
    assert!(closed.html.contains("class=\"selected\">0 Closed"), "the closed tab is highlighted");
    let filtered = b.get("/issues?q=&status=&category=water&locality=").await;
    assert!(filtered.html.contains("0 Open"));
    let bad_filters = b.get("/issues?status=nonsense&category=nonsense").await;
    assert_eq!(bad_filters.status, StatusCode::OK, "unknown filter values are ignored");

    let page = b.get(&issue_url(&id)).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.html.contains("Dark after 7pm\nnear the bus stop"));
    assert!(page.html.contains("href=\"https://example.org/photo.jpg\""));
    assert!(page.html.contains("comment, add evidence or propose a remedy"));
    assert!(!page.html.contains("Add a comment"));
    assert!(!page.html.contains("Change status"), "anonymous visitors get no status form");
    assert!(page.html.contains("Ward 7 Public Works Office (demo)") && page.html.contains("unverified"));

    let new = b.get("/issues/new").await;
    assert_eq!(new.status, StatusCode::SEE_OTHER);
    assert_eq!(new.location(), "/login?next=%2Fissues%2Fnew");

    let css = b.get("/static/app.css").await;
    assert_eq!(css.status, StatusCode::OK);
    assert!(css.headers[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/css"));
    assert_eq!(b.get("/about").await.status, StatusCode::OK);
    assert!(home.html.contains("href=\"/static/images/favicon.png\""));
    assert!(home.html.contains("href=\"/static/images/apple-touch-icon.png\""));
    assert!(home.html.contains("class=\"logo\"") && home.html.contains("src=\"/static/images/logo.jpg\""));
    for (path, kind, magic) in [
        ("/static/images/logo.jpg", "image/jpeg", &b"\xff\xd8"[..]),
        ("/static/images/favicon.png", "image/png", &b"\x89PNG"[..]),
        ("/static/images/apple-touch-icon.png", "image/png", &b"\x89PNG"[..]),
        ("/favicon.ico", "image/png", &b"\x89PNG"[..]),
    ] {
        let resp = b.router.clone().oneshot(Request::builder().uri(path).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        assert_eq!(resp.headers()[header::CONTENT_TYPE], kind, "{path}");
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(bytes.starts_with(magic), "{path}");
    }

    for missing in ["/issues/garbage", "/issues/pd%3Aloklekha.localhost%3A00000000-0000-7000-8000-000000000000"] {
        let p = b.get(missing).await;
        assert_eq!(p.status, StatusCode::NOT_FOUND);
        assert!(p.html.contains("Not found"));
    }

    // Writing without signing in sends you to sign in.
    let p = b
        .post(
            &format!("{}/comments", issue_url(&id)),
            &[("authenticity_token", "x"), ("body", "hi"), ("kind", "question")],
        )
        .await;
    assert_eq!(p.status, StatusCode::SEE_OTHER);
    assert!(p.location().starts_with("/login?next=%2Fissues%2F"));
}

#[tokio::test]
async fn sign_up_sign_in_sign_out() {
    let w = world(100);
    let mut b = Browser::new(&w);

    let p = b
        .submit(
            "/signup",
            "/signup",
            &[
                ("handle", "newbie"),
                ("display_name", "New Person"),
                ("password", PASSWORD),
                ("confirm", "different password"),
            ],
        )
        .await;
    assert_eq!(p.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(p.html.contains("do not match") && p.html.contains("value=\"newbie\""));
    let p = b
        .post(
            "/signup",
            &[
                ("authenticity_token", "forged"),
                ("handle", "newbie"),
                ("display_name", "N"),
                ("password", PASSWORD),
                ("confirm", PASSWORD),
            ],
        )
        .await;
    assert!(p.html.contains("form expired"), "CSRF is enforced");
    let p = b
        .submit(
            "/signup",
            "/signup",
            &[("handle", "asha"), ("display_name", "Dup"), ("password", PASSWORD), ("confirm", PASSWORD)],
        )
        .await;
    assert!(p.html.contains("That handle is taken"));
    let p = b
        .submit(
            "/signup",
            "/signup",
            &[("handle", "newbie"), ("display_name", "New Person"), ("password", "short"), ("confirm", "short")],
        )
        .await;
    assert!(p.html.contains("at least 10"));

    let p = b
        .submit(
            "/signup",
            "/signup",
            &[("handle", "newbie"), ("display_name", "New Person"), ("password", PASSWORD), ("confirm", PASSWORD)],
        )
        .await;
    assert_eq!(p.status, StatusCode::SEE_OTHER);
    let home = b.get("/").await;
    assert!(home.html.contains("@newbie") && home.html.contains("Welcome, @newbie!"));
    assert!(!b.get("/").await.html.contains("Welcome"), "flash messages show once");
    assert_eq!(b.get("/signup").await.status, StatusCode::SEE_OTHER, "already signed in");
    assert_eq!(b.get("/login?next=/about").await.location(), "/about");

    let p = b.submit("/", "/logout", &[]).await;
    assert_eq!(p.status, StatusCode::SEE_OTHER);
    assert!(b.get("/").await.html.contains("Sign in"));
    let p = b.post("/logout", &[("authenticity_token", "forged")]).await;
    assert_eq!(p.status, StatusCode::FORBIDDEN);

    let p =
        b.submit("/login", "/login", &[("handle", "newbie"), ("password", "wrong password!!"), ("next", "/")]).await;
    assert_eq!(p.status, StatusCode::UNAUTHORIZED);
    assert!(p.html.contains("Incorrect handle or password") && p.html.contains("value=\"newbie\""));
    let p = b.post("/login", &[("authenticity_token", "forged"), ("handle", "newbie"), ("password", PASSWORD)]).await;
    assert_eq!(p.status, StatusCode::FORBIDDEN);
    let p = b
        .submit("/login", "/login", &[("handle", "newbie"), ("password", PASSWORD), ("next", "https://evil.example/")])
        .await;
    assert_eq!(p.location(), "/", "open redirects are refused");
    b.submit("/", "/logout", &[]).await;
    let p = b
        .submit(
            "/login?next=/issues/new",
            "/login",
            &[("handle", "newbie"), ("password", PASSWORD), ("next", "/issues/new")],
        )
        .await;
    assert_eq!(p.location(), "/issues/new");
    assert_eq!(b.get("/issues/new").await.status, StatusCode::OK);
}

#[tokio::test]
async fn reporting_an_issue_through_the_form() {
    let w = world(100);
    let existing = seed_issue(&w, "Streetlight out on 4th Cross");
    let mut b = Browser::new(&w);
    b.login("ravi").await;

    let form = b.get("/issues/new").await;
    assert!(form.html.contains("Ward 7 Public Works Office (demo)") && form.html.contains("know</option>"));
    let ward7 = w.ward7.to_string();
    let p = b
        .submit(
            "/issues/new",
            "/issues/new",
            &[
                ("title", "4th Cross streetlight still out"),
                ("description", "Dark near the bus stop"),
                ("category", "streetlights"),
                ("location_text", ""),
                ("locality", "Ward 7"),
                ("affected_service", ""),
                ("institution", &ward7),
                ("source_url", "https://example.org/night.jpg"),
                ("source_private", "on"),
                ("withhold_identity", "on"),
            ],
        )
        .await;
    assert_eq!(p.status, StatusCode::SEE_OTHER, "{}", p.html);
    let created = b.get(p.location()).await;
    assert!(created.html.contains("Issue created.") && created.html.contains("may duplicate"));
    assert!(created.html.contains("Streetlight out on 4th Cross"));
    assert!(
        created.html.contains("(@ravi)") && !created.html.contains("identity withheld"),
        "reporters see their own name"
    );
    assert!(!created.html.contains("night.jpg"), "private links are for moderators only");

    // Anonymous visitors see neither the private link nor the reporter.
    let mut anon = Browser::new(&w);
    let public = anon.get(p.location()).await;
    assert!(public.html.contains("identity withheld"));
    assert!(!public.html.contains("night.jpg"));
    let _ = existing;

    let p = b.submit("/issues/new", "/issues/new", &[("title", "Keeps my text"), ("category", "potholes")]).await;
    assert_eq!(p.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(p.html.contains("Please check the form") && p.html.contains("value=\"Keeps my text\""));
    let p = b
        .submit("/issues/new", "/issues/new", &[("title", "x"), ("category", "water"), ("institution", "not-an-id")])
        .await;
    assert!(p.html.contains("Choose a responsible body"));
    let p = b.post("/issues/new", &[("authenticity_token", "forged"), ("title", "x"), ("category", "water")]).await;
    assert!(p.html.contains("form expired"));
}

#[tokio::test]
async fn issue_forms_and_permissions() {
    let w = world(100);
    let id = seed_issue(&w, "Water supply cut");
    let url = issue_url(&id);
    let mut citizen = Browser::new(&w);
    citizen.login("ravi").await;

    let page = citizen.get(&url).await;
    assert!(page.html.contains("Add a comment"));
    assert!(!page.html.contains("Change status"), "citizens cannot move a fresh issue");
    assert!(!page.html.contains("value=\"response\""), "citizens cannot post official responses");

    for (action, fields, message) in [
        ("comments", vec![("kind", "question"), ("body", "When will it be fixed?")], "Comment added."),
        (
            "evidence",
            vec![("title", "Meter reads zero"), ("url", "https://example.org/meter.jpg"), ("relation", "contradicts")],
            "Evidence added.",
        ),
        ("proposals", vec![("title", "Send a tanker"), ("body", "")], "Proposal added."),
        (
            "outcomes",
            vec![("title", "Still dry"), ("finding", "problem_persists"), ("evidence_url", "")],
            "Observation recorded.",
        ),
        ("reports", vec![("category", "spam"), ("details", "test")], "Moderators will review"),
    ] {
        let p = citizen.submit(&url, &format!("{url}/{action}"), &fields).await;
        assert_eq!(p.status, StatusCode::SEE_OTHER, "{action}");
        assert_eq!(p.location(), url);
        assert!(citizen.get(&url).await.html.contains(message), "{action}");
    }
    let page = citizen.get(&url).await;
    for text in [
        "When will it be fixed?",
        "contradicting evidence",
        "Send a tanker",
        "observation · problem persists",
        "meter.jpg",
    ] {
        assert!(page.html.contains(text), "missing {text}");
    }

    // Errors come back as messages, and nothing is written.
    let p = citizen.submit(&url, &format!("{url}/comments"), &[("kind", "question"), ("body", "   ")]).await;
    assert_eq!(p.status, StatusCode::SEE_OTHER);
    assert!(citizen.get(&url).await.html.contains("Comment body must not be empty"));
    let p = citizen.submit(&url, &format!("{url}/status"), &[("to", "acknowledged"), ("reason", "")]).await;
    assert_eq!(p.status, StatusCode::SEE_OTHER);
    assert!(citizen.get(&url).await.html.contains("Your role may not"));
    let p = citizen.submit(&url, &format!("{url}/status"), &[("to", "flying")]).await;
    assert_eq!(p.status, StatusCode::SEE_OTHER);
    assert!(citizen.get(&url).await.html.contains("Unknown status"));
    let before = citizen.get(&url).await.html.matches("class=\"card").count();
    let p = citizen
        .post(&format!("{url}/comments"), &[("authenticity_token", "forged"), ("kind", "question"), ("body", "forged")])
        .await;
    assert_eq!(p.status, StatusCode::SEE_OTHER);
    let after = citizen.get(&url).await;
    assert!(after.html.contains("Your form expired"));
    assert_eq!(after.html.matches("class=\"card").count(), before, "forged posts write nothing");
    let p = citizen
        .post("/issues/garbage/comments", &[("authenticity_token", "x"), ("kind", "question"), ("body", "x")])
        .await;
    assert_eq!(p.status, StatusCode::NOT_FOUND);

    // The assigned responder sees and uses the status form.
    let mut eng = Browser::new(&w);
    eng.login("eng").await;
    let page = eng.get(&url).await;
    assert!(page.html.contains("Change status") && page.html.contains("value=\"response\""));
    let p = eng
        .submit(
            &url,
            &format!("{url}/status"),
            &[("to", "acknowledged"), ("reason", "crew scheduled"), ("expected_version", "")],
        )
        .await;
    assert_eq!(p.status, StatusCode::SEE_OTHER);
    let page = eng.get(&url).await;
    assert!(page.html.contains("Status changed."));
    assert!(page.html.contains("changed the status from Submitted to Acknowledged by responsible body"));
    assert!(page.html.contains("crew scheduled"));
    // A stale form (old version) is refused with a clear message.
    let p = eng.submit(&url, &format!("{url}/status"), &[("to", "under_review"), ("expected_version", "1")]).await;
    assert_eq!(p.status, StatusCode::SEE_OTHER);
    assert!(eng.get(&url).await.html.contains("Someone else changed this issue"));
}

#[tokio::test]
async fn issue_page_shows_every_kind_of_record_and_event() {
    let w = world(100);
    let id = seed_issue(&w, "Streetlight out");
    let other = seed_issue(&w, "Same streetlight");
    let (asha, eng, moderator) = (session(&w, "asha"), session(&w, "eng"), session(&w, "mod1"));
    {
        let mut l = w.state.ledger.lock().unwrap();
        l.link_issues(
            &asha,
            &other,
            LinkRequest { other: id.clone(), relation: "duplicates".into(), note: None },
            None,
        )
        .unwrap();
        let third = l
            .create_issue(
                &asha,
                NewIssue {
                    title: "Dark lane".into(),
                    description: None,
                    category: "streetlights".into(),
                    location_text: None,
                    locality: None,
                    affected_service: None,
                    responsible_institution: None,
                    withhold_identity: false,
                    sources: vec![],
                },
                None,
            )
            .unwrap()
            .issue
            .id;
        l.link_issues(&eng, &id, LinkRequest { other: third, relation: "related_to".into(), note: None }, None)
            .unwrap();
        l.assign(&eng, &id, AssignRequest { institution: w.ward7.clone(), note: None }, None).unwrap();
        let proposal = l
            .propose(&asha, &id, NewProposal { title: "LED lamp".into(), body: Some("cheaper to run".into()) }, None)
            .unwrap();
        l.comment(&asha, &proposal.id, NewComment { kind: "argument".into(), body: "Please".into() }, None).unwrap();
        l.decide(&eng, &proposal.id, NewDecision { verdict: "accepted".into(), reason: "Budgeted".into() }, None)
            .unwrap();
        let action = l
            .plan_action(
                &eng,
                &id,
                NewAction {
                    title: "Replace fitting".into(),
                    description: None,
                    due_date: NaiveDate::from_ymd_opt(2026, 7, 10),
                },
                None,
            )
            .unwrap();
        l.update_action(&eng, &action.id, ActionUpdate { progress: "in_progress".into(), note: None }).unwrap();
        l.claim_completion(&eng, &id, NewClaim { statement: "Fitting replaced".into(), evidence_url: None }, None)
            .unwrap();
        l.transition(
            &eng,
            &id,
            TransitionRequest { to: IssueStatus::Acknowledged, reason: None, expected_version: None },
            None,
        )
        .unwrap();
        l.moderate(&moderator, &id, ModerationAction::Note { text: "watch this one".into() }).unwrap();
        l.moderate(
            &moderator,
            &id,
            ModerationAction::Redact {
                fields: vec![loklekha::service::RedactField::LocationText],
                reason: "too precise".into(),
            },
        )
        .unwrap();
    }
    let url = issue_url(&id);
    let mut anon = Browser::new(&w);
    let page = anon.get(&url).await;
    for text in [
        "proposal",
        "decision: accepted",
        "Budgeted",
        "Please",
        "action · in progress",
        "Due 2026-07-10",
        "updated “Replace fitting” to in progress",
        "completion claim",
        "assigned “Ward 7 Public Works Office (demo)”",
        "linked this to “Dark lane”",
        "redacted some content",
        "Same streetlight",
        "duplicate of this",
        "Participants",
        "asserted",
    ] {
        assert!(page.html.contains(text), "missing {text}");
    }
    assert!(
        !page.html.contains("watch this one") && !page.html.contains("moderation note"),
        "moderator notes are private"
    );
    let mut m = Browser::new(&w);
    m.login("mod1").await;
    assert!(m.get(&url).await.html.contains("added a moderation note"));

    let dup_page = anon.get(&issue_url(&other)).await;
    assert!(dup_page.html.contains("marked this as a duplicate of “Streetlight out”"));
    assert!(dup_page.html.contains("this is a duplicate of it"));

    // Hidden issues disappear for the public.
    {
        let mut l = w.state.ledger.lock().unwrap();
        l.moderate(&moderator, &other, ModerationAction::Hide { reason: "abuse".into() }).unwrap();
    }
    assert_eq!(anon.get(&issue_url(&other)).await.status, StatusCode::NOT_FOUND);
    let mod_view = m.get(&issue_url(&other)).await;
    assert!(mod_view.html.contains("hid this issue"));
    assert!(m.get("/issues").await.html.contains("hidden"));
    assert!(page.html.contains(&format!("/api/issues/{}/export", enc(&id.to_string()))));
}

#[tokio::test]
async fn writes_from_the_ui_are_rate_limited() {
    let w = world(1);
    let id = seed_issue(&w, "Rate limited");
    let url = issue_url(&id);
    let mut b = Browser::new(&w);
    b.login("ravi").await;
    b.submit(&url, &format!("{url}/comments"), &[("kind", "question"), ("body", "first")]).await;
    b.submit(&url, &format!("{url}/comments"), &[("kind", "question"), ("body", "second")]).await;
    let page = b.get(&url).await;
    assert!(page.html.contains("Too many changes"));
    assert!(page.html.contains("first") && !page.html.contains(">second<"));
    let p = b.submit("/issues/new", "/issues/new", &[("title", "Another"), ("category", "water")]).await;
    assert!(p.html.contains("Too many changes"));
}
