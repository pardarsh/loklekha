//! Every HTTP endpoint, driven through the router with real tokens.

use std::collections::HashMap;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use loklekha::api::{AppState, router};
use loklekha::config::{Config, bootstrap};
use loklekha::service::Ledger;
use pardarsh_core::prelude::*;
use serde_json::{Value, json};
use tower::ServiceExt;

struct App {
    router: axum::Router,
    tokens: HashMap<String, String>,
    ward7: String,
    water: String,
}

fn app() -> App {
    let (config, tokens) = Config::demo();
    let mut ledger = Ledger::new(MemoryStore::new(Origin::new(config.origin.clone()).unwrap()));
    let accounts = bootstrap(&mut ledger, &config).unwrap();
    let institutions = ledger.institutions().unwrap();
    let find = |h: &str| institutions.iter().find(|i| i.handle == h).unwrap().id.to_string();
    let (ward7, water) = (find("ward7_works"), find("city_water"));
    App { router: router(AppState::new(ledger, accounts, 1000)), tokens: tokens.into_iter().collect(), ward7, water }
}

fn enc(id: &str) -> String {
    id.replace(':', "%3A")
}

impl App {
    async fn raw(&self, req: Request<Body>) -> (StatusCode, Value) {
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn call(&self, method: &str, uri: &str, user: Option<&str>, body: Option<Value>) -> (StatusCode, Value) {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(u) = user {
            req = req.header("authorization", format!("Bearer {}", self.tokens[u]));
        }
        let body = match body {
            Some(b) => {
                req = req.header("content-type", "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        self.raw(req.body(body).unwrap()).await
    }

    async fn post(&self, uri: &str, user: &str, body: Value) -> Value {
        let (s, b) = self.call("POST", uri, Some(user), Some(body)).await;
        assert_eq!(s, StatusCode::CREATED, "POST {uri}: {b}");
        b
    }

    async fn issue(&self, title: &str) -> String {
        let b = self
            .post("/api/issues", "asha", json!({"title": title, "category": "water", "locality": "Ward 7", "responsible_institution": self.ward7}))
            .await;
        b["issue"]["id"].as_str().unwrap().to_string()
    }
}

#[tokio::test]
async fn read_endpoints() {
    let app = app();
    let id = app.issue("No water in Block C").await;
    let (s, me) = app.call("GET", "/api/me", Some("ward7_engineer"), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(me["role"], "responder");
    let (s, _) = app.call("GET", "/api/me", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let (s, list) = app.call("GET", "/api/issues?open_only=true&category=water&limit=10", None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 1);
    let (s, _) = app.call("GET", "/api/issues?status=bogus", None, None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = app.call("GET", "/api/issues?unknown=1", None, None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (s, dups) = app.call("GET", "/api/issues/duplicates?title=water%20Block%20C", None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(dups[0]["issue"]["id"], id);
    let (s, _) = app.call("GET", "/api/issues/duplicates", None, None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "title is required");

    let (s, rec) = app.call("GET", &format!("/api/records/{}", enc(&id)), None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(rec["record"]["id"], id);
    assert_eq!(rec["timeline"][0]["event"], "created");
    let (s, _) = app.call("GET", "/api/records/nonsense", None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (s, inst) = app.call("GET", "/api/institutions", None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(inst.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn full_institutional_flow_over_http() {
    let app = app();
    let id = app.issue("Valve leaking near the tank").await;
    let base = format!("/api/issues/{}", enc(&id));

    let ev = app
        .post(&format!("{base}/evidence"), "ravi", json!({"title": "Photo", "url": "https://example.org/v.jpg"}))
        .await;
    assert_eq!(ev["kind"], "evidence");
    let proposal = app.post(&format!("{base}/proposals"), "ravi", json!({"title": "Replace the valve"})).await;
    let other = app.issue("Another leak").await;
    app.post(&format!("{base}/links"), "ravi", json!({"other": other, "relation": "related_to"})).await;

    // Assignment: accept own institution, moderator adds another, then remove it.
    let a = app.post(&format!("{base}/assignments"), "ward7_engineer", json!({"institution": app.ward7})).await;
    assert!(
        a["relations"].as_array().unwrap().iter().any(|r| r["kind"] == "assigned_to" && r["certainty"] == "asserted")
    );
    let with_water = app.post(&format!("{base}/assignments"), "moderator", json!({"institution": app.water})).await;
    let water_rel = with_water["relations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["target"] == app.water.as_str() && r["retracted"] == false)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, _) =
        app.call("DELETE", &format!("{base}/assignments/{water_rel}?reason=wrong%20body"), Some("ravi"), None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = app.call("DELETE", &format!("{base}/assignments/{water_rel}"), Some("moderator"), None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "a reason is required");
    let (s, _) = app.call("DELETE", &format!("{base}/assignments/not-a-uuid?reason=x"), Some("moderator"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, body) = app
        .call("DELETE", &format!("{base}/assignments/{water_rel}?reason=wrong%20body"), Some("moderator"), None)
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");

    app.post(&format!("{base}/transitions"), "ward7_engineer", json!({"to": "acknowledged"})).await;
    let decision = app
        .post(
            &format!("/api/proposals/{}/decisions", enc(proposal["id"].as_str().unwrap())),
            "ward7_engineer",
            json!({"verdict": "accepted", "reason": "in budget"}),
        )
        .await;
    assert_eq!(decision["kind"], "decision");
    let action = app
        .post(&format!("{base}/actions"), "ward7_engineer", json!({"title": "Replace valve", "due_date": "2026-12-01"}))
        .await;
    let progress = app
        .post(
            &format!("/api/actions/{}/progress", enc(action["id"].as_str().unwrap())),
            "ward7_engineer",
            json!({"progress": "in_progress", "note": "parts ordered"}),
        )
        .await;
    assert_eq!(progress["extensions"]["loklekha.action"]["fields"]["progress"]["enum"], "in_progress");
    app.post(&format!("{base}/transitions"), "ward7_engineer", json!({"to": "in_progress"})).await;
    app.post(&format!("{base}/completion-claims"), "ward7_engineer", json!({"statement": "Valve replaced"})).await;
    app.post(&format!("{base}/transitions"), "ward7_engineer", json!({"to": "resolved", "reason": "replaced"})).await;
    app.post(&format!("{base}/outcomes"), "ravi", json!({"title": "Still dripping", "finding": "problem_persists"}))
        .await;
    app.post(&format!("{base}/transitions"), "ravi", json!({"to": "disputed", "reason": "still dripping"})).await;

    let (_, d) = app.call("GET", &base, None, None).await;
    assert_eq!(d["summary"]["status"], "disputed");
    for (key, n) in [
        ("evidence", 1),
        ("proposals", 1),
        ("actions", 1),
        ("completion_claims", 1),
        ("outcomes", 1),
        ("related", 1),
        ("responsible", 1),
    ] {
        assert_eq!(d[key].as_array().unwrap().len(), n, "{key}");
    }
    assert_eq!(d["proposals"][0]["decisions"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn moderation_over_http() {
    let app = app();
    let id = app.issue("Abusive post").await;
    let report = app
        .post(&format!("/api/records/{}/reports", enc(&id)), "ravi", json!({"category": "abuse", "details": "insults"}))
        .await;
    let report_id = report["report"].as_str().unwrap().to_string();
    let (s, _) = app.call("GET", "/api/moderation/queue", Some("ravi"), None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = app.call("GET", "/api/moderation/queue", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, queue) = app.call("GET", "/api/moderation/queue", Some("moderator"), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(queue[0]["id"], report_id);

    let m = format!("/api/records/{}/moderation", enc(&id));
    app.post(&m, "moderator", json!({"action": "note", "text": "first warning"})).await;
    app.post(&m, "moderator", json!({"action": "redact", "fields": [{"field": "title"}], "reason": "abusive"})).await;
    app.post(&m, "moderator", json!({"action": "resolve_report", "report": report_id, "state": "actioned"})).await;
    let (s, _) = app.call("POST", &m, Some("moderator"), Some(json!({"action": "explode"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = app.call("POST", &m, Some("ravi"), Some(json!({"action": "note", "text": "x"}))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (_, queue) = app.call("GET", "/api/moderation/queue", Some("moderator"), None).await;
    assert!(queue.as_array().unwrap().is_empty());
    let (_, d) = app.call("GET", &format!("/api/issues/{}", enc(&id)), None, None).await;
    assert_eq!(d["issue"]["title"], "[redacted]");
}

#[tokio::test]
async fn header_and_body_edge_cases() {
    let app = app();
    let id = app.issue("Edge cases").await;
    let uri = format!("/api/issues/{}/proposals", enc(&id));

    // Non-ASCII Authorization header.
    let req = Request::builder()
        .method("POST")
        .uri(&uri)
        .header("authorization", axum::http::HeaderValue::from_bytes(b"Bearer \xff").unwrap())
        .body(Body::from(json!({"title": "x"}).to_string()))
        .unwrap();
    assert_eq!(app.raw(req).await.0, StatusCode::UNAUTHORIZED);

    // Non-UTF-8 Idempotency-Key header.
    let req = Request::builder()
        .method("POST")
        .uri(&uri)
        .header("authorization", format!("Bearer {}", app.tokens["ravi"]))
        .header("idempotency-key", axum::http::HeaderValue::from_bytes(b"\xfe").unwrap())
        .body(Body::from(json!({"title": "x"}).to_string()))
        .unwrap();
    assert_eq!(app.raw(req).await.0, StatusCode::BAD_REQUEST);

    // Idempotency key with characters the core rejects.
    let req = Request::builder()
        .method("POST")
        .uri(&uri)
        .header("authorization", format!("Bearer {}", app.tokens["ravi"]))
        .header("idempotency-key", "has spaces")
        .body(Body::from(json!({"title": "x"}).to_string()))
        .unwrap();
    assert_eq!(app.raw(req).await.0, StatusCode::UNPROCESSABLE_ENTITY);

    // Bodies over 64 KiB are refused before parsing.
    let big = json!({"title": "x", "body": "a".repeat(70 * 1024)});
    let (s, _) = app.call("POST", &uri, Some("ravi"), Some(big)).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);

    // Writes to unknown records.
    let ghost = "pd%3Aloklekha.localhost%3A00000000-0000-7000-8000-000000000000";
    let (s, _) =
        app.call("POST", &format!("/api/issues/{ghost}/proposals"), Some("ravi"), Some(json!({"title": "x"}))).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = app.call("POST", "/api/issues/garbage/proposals", Some("ravi"), Some(json!({"title": "x"}))).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Unknown routes and wrong methods.
    let (s, _) = app.call("GET", "/api/nothing-here", None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = app.call("PUT", "/api/issues", Some("ravi"), Some(json!({}))).await;
    assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);
}
