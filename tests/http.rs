//! HTTP-level behaviour: auth, input handling, status codes, escaping, headers.

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
    tokens: std::collections::HashMap<String, String>,
}

fn app(writes_per_minute: u32) -> App {
    let (mut config, tokens) = Config::demo();
    config.writes_per_minute = writes_per_minute;
    let mut ledger = Ledger::new(SqliteStore::open_in_memory(Origin::new(config.origin.clone()).unwrap()).unwrap());
    let accounts = bootstrap(&mut ledger, &config).unwrap();
    let state = AppState::new(ledger, accounts, config.writes_per_minute);
    App { router: router(state), tokens: tokens.into_iter().collect() }
}

impl App {
    async fn call(
        &self,
        method: &str,
        uri: &str,
        user: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, String, axum::http::HeaderMap) {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(u) = user {
            req = req.header("authorization", format!("Bearer {}", self.tokens[u]));
        }
        let req = match body {
            Some(b) => req.header("content-type", "application/json").body(Body::from(b.to_string())),
            None => req.body(Body::empty()),
        }
        .unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned(), headers)
    }

    async fn json(&self, method: &str, uri: &str, user: Option<&str>, body: Option<Value>) -> (StatusCode, Value) {
        let (s, b, _) = self.call(method, uri, user, body).await;
        (s, serde_json::from_str(&b).unwrap_or(Value::Null))
    }
}

fn enc(id: &str) -> String {
    id.replace(':', "%3A")
}

#[tokio::test]
async fn issue_lifecycle_over_http() {
    let app = app(100);
    let (s, institutions) = app.json("GET", "/api/institutions", None, None).await;
    assert_eq!(s, StatusCode::OK);
    let ward7 = institutions.as_array().unwrap().iter().find(|i| i["handle"] == "ward7_works").unwrap()["id"].clone();

    let new_issue = json!({
        "title": "<script>alert('x')</script> Garbage not collected",
        "category": "waste",
        "locality": "Ward 7",
        "responsible_institution": ward7,
    });
    let (s, _) = app.json("POST", "/api/issues", None, Some(new_issue.clone())).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, body) = app.json("POST", "/api/issues", Some("asha"), Some(new_issue.clone())).await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    let id = body["issue"]["id"].as_str().unwrap().to_string();
    assert!(id.starts_with("pd:loklekha.localhost:"));

    // Clients cannot smuggle in fields such as a status.
    let mut sneaky = new_issue.clone();
    sneaky["status"] = json!("resolved");
    let (s, body) = app.json("POST", "/api/issues", Some("asha"), Some(sneaky)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    // Semantic validation surfaces as 422 with paths.
    let (s, body) =
        app.json("POST", "/api/issues", Some("asha"), Some(json!({"title": "x", "category": "nope"}))).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body["issues"].as_array().unwrap().iter().any(|i| i["path"].as_str().unwrap().contains("category")));
    let (s, _) = app.json("POST", "/api/issues", Some("asha"), None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (s, _) = app
        .json(
            "POST",
            &format!("/api/issues/{}/transitions", enc(&id)),
            Some("asha"),
            Some(json!({"to": "acknowledged"})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, body) = app
        .json(
            "POST",
            &format!("/api/issues/{}/transitions", enc(&id)),
            Some("ward7_engineer"),
            Some(json!({"to": "acknowledged"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    let (s, body) = app
        .json(
            "POST",
            &format!("/api/issues/{}/transitions", enc(&id)),
            Some("ward7_engineer"),
            Some(json!({"to": "under_review", "expected_version": 1})),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");

    let (s, body) = app
        .json(
            "POST",
            &format!("/api/records/{}/comments", enc(&id)),
            Some("ravi"),
            Some(json!({"kind": "question", "body": "When is pickup scheduled?"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");

    let (s, detail) = app.json("GET", &format!("/api/issues/{}", enc(&id)), None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(detail["summary"]["status"], "acknowledged");
    assert_eq!(detail["comments"].as_array().unwrap().len(), 1);

    // JSON responses carry the same security headers as pages; the
    // browser UI itself is tested in tests/ui.rs.
    let (s, _, headers) = app.call("GET", &format!("/api/issues/{}", enc(&id)), None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(headers["content-security-policy"].to_str().unwrap().contains("default-src 'none'"));
    assert_eq!(headers["x-content-type-options"], "nosniff");
    let (s, list, _) = app.call("GET", "/api/issues?q=&status=&category=waste", None, None).await;
    assert_eq!(s, StatusCode::OK, "empty query fields are ignored");
    assert!(list.contains("<script>alert"), "JSON returns the raw title; escaping is the renderer's job");

    let (s, bundle) = app.json("GET", &format!("/api/issues/{}/export", enc(&id)), None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(bundle["format"], "pardarsh.bundle");
    assert_eq!(bundle["completeness"], "filtered");

    // Hidden and unknown records look the same: 404.
    let (s, _) = app
        .json(
            "POST",
            &format!("/api/records/{}/moderation", enc(&id)),
            Some("moderator"),
            Some(json!({"action": "hide", "reason": "check"})),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _) = app.json("GET", &format!("/api/issues/{}", enc(&id)), None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) =
        app.json("GET", "/api/issues/pd%3Aloklekha.localhost%3A00000000-0000-7000-8000-000000000000", None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = app.json("GET", "/api/issues/garbage", None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (s, _) = app.json("GET", "/api/me", Some("ravi"), None).await;
    assert_eq!(s, StatusCode::OK);
    let mut bad = app.tokens.clone();
    bad.insert("ravi".into(), "lk_wrong".into());
    let wrong = App { router: app.router.clone(), tokens: bad };
    let (s, _) = wrong.json("GET", "/api/me", Some("ravi"), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn writes_are_rate_limited_and_idempotent() {
    let app = app(3);
    let body = json!({"title": "Overflowing drain", "category": "drainage"});
    let send = |key: &'static str| {
        let app = &app;
        let body = body.clone();
        async move {
            let req = Request::builder()
                .method("POST")
                .uri("/api/issues")
                .header("authorization", format!("Bearer {}", app.tokens["asha"]))
                .header("content-type", "application/json")
                .header("idempotency-key", key)
                .body(Body::from(body.to_string()))
                .unwrap();
            let resp = app.router.clone().oneshot(req).await.unwrap();
            let status = resp.status();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            (status, serde_json::from_slice::<Value>(&bytes).unwrap())
        }
    };
    let (s1, a) = send("k1").await;
    let (s2, b) = send("k1").await;
    assert_eq!((s1, s2), (StatusCode::CREATED, StatusCode::CREATED));
    assert_eq!(a["issue"]["id"], b["issue"]["id"], "retry returns the original issue");
    let (s3, _) = send("k2").await;
    assert_eq!(s3, StatusCode::CREATED);
    let (s4, _) = send("k3").await;
    assert_eq!(s4, StatusCode::TOO_MANY_REQUESTS);
    let (s, list) = app.json("GET", "/api/issues", None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 2);
}
