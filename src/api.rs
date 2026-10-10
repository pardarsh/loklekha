//! JSON HTTP API, authenticated with bearer tokens. The browser UI lives in [`crate::ui`].

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use pardarsh_core::id::{RecordId, RelationId};
use pardarsh_core::storage::Store;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::error::{AppError, AppResult};
use crate::identity::{Accounts, Session};
use crate::service::{Ledger, SearchQuery};

/// Simple per-account sliding-window limit on writes.
pub struct RateLimiter {
    per_minute: u32,
    hits: HashMap<String, VecDeque<Instant>>,
}

impl RateLimiter {
    pub fn new(per_minute: u32) -> Self {
        Self { per_minute, hits: HashMap::new() }
    }

    fn check(&mut self, key: &str) -> AppResult<()> {
        self.check_at(key, Instant::now())
    }

    fn check_at(&mut self, key: &str, now: Instant) -> AppResult<()> {
        let q = self.hits.entry(key.to_string()).or_default();
        while q.front().is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60)) {
            q.pop_front();
        }
        if q.len() as u32 >= self.per_minute {
            return Err(AppError::RateLimited);
        }
        q.push_back(now);
        Ok(())
    }
}

pub struct AppState<S: Store> {
    pub ledger: Mutex<Ledger<S>>,
    pub accounts: Accounts,
    pub limiter: Mutex<RateLimiter>,
}

impl<S: Store> AppState<S> {
    pub fn new(ledger: Ledger<S>, accounts: Accounts, writes_per_minute: u32) -> Arc<Self> {
        Arc::new(Self {
            ledger: Mutex::new(ledger),
            accounts,
            limiter: Mutex::new(RateLimiter::new(writes_per_minute)),
        })
    }

    pub(crate) fn ledger(&self) -> MutexGuard<'_, Ledger<S>> {
        self.ledger.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn session(&self, headers: &HeaderMap) -> AppResult<Session> {
        let auth =
            headers.get(header::AUTHORIZATION).map(|v| v.to_str().map_err(|_| AppError::Unauthorized)).transpose()?;
        self.accounts.session_for_bearer(auth)
    }

    /// Count a write against the per-account limit.
    pub(crate) fn rate_limit(&self, handle: &str) -> AppResult<()> {
        self.limiter.lock().unwrap_or_else(|e| e.into_inner()).check(handle)
    }

    /// Authenticate, rate-limit and read the idempotency key of a write.
    fn writer(&self, headers: &HeaderMap) -> AppResult<(Session, Option<String>)> {
        let session = self.session(headers)?;
        let account = session.require()?;
        self.rate_limit(&account.handle)?;
        let key = headers
            .get("idempotency-key")
            .map(|v| v.to_str().map(str::to_string).map_err(|_| AppError::BadRequest("invalid Idempotency-Key".into())))
            .transpose()?;
        Ok((session, key))
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            AppError::Core(e) => match e {
                pardarsh_core::Error::Validation(_) => StatusCode::UNPROCESSABLE_ENTITY,
                pardarsh_core::Error::NotFound(_) => StatusCode::NOT_FOUND,
                pardarsh_core::Error::Conflict { .. } | pardarsh_core::Error::IdempotencyConflict(_) => {
                    StatusCode::CONFLICT
                }
                pardarsh_core::Error::NotPermitted(_) => StatusCode::FORBIDDEN,
                pardarsh_core::Error::Id(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
        };
        let message = if status == StatusCode::INTERNAL_SERVER_ERROR {
            eprintln!("internal error: {self}");
            "internal error".to_string()
        } else if let AppError::Core(pardarsh_core::Error::NotFound(_)) = self {
            "not found".to_string()
        } else {
            self.to_string()
        };
        let body = json!({ "error": message, "issues": self.validation_issues() });
        let mut resp = (status, Json(body)).into_response();
        if status == StatusCode::UNAUTHORIZED {
            resp.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        resp
    }
}

fn parse<T: DeserializeOwned>(body: &Bytes) -> AppResult<T> {
    serde_json::from_slice(body).map_err(|e| AppError::BadRequest(format!("invalid request body: {e}")))
}

fn id(raw: &str) -> AppResult<RecordId> {
    raw.parse().map_err(|_| AppError::NotFound)
}

type St<S> = State<Arc<AppState<S>>>;

/// Security headers for every response (API and UI).
pub(crate) async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
    );
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    resp
}

pub fn router<S: Store + 'static>(state: Arc<AppState<S>>) -> Router {
    Router::new()
        .route("/api/me", get(me::<S>))
        .route("/api/institutions", get(institutions::<S>))
        .route("/api/issues", get(search::<S>).post(create_issue::<S>))
        .route("/api/issues/duplicates", get(duplicates::<S>))
        .route("/api/issues/{id}", get(issue_detail::<S>))
        .route("/api/issues/{id}/export", get(export_issue::<S>))
        .route("/api/issues/{id}/evidence", post(add_evidence::<S>))
        .route("/api/issues/{id}/proposals", post(propose::<S>))
        .route("/api/issues/{id}/links", post(link::<S>))
        .route("/api/issues/{id}/transitions", post(transition::<S>))
        .route("/api/issues/{id}/assignments", post(assign::<S>))
        .route("/api/issues/{id}/assignments/{relation}", delete(unassign::<S>))
        .route("/api/issues/{id}/actions", post(plan_action::<S>))
        .route("/api/issues/{id}/completion-claims", post(claim::<S>))
        .route("/api/issues/{id}/outcomes", post(outcome::<S>))
        .route("/api/records/{id}", get(record::<S>))
        .route("/api/records/{id}/comments", post(comment::<S>))
        .route("/api/records/{id}/reports", post(report::<S>))
        .route("/api/records/{id}/moderation", post(moderate::<S>))
        .route("/api/proposals/{id}/decisions", post(decide::<S>))
        .route("/api/actions/{id}/progress", post(action_progress::<S>))
        .route("/api/moderation/queue", get(queue::<S>))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

// ---- reads -------------------------------------------------------------------

async fn me<S: Store + 'static>(State(st): St<S>, headers: HeaderMap) -> AppResult<Response> {
    let session = st.session(&headers)?;
    Ok(Json(session.require()?.clone()).into_response())
}

async fn institutions<S: Store + 'static>(State(st): St<S>) -> AppResult<Response> {
    Ok(Json(st.ledger().institutions()?).into_response())
}

async fn search<S: Store + 'static>(
    State(st): St<S>,
    headers: HeaderMap,
    Query(q): Query<SearchQuery>,
) -> AppResult<Response> {
    let session = st.session(&headers)?;
    Ok(Json(st.ledger().search(&session, &q)?).into_response())
}

#[derive(Deserialize)]
struct DuplicateQuery {
    title: String,
    #[serde(default)]
    description: String,
}

async fn duplicates<S: Store + 'static>(
    State(st): St<S>,
    headers: HeaderMap,
    Query(q): Query<DuplicateQuery>,
) -> AppResult<Response> {
    let session = st.session(&headers)?;
    Ok(Json(st.ledger().suggest_duplicates(&session, &q.title, &q.description)?).into_response())
}

async fn issue_detail<S: Store + 'static>(
    State(st): St<S>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> AppResult<Response> {
    let session = st.session(&headers)?;
    Ok(Json(st.ledger().issue_detail(&session, &id(&raw)?)?).into_response())
}

async fn export_issue<S: Store + 'static>(
    State(st): St<S>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> AppResult<Response> {
    let session = st.session(&headers)?;
    Ok(Json(st.ledger().export_issue(&session, &id(&raw)?)?).into_response())
}

async fn record<S: Store + 'static>(
    State(st): St<S>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> AppResult<Response> {
    let session = st.session(&headers)?;
    let (record, timeline) = st.ledger().record(&session, &id(&raw)?)?;
    Ok(Json(json!({ "record": record, "timeline": timeline })).into_response())
}

async fn queue<S: Store + 'static>(State(st): St<S>, headers: HeaderMap) -> AppResult<Response> {
    let session = st.session(&headers)?;
    Ok(Json(st.ledger().moderation_queue(&session)?).into_response())
}

// ---- writes ------------------------------------------------------------------

fn created<T: serde::Serialize>(v: T) -> Response {
    (StatusCode::CREATED, Json(v)).into_response()
}

macro_rules! write_handler {
    ($name:ident, |$ledger:ident, $session:ident, $id:ident, $key:ident, $body:ident| $call:expr) => {
        async fn $name<S: Store + 'static>(
            State(st): St<S>,
            headers: HeaderMap,
            Path(raw): Path<String>,
            $body: Bytes,
        ) -> AppResult<Response> {
            let ($session, $key) = st.writer(&headers)?;
            let $id = id(&raw)?;
            let mut $ledger = st.ledger();
            let $key = $key.as_deref();
            Ok(created($call?))
        }
    };
}

async fn create_issue<S: Store + 'static>(State(st): St<S>, headers: HeaderMap, body: Bytes) -> AppResult<Response> {
    let (session, key) = st.writer(&headers)?;
    let input = parse(&body)?;
    Ok(created(st.ledger().create_issue(&session, input, key.as_deref())?))
}

write_handler!(add_evidence, |l, s, id, key, body| l.add_evidence(&s, &id, parse(&body)?, key));
write_handler!(propose, |l, s, id, key, body| l.propose(&s, &id, parse(&body)?, key));
write_handler!(link, |l, s, id, key, body| l.link_issues(&s, &id, parse(&body)?, key));
write_handler!(transition, |l, s, id, key, body| l.transition(&s, &id, parse(&body)?, key));
write_handler!(assign, |l, s, id, key, body| l.assign(&s, &id, parse(&body)?, key));
write_handler!(plan_action, |l, s, id, key, body| l.plan_action(&s, &id, parse(&body)?, key));
write_handler!(claim, |l, s, id, key, body| l.claim_completion(&s, &id, parse(&body)?, key));
write_handler!(outcome, |l, s, id, key, body| l.record_outcome(&s, &id, parse(&body)?, key));
write_handler!(comment, |l, s, id, key, body| l.comment(&s, &id, parse(&body)?, key));
write_handler!(report, |l, s, id, key, body| l.report(&s, &id, parse(&body)?, key).map(|id| json!({ "report": id })));
write_handler!(decide, |l, s, id, key, body| l.decide(&s, &id, parse(&body)?, key));
write_handler!(moderate, |l, s, id, _key, body| l.moderate(&s, &id, parse(&body)?));
write_handler!(action_progress, |l, s, id, _key, body| l.update_action(&s, &id, parse(&body)?));

#[derive(Deserialize)]
struct UnassignQuery {
    reason: String,
}

async fn unassign<S: Store + 'static>(
    State(st): St<S>,
    headers: HeaderMap,
    Path((raw, relation)): Path<(String, String)>,
    Query(q): Query<UnassignQuery>,
) -> AppResult<Response> {
    let (session, _) = st.writer(&headers)?;
    let relation: RelationId = relation.parse().map_err(|_| AppError::NotFound)?;
    Ok(Json(st.ledger().unassign(&session, &id(&raw)?, relation, &q.reason)?).into_response())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use pardarsh_core::id::{Origin, RecordId};
    use pardarsh_core::validation::ValidationErrors;

    use super::*;

    #[test]
    fn rate_limiter_allows_a_window_then_refuses_then_recovers() {
        let mut l = RateLimiter::new(2);
        let t0 = Instant::now();
        l.check_at("asha", t0).unwrap();
        l.check_at("asha", t0 + Duration::from_secs(1)).unwrap();
        assert!(matches!(l.check_at("asha", t0 + Duration::from_secs(2)), Err(AppError::RateLimited)));
        // Limits are per account.
        l.check_at("ravi", t0 + Duration::from_secs(2)).unwrap();
        // Requests older than a minute leave the window.
        l.check_at("asha", t0 + Duration::from_secs(61)).unwrap();
        assert!(matches!(l.check_at("asha", t0 + Duration::from_secs(61)), Err(AppError::RateLimited)));
        l.check_at("asha", t0 + Duration::from_secs(200)).unwrap();
        assert!(l.check("new_user").is_ok());
    }

    #[test]
    fn rate_limit_of_zero_refuses_every_write() {
        let mut l = RateLimiter::new(0);
        assert!(matches!(l.check("asha"), Err(AppError::RateLimited)));
    }

    fn status_of(e: AppError) -> (StatusCode, serde_json::Value, Option<String>) {
        let resp = e.into_response();
        let status = resp.status();
        let auth = resp.headers().get("www-authenticate").map(|v| v.to_str().unwrap().to_string());
        let body = futures_body(resp);
        (status, body, auth)
    }

    fn futures_body(resp: axum::response::Response) -> serde_json::Value {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let bytes = rt.block_on(axum::body::to_bytes(resp.into_body(), usize::MAX)).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn errors_map_to_status_codes_without_leaking_internals() {
        let id = RecordId::generate(&Origin::new("test.local").unwrap());
        let cases = vec![
            (AppError::Unauthorized, StatusCode::UNAUTHORIZED),
            (AppError::Forbidden("no".into()), StatusCode::FORBIDDEN),
            (AppError::NotFound, StatusCode::NOT_FOUND),
            (AppError::BadRequest("bad".into()), StatusCode::BAD_REQUEST),
            (AppError::RateLimited, StatusCode::TOO_MANY_REQUESTS),
            (
                pardarsh_core::Error::Validation(ValidationErrors::single("title", "empty")).into(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (pardarsh_core::Error::NotFound(id.clone()).into(), StatusCode::NOT_FOUND),
            (pardarsh_core::Error::Conflict { id: id.clone(), expected: 1, actual: 2 }.into(), StatusCode::CONFLICT),
            (pardarsh_core::Error::IdempotencyConflict("k".into()).into(), StatusCode::CONFLICT),
            (pardarsh_core::Error::NotPermitted("retracted".into()).into(), StatusCode::FORBIDDEN),
            (
                pardarsh_core::Error::Id(pardarsh_core::id::IdError::InvalidRecordId("x".into())).into(),
                StatusCode::BAD_REQUEST,
            ),
            (pardarsh_core::Error::Storage("disk on fire at /var/db".into()).into(), StatusCode::INTERNAL_SERVER_ERROR),
            (pardarsh_core::Error::Serialization("oops".into()).into(), StatusCode::INTERNAL_SERVER_ERROR),
        ];
        for (err, expected) in cases {
            let label = format!("{err:?}");
            let (status, body, auth) = status_of(err);
            assert_eq!(status, expected, "{label}");
            assert_eq!(auth.is_some(), expected == StatusCode::UNAUTHORIZED, "{label}");
            let message = body["error"].as_str().unwrap();
            if expected == StatusCode::INTERNAL_SERVER_ERROR {
                assert_eq!(message, "internal error", "internals must not leak");
            }
            if label.contains("NotFound") {
                assert_eq!(message, "not found", "record ids must not leak");
            }
        }
        let (_, body, _) =
            status_of(pardarsh_core::Error::Validation(ValidationErrors::single("title", "empty")).into());
        assert_eq!(body["issues"][0]["path"], "title");
        let (_, body, _) = status_of(AppError::Forbidden("no".into()));
        assert!(body["issues"].is_null());
    }

    #[test]
    fn ids_in_paths() {
        assert!(id("pd:test.local:0190a5d2-5b8e-7cc4-9a43-6e3d6f0c3c11").is_ok());
        assert!(matches!(id("nope"), Err(AppError::NotFound)));
    }

    #[test]
    fn bodies_must_be_json_of_the_right_shape() {
        #[derive(serde::Deserialize, Debug)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct T {
            a: u8,
        }
        assert!(parse::<T>(&Bytes::from_static(br#"{"a":1}"#)).is_ok());
        for bad in [&b""[..], b"{", br#"{"a":"x"}"#, br#"{"a":1,"b":2}"#] {
            assert!(matches!(parse::<T>(&Bytes::copy_from_slice(bad)), Err(AppError::BadRequest(_))));
        }
    }
}
