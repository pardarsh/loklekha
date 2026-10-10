//! Assembles the full web application: JSON API plus browser UI with
//! sessions (`tower-sessions`), sign-in (`axum-login`) and CSRF protection
//! (`axum_csrf`).

use std::sync::Arc;

use axum::Router;
use axum_csrf::{CsrfConfig, Key};
use axum_login::AuthManagerLayerBuilder;
use pardarsh_core::storage::Store;
use tower_sessions::cookie::{SameSite, time::Duration};
use tower_sessions::{Expiry, SessionManagerLayer, SessionStore};

use crate::api::{self, AppState};
use crate::auth::Backend;
use crate::ui::{self, UiState};
use crate::users::UserStore;

/// Cookie settings for the browser UI.
#[derive(Clone, Debug)]
pub struct WebConfig {
    /// Send cookies only over HTTPS. Turn off only for local development.
    pub secure_cookies: bool,
    /// Sign users out after this much inactivity.
    pub session_days: i64,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self { secure_cookies: true, session_days: 14 }
    }
}

pub fn app<S, SS>(state: Arc<AppState<S>>, users: UserStore, sessions: SS, web: &WebConfig) -> Router
where
    S: Store + 'static,
    SS: SessionStore + Clone,
{
    let session_layer = SessionManagerLayer::new(sessions)
        .with_name("loklekha_session")
        .with_secure(web.secure_cookies)
        .with_http_only(true)
        .with_same_site(SameSite::Lax)
        .with_expiry(Expiry::OnInactivity(Duration::days(web.session_days)));
    let auth = AuthManagerLayerBuilder::new(Backend { users: users.clone() }, session_layer).build();
    let csrf = CsrfConfig::default()
        .with_key(Some(Key::generate()))
        .with_cookie_name("loklekha_csrf")
        .with_secure(web.secure_cookies)
        .with_http_only(true)
        .with_cookie_same_site(axum_csrf::SameSite::Strict);
    let ui = ui::router(UiState { app: state.clone(), users, csrf }).layer(auth);
    Router::new().merge(api::router(state)).merge(ui)
}
