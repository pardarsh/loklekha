//! Browser sign-in, built on `axum-login` (authentication flow) and
//! `tower-sessions` (session cookies and storage).

use axum_login::{AuthUser, AuthnBackend, UserId};
use serde::Deserialize;

use crate::error::AppError;
use crate::users::{User, UserStore};

impl AuthUser for User {
    type Id = i64;

    fn id(&self) -> Self::Id {
        self.id
    }

    /// Sessions are bound to the password hash, so changing a password signs
    /// the user out everywhere.
    fn session_auth_hash(&self) -> &[u8] {
        self.password_hash.as_bytes()
    }
}

/// Sign-in form fields.
#[derive(Clone, Deserialize)]
pub struct Credentials {
    pub handle: String,
    pub password: String,
    /// Where to go after signing in (must be a local path).
    #[serde(default)]
    pub next: Option<String>,
    #[serde(default)]
    pub authenticity_token: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials").field("handle", &self.handle).finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct Backend {
    pub users: UserStore,
}

#[derive(Debug, thiserror::Error)]
#[error("authentication backend error: {0}")]
pub struct BackendError(String);

impl From<AppError> for BackendError {
    fn from(e: AppError) -> Self {
        BackendError(e.to_string())
    }
}

impl AuthnBackend for Backend {
    type User = User;
    type Credentials = Credentials;
    type Error = BackendError;

    async fn authenticate(&self, creds: Self::Credentials) -> Result<Option<Self::User>, Self::Error> {
        let users = self.users.clone();
        // Argon2 is deliberately slow; keep it off the async worker threads.
        tokio::task::spawn_blocking(move || users.verify(creds.handle.trim(), &creds.password))
            .await
            .map_err(|e| BackendError(e.to_string()))?
            .map_err(Into::into)
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        Ok(self.users.find_by_id(*user_id)?)
    }
}

pub type AuthSession = axum_login::AuthSession<Backend>;

/// Only allow redirects to local paths ("/issues/..."), never to other sites.
pub fn safe_next(next: Option<&str>) -> String {
    match next {
        Some(n) if n.starts_with('/') && !n.starts_with("//") && !n.contains('\\') && !n.contains("://") => {
            n.to_string()
        }
        _ => "/".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::Ledger;
    use crate::users::NewUser;
    use crate::workflow::Role;
    use pardarsh_core::id::Origin;
    use pardarsh_core::storage::MemoryStore;

    #[test]
    fn next_paths_must_be_local() {
        assert_eq!(safe_next(Some("/issues/pd%3Ax")), "/issues/pd%3Ax");
        assert_eq!(safe_next(Some("/")), "/");
        for bad in [
            None,
            Some(""),
            Some("https://evil.example"),
            Some("//evil.example"),
            Some("/\\evil"),
            Some("issues"),
            Some("/x?u=http://e"),
        ] {
            assert_eq!(safe_next(bad), "/", "{bad:?}");
        }
    }

    #[tokio::test]
    async fn backend_authenticates_and_loads_users() {
        let users = UserStore::open_in_memory().unwrap();
        let mut ledger = Ledger::new(MemoryStore::new(Origin::new("auth.test").unwrap()));
        let u = users
            .create(
                &mut ledger,
                NewUser {
                    handle: "asha",
                    display_name: "Asha",
                    password: "correct horse battery",
                    role: Role::Citizen,
                    institution: None,
                },
            )
            .unwrap();
        let backend = Backend { users };
        let creds = |p: &str| Credentials {
            handle: " asha ".into(),
            password: p.into(),
            next: None,
            authenticity_token: String::new(),
        };
        assert_eq!(backend.authenticate(creds("correct horse battery")).await.unwrap().unwrap().id, u.id);
        assert!(backend.authenticate(creds("nope nope nope")).await.unwrap().is_none());
        assert_eq!(backend.get_user(&u.id).await.unwrap().unwrap().handle, "asha");
        assert!(backend.get_user(&12345).await.unwrap().is_none());
        assert_eq!(u.session_auth_hash(), u.password_hash.as_bytes());
        assert_eq!(AuthUser::id(&u), u.id);
        assert!(!format!("{:?}", creds("secret-password")).contains("secret-password"), "passwords are not logged");
        assert!(BackendError::from(AppError::NotFound).to_string().contains("not found"));
    }
}
