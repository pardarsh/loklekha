//! Accounts, sessions and API tokens.
//!
//! Every account is backed by a public `actor` record (so contributions are
//! attributable in the core graph), but credentials and roles never enter the
//! record store. Tokens are stored only as SHA-256 hashes.

use std::collections::HashMap;

use pardarsh_core::access::Viewer;
use pardarsh_core::id::RecordId;
use pardarsh_core::model::{ActorRef, Attribution};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{AppError, AppResult};
use crate::vocab::MODERATORS;
use crate::workflow::Role;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub actor_id: RecordId,
    pub handle: String,
    pub display_name: String,
    pub role: Role,
    /// Institution (actor record) a responder acts for.
    pub institution: Option<RecordId>,
}

impl Account {
    pub fn actor_ref(&self) -> ActorRef {
        ActorRef::Record { id: self.actor_id.clone() }
    }

    pub fn is_moderator(&self) -> bool {
        matches!(self.role, Role::Moderator | Role::Admin)
    }
}

/// The caller of a request.
#[derive(Clone, Debug, Default)]
pub enum Session {
    #[default]
    Anonymous,
    User(Account),
}

impl Session {
    pub fn account(&self) -> Option<&Account> {
        match self {
            Session::User(a) => Some(a),
            Session::Anonymous => None,
        }
    }

    pub fn require(&self) -> AppResult<&Account> {
        self.account().ok_or(AppError::Unauthorized)
    }

    pub fn require_moderator(&self) -> AppResult<&Account> {
        let a = self.require()?;
        if a.is_moderator() { Ok(a) } else { Err(AppError::Forbidden("moderator role required".into())) }
    }

    /// What this caller may see.
    pub fn viewer(&self) -> Viewer {
        match self {
            Session::Anonymous => Viewer::public(),
            Session::User(a) => {
                let mut v = Viewer::actor(a.actor_ref());
                if a.is_moderator() {
                    v = v.with_audience(MODERATORS);
                    v.privileged = true;
                }
                v
            }
        }
    }

    pub fn attribution(&self) -> AppResult<Attribution> {
        Ok(Attribution::public(self.require()?.actor_ref()))
    }
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// A new random API token (256 bits).
pub fn generate_token() -> String {
    format!("lk_{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple())
}

/// Token-hash → account lookup.
#[derive(Clone, Debug, Default)]
pub struct Accounts {
    by_token_hash: HashMap<String, Account>,
}

impl Accounts {
    pub fn insert(&mut self, token_sha256: String, account: Account) {
        self.by_token_hash.insert(token_sha256.to_ascii_lowercase(), account);
    }

    pub fn authenticate(&self, token: &str) -> Option<&Account> {
        self.by_token_hash.get(&hash_token(token))
    }

    pub fn session_for_bearer(&self, header: Option<&str>) -> AppResult<Session> {
        match header {
            None => Ok(Session::Anonymous),
            Some(h) => {
                let token = h.strip_prefix("Bearer ").ok_or(AppError::Unauthorized)?;
                self.authenticate(token.trim()).cloned().map(Session::User).ok_or(AppError::Unauthorized)
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Account> {
        self.by_token_hash.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pardarsh_core::id::Origin;

    fn account(role: Role) -> Account {
        Account {
            actor_id: RecordId::generate(&Origin::new("test.local").unwrap()),
            handle: "asha".into(),
            display_name: "Asha".into(),
            role,
            institution: None,
        }
    }

    fn accounts() -> (Accounts, String) {
        let token = generate_token();
        let mut a = Accounts::default();
        // Stored hashes are normalised to lowercase.
        a.insert(hash_token(&token).to_ascii_uppercase(), account(Role::Citizen));
        (a, token)
    }

    #[test]
    fn tokens_are_random_prefixed_and_hashed() {
        let (a, b) = (generate_token(), generate_token());
        assert_ne!(a, b);
        assert!(a.starts_with("lk_") && a.len() == 67, "{a}");
        let h = hash_token("secret");
        assert_eq!(h.len(), 64);
        assert_eq!(h, hash_token("secret"));
        assert_ne!(h, hash_token("Secret"));
    }

    #[test]
    fn authenticates_by_token_hash() {
        let (a, token) = accounts();
        assert_eq!(a.authenticate(&token).unwrap().handle, "asha");
        assert!(a.authenticate("lk_wrong").is_none());
        assert_eq!(a.iter().count(), 1);
    }

    #[test]
    fn bearer_header_parsing() {
        let (a, token) = accounts();
        assert!(matches!(a.session_for_bearer(None), Ok(Session::Anonymous)));
        assert!(matches!(a.session_for_bearer(Some(&format!("Bearer {token}"))), Ok(Session::User(_))));
        assert!(matches!(a.session_for_bearer(Some(&format!("Bearer  {token} "))), Ok(Session::User(_))));
        assert!(matches!(a.session_for_bearer(Some(&token)), Err(AppError::Unauthorized)));
        assert!(matches!(a.session_for_bearer(Some(&format!("Basic {token}"))), Err(AppError::Unauthorized)));
        assert!(matches!(a.session_for_bearer(Some("Bearer lk_wrong")), Err(AppError::Unauthorized)));
    }

    #[test]
    fn sessions_and_viewers() {
        let anon = Session::Anonymous;
        assert!(anon.account().is_none());
        assert!(matches!(anon.require(), Err(AppError::Unauthorized)));
        assert!(matches!(anon.attribution(), Err(AppError::Unauthorized)));
        assert!(matches!(anon.require_moderator(), Err(AppError::Unauthorized)));
        assert_eq!(anon.viewer(), Viewer::public());

        let citizen = Session::User(account(Role::Citizen));
        assert!(matches!(citizen.require_moderator(), Err(AppError::Forbidden(_))));
        let v = citizen.viewer();
        assert!(!v.privileged && v.audiences.is_empty());
        assert_eq!(v.actor, Some(citizen.account().unwrap().actor_ref()));
        assert_eq!(citizen.attribution().unwrap().actor, citizen.account().unwrap().actor_ref());

        for role in [Role::Moderator, Role::Admin] {
            let s = Session::User(account(role));
            assert!(s.require_moderator().is_ok());
            let v = s.viewer();
            assert!(v.privileged && v.audiences.contains(MODERATORS));
        }
        assert!(!account(Role::Responder).is_moderator());
    }
}
