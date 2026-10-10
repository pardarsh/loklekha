//! Web user accounts: handles, roles and password hashes.
//!
//! Credentials never enter the pardarsh record store. Each user is linked to
//! a public `actor` record (the same one an API-token account with the same
//! handle uses), and passwords are hashed with Argon2 by the `password-auth`
//! crate.

use std::path::Path;
use std::sync::{Arc, Mutex};

use pardarsh_core::id::RecordId;
use pardarsh_core::storage::Store;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::identity::Account;
use crate::service::Ledger;
use crate::workflow::Role;

/// Minimum password length for new accounts.
pub const MIN_PASSWORD_LEN: usize = 10;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub handle: String,
    pub display_name: String,
    pub role: Role,
    pub actor_id: RecordId,
    pub institution: Option<RecordId>,
    /// Argon2 PHC string. Changing it invalidates existing sessions.
    pub password_hash: String,
}

impl User {
    pub fn account(&self) -> Account {
        Account {
            actor_id: self.actor_id.clone(),
            handle: self.handle.clone(),
            display_name: self.display_name.clone(),
            role: self.role,
            institution: self.institution.clone(),
        }
    }
}

/// A request to create a user.
#[derive(Clone, Debug)]
pub struct NewUser<'a> {
    pub handle: &'a str,
    pub display_name: &'a str,
    pub password: &'a str,
    pub role: Role,
    /// Handle of the institution a responder acts for.
    pub institution: Option<&'a str>,
}

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS lk_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    handle TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    institution_id TEXT,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
)";

fn db(e: rusqlite::Error) -> AppError {
    AppError::Core(pardarsh_core::Error::Storage(e.to_string()))
}

pub fn valid_handle(h: &str) -> bool {
    (2..=40).contains(&h.len()) && h.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// SQLite-backed user store. Cheap to clone.
#[derive(Clone)]
pub struct UserStore {
    conn: Arc<Mutex<Connection>>,
}

impl std::fmt::Debug for UserStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserStore").finish_non_exhaustive()
    }
}

impl UserStore {
    pub fn open(path: impl AsRef<Path>) -> AppResult<Self> {
        Self::init(Connection::open(path).map_err(db)?)
    }

    pub fn open_in_memory() -> AppResult<Self> {
        Self::init(Connection::open_in_memory().map_err(db)?)
    }

    fn init(conn: Connection) -> AppResult<Self> {
        conn.execute_batch(SCHEMA).map_err(db)?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Create a user, its actor record if needed, and hash the password.
    pub fn create<S: Store>(&self, ledger: &mut Ledger<S>, new: NewUser<'_>) -> AppResult<User> {
        if !valid_handle(new.handle) {
            return Err(AppError::BadRequest("handles are 2-40 characters of a-z, 0-9 and _".into()));
        }
        let display_name = new.display_name.trim();
        if display_name.is_empty() || display_name.chars().count() > 80 {
            return Err(AppError::BadRequest("display name must be 1-80 characters".into()));
        }
        if new.password.chars().count() < MIN_PASSWORD_LEN {
            return Err(AppError::BadRequest(format!("passwords need at least {MIN_PASSWORD_LEN} characters")));
        }
        if self.find_by_handle(new.handle)?.is_some() {
            return Err(AppError::BadRequest("that handle is taken".into()));
        }
        let institutions = ledger.institutions()?;
        if institutions.iter().any(|i| i.handle == new.handle) {
            return Err(AppError::BadRequest("that handle is taken".into()));
        }
        let institution = match (new.role, new.institution) {
            (Role::Responder, Some(h)) => Some(
                institutions
                    .iter()
                    .find(|i| i.handle == h)
                    .map(|i| i.id.clone())
                    .ok_or_else(|| AppError::BadRequest(format!("unknown institution {h}")))?,
            ),
            (Role::Responder, None) => return Err(AppError::BadRequest("responders need an institution".into())),
            (_, Some(_)) => return Err(AppError::BadRequest("only responders belong to an institution".into())),
            (_, None) => None,
        };
        let actor_id = ledger.ensure_actor(new.handle, display_name, "person")?;
        let password_hash = password_auth::generate_hash(new.password);
        let conn = self.conn();
        conn.execute(
            "INSERT INTO lk_users (handle, display_name, role, actor_id, institution_id, password_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                new.handle,
                display_name,
                role_str(new.role),
                actor_id.to_string(),
                institution.as_ref().map(|i| i.to_string()),
                password_hash
            ],
        )
        .map_err(db)?;
        let id = conn.last_insert_rowid();
        Ok(User {
            id,
            handle: new.handle.into(),
            display_name: display_name.into(),
            role: new.role,
            actor_id,
            institution,
            password_hash,
        })
    }

    pub fn find_by_id(&self, id: i64) -> AppResult<Option<User>> {
        self.find("id = ?1", params![id])
    }

    pub fn find_by_handle(&self, handle: &str) -> AppResult<Option<User>> {
        self.find("handle = ?1", params![handle])
    }

    fn find(&self, filter: &str, args: impl rusqlite::Params) -> AppResult<Option<User>> {
        let sql = format!(
            "SELECT id, handle, display_name, role, actor_id, institution_id, password_hash FROM lk_users WHERE {filter}"
        );
        let row = self
            .conn()
            .query_row(&sql, args, |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, String>(6)?,
                ))
            })
            .optional()
            .map_err(db)?;
        let Some((id, handle, display_name, role, actor, institution, password_hash)) = row else {
            return Ok(None);
        };
        let corrupt =
            |what: &str| AppError::Core(pardarsh_core::Error::Storage(format!("corrupt user row {id}: {what}")));
        Ok(Some(User {
            id,
            handle,
            display_name,
            role: parse_role(&role).ok_or_else(|| corrupt("role"))?,
            actor_id: actor.parse().map_err(|_| corrupt("actor id"))?,
            institution: institution.map(|i| i.parse()).transpose().map_err(|_| corrupt("institution id"))?,
            password_hash,
        }))
    }

    /// Check a handle and password. Runs the (deliberately slow) hash check
    /// even for unknown handles so timing does not reveal which handles exist.
    pub fn verify(&self, handle: &str, password: &str) -> AppResult<Option<User>> {
        static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        let dummy = DUMMY.get_or_init(|| password_auth::generate_hash("loklekha-timing-equaliser"));
        let user = self.find_by_handle(handle)?;
        let hash = user.as_ref().map_or(dummy.as_str(), |u| u.password_hash.as_str());
        let ok = password_auth::verify_password(password, hash).is_ok();
        Ok(user.filter(|_| ok))
    }

    pub fn set_password(&self, handle: &str, password: &str) -> AppResult<()> {
        if password.chars().count() < MIN_PASSWORD_LEN {
            return Err(AppError::BadRequest(format!("passwords need at least {MIN_PASSWORD_LEN} characters")));
        }
        let changed = self
            .conn()
            .execute(
                "UPDATE lk_users SET password_hash = ?1 WHERE handle = ?2",
                params![password_auth::generate_hash(password), handle],
            )
            .map_err(db)?;
        if changed == 0 { Err(AppError::NotFound) } else { Ok(()) }
    }

    pub fn count(&self) -> AppResult<i64> {
        self.conn().query_row("SELECT COUNT(*) FROM lk_users", [], |r| r.get(0)).map_err(db)
    }
}

fn role_str(role: Role) -> &'static str {
    match role {
        Role::Citizen => "citizen",
        Role::Responder => "responder",
        Role::Moderator => "moderator",
        Role::Admin => "admin",
    }
}

/// Parse a role name as used in the database and CLI.
pub fn parse_role(s: &str) -> Option<Role> {
    match s {
        "citizen" => Some(Role::Citizen),
        "responder" => Some(Role::Responder),
        "moderator" => Some(Role::Moderator),
        "admin" => Some(Role::Admin),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pardarsh_core::id::Origin;
    use pardarsh_core::storage::MemoryStore;

    fn setup() -> (UserStore, Ledger<MemoryStore>) {
        let mut ledger = Ledger::new(MemoryStore::new(Origin::new("users.test").unwrap()));
        ledger.ensure_actor("ward7_works", "Ward 7 Works", "institution").unwrap();
        (UserStore::open_in_memory().unwrap(), ledger)
    }

    fn citizen<'a>(handle: &'a str, password: &'a str) -> NewUser<'a> {
        NewUser { handle, display_name: "Asha K", password, role: Role::Citizen, institution: None }
    }

    #[test]
    fn create_find_and_verify() {
        let (users, mut ledger) = setup();
        let u = users.create(&mut ledger, citizen("asha", "correct horse battery")).unwrap();
        assert!(u.password_hash.starts_with("$argon2"), "{}", u.password_hash);
        assert_eq!(users.find_by_id(u.id).unwrap().unwrap(), u);
        assert_eq!(users.find_by_handle("asha").unwrap().unwrap(), u);
        assert!(users.find_by_handle("nobody").unwrap().is_none());
        assert!(users.find_by_id(999).unwrap().is_none());
        assert_eq!(users.verify("asha", "correct horse battery").unwrap().unwrap().id, u.id);
        assert!(users.verify("asha", "wrong password!").unwrap().is_none());
        assert!(users.verify("nobody", "correct horse battery").unwrap().is_none());
        assert_eq!(users.count().unwrap(), 1);
        let account = u.account();
        assert_eq!(account.handle, "asha");
        assert_eq!(account.role, Role::Citizen);
        assert_eq!(account.actor_id, ledger.ensure_actor("asha", "x", "person").unwrap(), "shares the actor record");
    }

    #[test]
    fn create_rejects_bad_input() {
        let (users, mut ledger) = setup();
        users.create(&mut ledger, citizen("asha", "correct horse battery")).unwrap();
        let bad = |u: NewUser<'_>, users: &UserStore, ledger: &mut Ledger<MemoryStore>| match users.create(ledger, u) {
            Err(AppError::BadRequest(m)) => m,
            other => panic!("expected BadRequest, got {:?}", other.map(|u| u.handle)),
        };
        assert!(bad(citizen("Asha", "correct horse battery"), &users, &mut ledger).contains("handles"));
        assert!(bad(citizen("asha", "correct horse battery"), &users, &mut ledger).contains("taken"));
        assert!(bad(citizen("ward7_works", "correct horse battery"), &users, &mut ledger).contains("taken"));
        assert!(bad(citizen("ravi", "short"), &users, &mut ledger).contains("at least"));
        let mut blank = citizen("ravi", "correct horse battery");
        blank.display_name = "   ";
        assert!(bad(blank, &users, &mut ledger).contains("display name"));
        let responder = |institution| NewUser {
            handle: "eng",
            display_name: "Eng",
            password: "correct horse battery",
            role: Role::Responder,
            institution,
        };
        assert!(bad(responder(None), &users, &mut ledger).contains("need an institution"));
        assert!(bad(responder(Some("nowhere")), &users, &mut ledger).contains("unknown institution"));
        let mut mod_with_inst = citizen("mod", "correct horse battery");
        mod_with_inst.role = Role::Moderator;
        mod_with_inst.institution = Some("ward7_works");
        assert!(bad(mod_with_inst, &users, &mut ledger).contains("only responders"));
        let eng = users.create(&mut ledger, responder(Some("ward7_works"))).unwrap();
        assert!(eng.institution.is_some());
        assert_eq!(users.find_by_handle("eng").unwrap().unwrap().institution, eng.institution);
    }

    #[test]
    fn set_password_and_roles_round_trip() {
        let (users, mut ledger) = setup();
        for (handle, role) in [("cit", Role::Citizen), ("mod", Role::Moderator), ("adm", Role::Admin)] {
            let u = users
                .create(
                    &mut ledger,
                    NewUser {
                        handle,
                        display_name: handle,
                        password: "correct horse battery",
                        role,
                        institution: None,
                    },
                )
                .unwrap();
            assert_eq!(users.find_by_id(u.id).unwrap().unwrap().role, role);
        }
        users.set_password("cit", "another long password").unwrap();
        assert!(users.verify("cit", "correct horse battery").unwrap().is_none());
        assert!(users.verify("cit", "another long password").unwrap().is_some());
        assert!(matches!(users.set_password("cit", "short"), Err(AppError::BadRequest(_))));
        assert!(matches!(users.set_password("nobody", "another long password"), Err(AppError::NotFound)));
        assert_eq!(parse_role("emperor"), None);
    }

    #[test]
    fn persists_on_disk_and_detects_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("users.sqlite");
        let (_, mut ledger) = setup();
        let id =
            UserStore::open(&path).unwrap().create(&mut ledger, citizen("asha", "correct horse battery")).unwrap().id;
        let users = UserStore::open(&path).unwrap();
        assert!(users.find_by_id(id).unwrap().is_some());
        users.conn().execute("UPDATE lk_users SET role = 'emperor'", []).unwrap();
        assert!(matches!(users.find_by_id(id), Err(AppError::Core(_))));
        assert!(format!("{users:?}").contains("UserStore"));
    }
}
