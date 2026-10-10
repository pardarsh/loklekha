//! Instance configuration and bootstrap of institutions and accounts.

use std::collections::HashMap;

use pardarsh_core::storage::Store;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::identity::{Account, Accounts, generate_token, hash_token};
use crate::service::Ledger;
use crate::workflow::Role;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// DNS-like name of this instance; becomes part of every record id.
    pub origin: String,
    /// SQLite database path.
    pub database: String,
    pub bind: String,
    #[serde(default = "default_writes_per_minute")]
    pub writes_per_minute: u32,
    /// Mark session and CSRF cookies `Secure` (HTTPS only). Keep on in
    /// production; the demo configuration turns it off for plain-HTTP localhost.
    #[serde(default = "default_secure_cookies")]
    pub secure_cookies: bool,
    #[serde(default)]
    pub institutions: Vec<InstitutionConfig>,
    #[serde(default)]
    pub accounts: Vec<AccountConfig>,
}

fn default_writes_per_minute() -> u32 {
    30
}

fn default_secure_cookies() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstitutionConfig {
    pub handle: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConfig {
    pub handle: String,
    pub name: String,
    pub role: Role,
    /// Handle of the institution a responder acts for.
    #[serde(default)]
    pub institution: Option<String>,
    /// SHA-256 (hex) of the account's API token. Tokens are never stored.
    pub token_sha256: String,
}

fn valid_handle(h: &str) -> bool {
    (2..=40).contains(&h.len()) && h.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

impl Config {
    pub fn load(path: &str) -> AppResult<Self> {
        let raw =
            std::fs::read_to_string(path).map_err(|e| AppError::BadRequest(format!("cannot read {path}: {e}")))?;
        serde_json::from_str(&raw).map_err(|e| AppError::BadRequest(format!("invalid config {path}: {e}")))
    }

    /// A demo configuration with fresh tokens. Returns the config and the
    /// plaintext tokens (shown once).
    pub fn demo() -> (Self, Vec<(String, String)>) {
        let mut tokens = Vec::new();
        let mut account = |handle: &str, name: &str, role: Role, institution: Option<&str>| {
            let token = generate_token();
            let cfg = AccountConfig {
                handle: handle.into(),
                name: name.into(),
                role,
                institution: institution.map(str::to_string),
                token_sha256: hash_token(&token),
            };
            tokens.push((handle.to_string(), token));
            cfg
        };
        let accounts = vec![
            account("asha", "Asha (resident)", Role::Citizen, None),
            account("ravi", "Ravi (resident)", Role::Citizen, None),
            account("ward7_engineer", "Ward 7 Assistant Engineer", Role::Responder, Some("ward7_works")),
            account("moderator", "Volunteer moderator", Role::Moderator, None),
        ];
        let config = Config {
            origin: "loklekha.localhost".into(),
            database: "loklekha.sqlite".into(),
            bind: "127.0.0.1:8080".into(),
            writes_per_minute: default_writes_per_minute(),
            secure_cookies: false,
            institutions: vec![
                InstitutionConfig { handle: "ward7_works".into(), name: "Ward 7 Public Works Office (demo)".into() },
                InstitutionConfig { handle: "city_water".into(), name: "City Water Board (demo)".into() },
            ],
            accounts,
        };
        (config, tokens)
    }
}

/// Make sure every configured institution and account has an actor record,
/// and build the token lookup.
pub fn bootstrap<S: Store>(ledger: &mut Ledger<S>, config: &Config) -> AppResult<Accounts> {
    let mut institutions = HashMap::new();
    for i in &config.institutions {
        if !valid_handle(&i.handle) {
            return Err(AppError::BadRequest(format!("invalid institution handle {:?}", i.handle)));
        }
        institutions.insert(i.handle.clone(), ledger.ensure_actor(&i.handle, &i.name, "institution")?);
    }
    let mut accounts = Accounts::default();
    for a in &config.accounts {
        if !valid_handle(&a.handle) || institutions.contains_key(&a.handle) {
            return Err(AppError::BadRequest(format!("invalid or duplicate account handle {:?}", a.handle)));
        }
        if a.token_sha256.len() != 64 || !a.token_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(AppError::BadRequest(format!("account {}: token_sha256 must be 64 hex characters", a.handle)));
        }
        let institution = match (&a.role, &a.institution) {
            (Role::Responder, Some(h)) => Some(
                institutions.get(h).cloned().ok_or_else(|| AppError::BadRequest(format!("unknown institution {h}")))?,
            ),
            (Role::Responder, None) => {
                return Err(AppError::BadRequest(format!("responder {} needs an institution", a.handle)));
            }
            (_, Some(_)) => {
                return Err(AppError::BadRequest(format!("only responders belong to an institution ({})", a.handle)));
            }
            (_, None) => None,
        };
        let actor_id = ledger.ensure_actor(&a.handle, &a.name, "person")?;
        accounts.insert(
            a.token_sha256.clone(),
            Account { actor_id, handle: a.handle.clone(), display_name: a.name.clone(), role: a.role, institution },
        );
    }
    Ok(accounts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pardarsh_core::id::Origin;
    use pardarsh_core::storage::MemoryStore;

    fn ledger() -> Ledger<MemoryStore> {
        Ledger::new(MemoryStore::new(Origin::new("test.local").unwrap()))
    }

    fn account(handle: &str, role: Role, institution: Option<&str>) -> AccountConfig {
        AccountConfig {
            handle: handle.into(),
            name: handle.into(),
            role,
            institution: institution.map(str::to_string),
            token_sha256: hash_token(handle),
        }
    }

    fn config(accounts: Vec<AccountConfig>) -> Config {
        let (mut c, _) = Config::demo();
        c.accounts = accounts;
        c
    }

    fn err(c: &Config) -> String {
        match bootstrap(&mut ledger(), c) {
            Err(AppError::BadRequest(m)) => m,
            Err(other) => panic!("expected BadRequest, got {other:?}"),
            Ok(_) => panic!("expected BadRequest, got Ok"),
        }
    }

    #[test]
    fn handles() {
        assert!(valid_handle("ab"));
        assert!(valid_handle("ward7_works"));
        let long = "x".repeat(41);
        for bad in ["a", "Asha", "has space", "dash-ed", long.as_str()] {
            assert!(!valid_handle(bad), "{bad}");
        }
    }

    #[test]
    fn demo_config_bootstraps_and_its_tokens_authenticate() {
        let (c, tokens) = Config::demo();
        assert_eq!(tokens.len(), c.accounts.len());
        let mut l = ledger();
        let accounts = bootstrap(&mut l, &c).unwrap();
        for (handle, token) in &tokens {
            assert_eq!(&accounts.authenticate(token).unwrap().handle, handle);
        }
        let engineer = accounts.iter().find(|a| a.handle == "ward7_engineer").unwrap();
        assert_eq!(engineer.role, Role::Responder);
        assert!(engineer.institution.is_some());
        assert_eq!(l.institutions().unwrap().len(), 2);
        // Bootstrapping again reuses the same actor records.
        let again = bootstrap(&mut l, &c).unwrap();
        let id = |a: &Accounts| a.iter().find(|a| a.handle == "asha").unwrap().actor_id.clone();
        assert_eq!(id(&again), id(&accounts));
        assert_eq!(l.institutions().unwrap().len(), 2);
    }

    #[test]
    fn rejects_invalid_accounts_and_institutions() {
        let mut c = config(vec![]);
        c.institutions[0].handle = "Bad Handle".into();
        assert!(err(&c).contains("invalid institution handle"));

        assert!(err(&config(vec![account("x", Role::Citizen, None)])).contains("invalid or duplicate"));
        assert!(err(&config(vec![account("ward7_works", Role::Citizen, None)])).contains("invalid or duplicate"));
        let mut short = account("asha", Role::Citizen, None);
        short.token_sha256 = "abc".into();
        assert!(err(&config(vec![short])).contains("64 hex"));
        let mut not_hex = account("asha", Role::Citizen, None);
        not_hex.token_sha256 = "z".repeat(64);
        assert!(err(&config(vec![not_hex])).contains("64 hex"));
        assert!(err(&config(vec![account("eng", Role::Responder, None)])).contains("needs an institution"));
        assert!(err(&config(vec![account("eng", Role::Responder, Some("nowhere"))])).contains("unknown institution"));
        assert!(err(&config(vec![account("asha", Role::Citizen, Some("ward7_works"))])).contains("only responders"));
        assert!(err(&config(vec![account("mod", Role::Moderator, Some("ward7_works"))])).contains("only responders"));
    }

    #[test]
    fn load_reads_and_validates_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name).to_string_lossy().into_owned();

        assert!(
            matches!(Config::load(&path("missing.json")), Err(AppError::BadRequest(m)) if m.contains("cannot read"))
        );

        std::fs::write(path("bad.json"), "{not json").unwrap();
        assert!(
            matches!(Config::load(&path("bad.json")), Err(AppError::BadRequest(m)) if m.contains("invalid config"))
        );

        std::fs::write(path("unknown.json"), r#"{"origin":"a.b","database":"x","bind":"y","surprise":1}"#).unwrap();
        assert!(Config::load(&path("unknown.json")).is_err(), "unknown fields are rejected");

        std::fs::write(path("minimal.json"), r#"{"origin":"a.b","database":"x","bind":"y"}"#).unwrap();
        let c = Config::load(&path("minimal.json")).unwrap();
        assert_eq!(c.writes_per_minute, 30);
        assert!(c.institutions.is_empty() && c.accounts.is_empty());

        let (demo, _) = Config::demo();
        std::fs::write(path("demo.json"), serde_json::to_string(&demo).unwrap()).unwrap();
        assert_eq!(Config::load(&path("demo.json")).unwrap().accounts.len(), demo.accounts.len());
    }
}
