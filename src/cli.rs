//! Command-line interface (clap).
//!
//! Kept in the library so every command can be tested; `main.rs` only parses
//! arguments and calls [`run`].

use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use pardarsh_core::id::{Origin, RecordId};
use pardarsh_core::storage::SqliteStore;
use tokio::net::TcpListener;

use tower_sessions::ExpiredDeletion;
use tower_sessions_rusqlite_store::RusqliteStore;

use crate::api::AppState;
use crate::config::{Config, bootstrap};
use crate::identity::{Accounts, Session, hash_token};
use crate::server::{WebConfig, app};
use crate::service::Ledger;
use crate::users::{NewUser, UserStore, parse_role};

#[derive(Debug, Parser)]
#[command(name = "loklekha", version, about = "Loklekha: a public civic issue ledger built on pardarsh-core")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum Command {
    /// Write a demo configuration and print its API tokens (shown once).
    DemoConfig {
        /// Where to write the configuration.
        #[arg(long, default_value = "loklekha.json")]
        out: PathBuf,
    },
    /// Run the web server.
    Serve {
        #[arg(long, default_value = "loklekha.json")]
        config: PathBuf,
        /// Address to listen on, overriding `bind` in the configuration.
        #[arg(long)]
        bind: Option<String>,
    },
    /// Print the public export bundle for an issue.
    Export {
        /// Issue id, e.g. pd:loklekha.example.org:0190...
        issue_id: RecordId,
        #[arg(long, default_value = "loklekha.json")]
        config: PathBuf,
    },
    /// Print the SHA-256 of an API token, for the `token_sha256` config field.
    HashToken { token: String },
    /// Create a web sign-in account and print its generated password (shown once).
    CreateUser {
        /// Public handle (a-z, 0-9, _).
        handle: String,
        /// Display name.
        #[arg(long)]
        name: String,
        /// citizen, responder, moderator or admin.
        #[arg(long, default_value = "citizen")]
        role: String,
        /// Institution handle, required for responders.
        #[arg(long)]
        institution: Option<String>,
        #[arg(long, default_value = "loklekha.json")]
        config: PathBuf,
    },
}

/// Open the configured store and bootstrap institutions and accounts.
pub fn open(config: &Config) -> Result<(Ledger<SqliteStore>, Accounts), String> {
    let origin = Origin::new(config.origin.clone()).map_err(|e| e.to_string())?;
    let store = SqliteStore::open(&config.database, origin).map_err(|e| e.to_string())?;
    let mut ledger = Ledger::new(store);
    let accounts = bootstrap(&mut ledger, config).map_err(|e| e.to_string())?;
    Ok((ledger, accounts))
}

fn load(path: &Path) -> Result<Config, String> {
    Config::load(&path.to_string_lossy()).map_err(|e| e.to_string())
}

fn io(e: std::io::Error) -> String {
    e.to_string()
}

/// Serve on an already bound listener until `shutdown` completes.
pub async fn serve(
    config: &Config,
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), String> {
    let (ledger, accounts) = open(config)?;
    let users = UserStore::open(&config.database).map_err(|e| e.to_string())?;
    let conn = tokio_rusqlite::Connection::open(&config.database).await.map_err(|e| e.to_string())?;
    let sessions = RusqliteStore::new(conn);
    sessions.migrate().await.map_err(|e| e.to_string())?;
    let cleanup =
        tokio::task::spawn(sessions.clone().continuously_delete_expired(std::time::Duration::from_secs(3600)));
    let state = AppState::new(ledger, accounts, config.writes_per_minute);
    let web = WebConfig { secure_cookies: config.secure_cookies, ..WebConfig::default() };
    let result =
        axum::serve(listener, app(state, users, sessions, &web)).with_graceful_shutdown(shutdown).await.map_err(io);
    cleanup.abort();
    result
}

/// Run one command, writing user-facing output to `out`.
pub async fn run(command: Command, out: &mut (dyn Write + Send)) -> Result<(), String> {
    match command {
        Command::DemoConfig { out: path } => {
            if path.exists() {
                return Err(format!("{} already exists; refusing to overwrite", path.display()));
            }
            let (config, tokens) = Config::demo();
            let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
            std::fs::write(&path, json + "\n").map_err(io)?;
            writeln!(out, "wrote {}. API tokens (shown once, only hashes are stored):", path.display()).map_err(io)?;
            for (handle, token) in tokens {
                writeln!(out, "  {handle:<16} {token}").map_err(io)?;
            }
            writeln!(
                out,
                "Create web sign-in accounts with `loklekha create-user <handle> --name <name> [--role ...]`."
            )
            .map_err(io)
        }
        Command::Serve { config, bind } => {
            let config = load(&config)?;
            let addr = bind.unwrap_or_else(|| config.bind.clone());
            let listener = TcpListener::bind(&addr).await.map_err(|e| format!("cannot listen on {addr}: {e}"))?;
            let local = listener.local_addr().map_err(io)?;
            writeln!(out, "loklekha listening on http://{local}").map_err(io)?;
            serve(&config, listener, async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await
        }
        Command::Export { issue_id, config } => {
            let config = load(&config)?;
            let (ledger, _) = open(&config)?;
            let bundle = ledger.export_issue(&Session::Anonymous, &issue_id).map_err(|e| e.to_string())?;
            writeln!(out, "{}", bundle.to_json_pretty().map_err(|e| e.to_string())?).map_err(io)
        }
        Command::HashToken { token } => writeln!(out, "{}", hash_token(&token)).map_err(io),
        Command::CreateUser { handle, name, role, institution, config } => {
            let role = parse_role(&role)
                .ok_or_else(|| format!("unknown role {role:?}; use citizen, responder, moderator or admin"))?;
            let config = load(&config)?;
            let (mut ledger, _) = open(&config)?;
            let users = UserStore::open(&config.database).map_err(|e| e.to_string())?;
            let password = uuid::Uuid::new_v4().simple().to_string();
            let user = users
                .create(
                    &mut ledger,
                    NewUser {
                        handle: &handle,
                        display_name: &name,
                        password: &password,
                        role,
                        institution: institution.as_deref(),
                    },
                )
                .map_err(|e| e.to_string())?;
            writeln!(out, "created @{} ({role:?}). Password (shown once): {password}", user.handle).map_err(io)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use clap::CommandFactory;
    use pardarsh_core::id::Origin;

    use super::*;
    use crate::service::NewIssue;

    fn parse(args: &[&str]) -> Result<Command, clap::Error> {
        Cli::try_parse_from(std::iter::once("loklekha").chain(args.iter().copied())).map(|c| c.command)
    }

    async fn run_to_string(command: Command) -> Result<String, String> {
        let mut out = Vec::new();
        run(command, &mut out).await?;
        Ok(String::from_utf8(out).unwrap())
    }

    /// A demo config whose database lives in a temporary directory.
    fn temp_config(dir: &tempfile::TempDir) -> (PathBuf, Config) {
        let (mut config, _) = Config::demo();
        config.database = dir.path().join("ledger.sqlite").to_string_lossy().into_owned();
        config.bind = "127.0.0.1:0".into();
        let path = dir.path().join("loklekha.json");
        std::fs::write(&path, serde_json::to_string(&config).unwrap()).unwrap();
        (path, config)
    }

    #[test]
    fn clap_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_every_command_with_defaults() {
        assert_eq!(parse(&["demo-config"]).unwrap(), Command::DemoConfig { out: "loklekha.json".into() });
        assert_eq!(parse(&["demo-config", "--out", "x.json"]).unwrap(), Command::DemoConfig { out: "x.json".into() });
        assert_eq!(parse(&["serve"]).unwrap(), Command::Serve { config: "loklekha.json".into(), bind: None });
        assert_eq!(
            parse(&["serve", "--config", "c.json", "--bind", "0.0.0.0:9000"]).unwrap(),
            Command::Serve { config: "c.json".into(), bind: Some("0.0.0.0:9000".into()) }
        );
        let id = "pd:loklekha.localhost:0190a5d2-5b8e-7cc4-9a43-6e3d6f0c3c11";
        assert_eq!(
            parse(&["export", id]).unwrap(),
            Command::Export { issue_id: id.parse().unwrap(), config: "loklekha.json".into() }
        );
        assert_eq!(parse(&["hash-token", "abc"]).unwrap(), Command::HashToken { token: "abc".into() });
    }

    #[test]
    fn rejects_bad_arguments() {
        use clap::error::ErrorKind;
        assert_eq!(parse(&[]).unwrap_err().kind(), ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand);
        assert_eq!(parse(&["frobnicate"]).unwrap_err().kind(), ErrorKind::InvalidSubcommand);
        assert_eq!(parse(&["export", "not-an-id"]).unwrap_err().kind(), ErrorKind::ValueValidation);
        assert_eq!(parse(&["export"]).unwrap_err().kind(), ErrorKind::MissingRequiredArgument);
        assert_eq!(parse(&["hash-token"]).unwrap_err().kind(), ErrorKind::MissingRequiredArgument);
        assert_eq!(parse(&["serve", "--port", "1"]).unwrap_err().kind(), ErrorKind::UnknownArgument);
        assert_eq!(parse(&["--version"]).unwrap_err().kind(), ErrorKind::DisplayVersion);
    }

    #[tokio::test]
    async fn hash_token_prints_the_sha256() {
        let out = run_to_string(Command::HashToken { token: "secret".into() }).await.unwrap();
        assert_eq!(out.trim(), hash_token("secret"));
    }

    #[tokio::test]
    async fn demo_config_writes_once_and_prints_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("demo.json");
        let out = run_to_string(Command::DemoConfig { out: path.clone() }).await.unwrap();
        assert!(out.contains("shown once"));
        let config = Config::load(&path.to_string_lossy()).unwrap();
        for account in &config.accounts {
            let line = out.lines().find(|l| l.trim_start().starts_with(&account.handle)).unwrap();
            let token = line.split_whitespace().last().unwrap();
            assert_eq!(hash_token(token), account.token_sha256, "printed token matches the stored hash");
        }
        assert!(!std::fs::read_to_string(&path).unwrap().contains("lk_"), "plain tokens are never written");
        let again = run_to_string(Command::DemoConfig { out: path }).await.unwrap_err();
        assert!(again.contains("refusing to overwrite"));
    }

    #[tokio::test]
    async fn export_prints_the_public_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let (path, config) = temp_config(&dir);
        let id = {
            let (mut ledger, accounts) = open(&config).unwrap();
            let asha = accounts.iter().find(|a| a.handle == "asha").unwrap().clone();
            let issue = NewIssue {
                title: "Broken handpump".into(),
                description: None,
                category: "water".into(),
                location_text: None,
                locality: None,
                affected_service: None,
                responsible_institution: None,
                withhold_identity: true,
                sources: vec![],
            };
            ledger.create_issue(&Session::User(asha), issue, None).unwrap().issue.id
        };
        let out = run_to_string(Command::Export { issue_id: id.clone(), config: path.clone() }).await.unwrap();
        let bundle: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(bundle["format"], "pardarsh.bundle");
        assert_eq!(bundle["completeness"], "filtered");
        assert_eq!(bundle["entries"][0]["record"]["id"], id.to_string());
        assert!(!out.contains("\"asha\""), "withheld reporter is not exported");

        let missing = RecordId::generate(&Origin::new(config.origin.clone()).unwrap());
        let err = run_to_string(Command::Export { issue_id: missing, config: path }).await.unwrap_err();
        assert!(err.contains("not found"));
    }

    #[tokio::test]
    async fn commands_report_bad_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.json");
        let id: RecordId = "pd:loklekha.localhost:0190a5d2-5b8e-7cc4-9a43-6e3d6f0c3c11".parse().unwrap();
        let err = run_to_string(Command::Export { issue_id: id, config: missing.clone() }).await.unwrap_err();
        assert!(err.contains("cannot read"));
        let err = run_to_string(Command::Serve { config: missing, bind: None }).await.unwrap_err();
        assert!(err.contains("cannot read"));

        let (path, _) = temp_config(&dir);
        let err =
            run_to_string(Command::Serve { config: path, bind: Some("not an address".into()) }).await.unwrap_err();
        assert!(err.contains("cannot listen on not an address"));

        let (_, mut bad_origin) = temp_config(&dir);
        bad_origin.origin = "Not An Origin".into();
        assert!(open(&bad_origin).err().unwrap().contains("invalid origin"));

        let (_, mut bad_db) = temp_config(&dir);
        bad_db.database = dir.path().join("no-such-dir").join("x.sqlite").to_string_lossy().into_owned();
        assert!(open(&bad_db).is_err());

        let (_, mut bad_accounts) = temp_config(&dir);
        bad_accounts.accounts[0].token_sha256 = "short".into();
        assert!(open(&bad_accounts).err().unwrap().contains("64 hex"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serve_answers_http_until_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let (_, config) = temp_config(&dir);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            serve(&config, listener, async {
                let _ = rx.await;
            })
            .await
        });
        let response = tokio::task::spawn_blocking(move || {
            let mut stream = std::net::TcpStream::connect(addr).unwrap();
            stream
                .write_all(b"GET /api/institutions HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut body = String::new();
            stream.read_to_string(&mut body).unwrap();
            body
        })
        .await
        .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("Ward 7 Public Works Office (demo)"));
        let page = tokio::task::spawn_blocking(move || {
            let mut stream = std::net::TcpStream::connect(addr).unwrap();
            stream.write_all(b"GET /issues HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
            let mut body = String::new();
            stream.read_to_string(&mut body).unwrap();
            body
        })
        .await
        .unwrap();
        assert!(page.starts_with("HTTP/1.1 200"), "{page}");
        assert!(page.contains("Sign in") && page.contains("loklekha_csrf="), "the UI is served with a CSRF cookie");
        tx.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[test]
    fn parses_create_user() {
        assert_eq!(
            parse(&["create-user", "asha", "--name", "Asha K"]).unwrap(),
            Command::CreateUser {
                handle: "asha".into(),
                name: "Asha K".into(),
                role: "citizen".into(),
                institution: None,
                config: "loklekha.json".into()
            }
        );
        assert!(parse(&["create-user", "asha"]).is_err(), "--name is required");
    }

    #[tokio::test]
    async fn create_user_prints_a_working_password() {
        let dir = tempfile::tempdir().unwrap();
        let (path, config) = temp_config(&dir);
        let cmd = |handle: &str, role: &str, institution: Option<&str>| Command::CreateUser {
            handle: handle.into(),
            name: "Someone".into(),
            role: role.into(),
            institution: institution.map(str::to_string),
            config: path.clone(),
        };
        let out = run_to_string(cmd("eng2", "responder", Some("ward7_works"))).await.unwrap();
        assert!(out.contains("created @eng2 (Responder)"));
        let password = out.trim().rsplit(' ').next().unwrap().to_string();
        let users = UserStore::open(&config.database).unwrap();
        let user = users.verify("eng2", &password).unwrap().expect("printed password signs in");
        assert!(user.institution.is_some());

        assert!(run_to_string(cmd("eng2", "citizen", None)).await.unwrap_err().contains("taken"));
        assert!(run_to_string(cmd("x3", "emperor", None)).await.unwrap_err().contains("unknown role"));
        assert!(run_to_string(cmd("x4", "responder", None)).await.unwrap_err().contains("need an institution"));
        let missing = dir.path().join("missing.json");
        let err = run_to_string(Command::CreateUser {
            handle: "x5".into(),
            name: "n".into(),
            role: "citizen".into(),
            institution: None,
            config: missing,
        })
        .await
        .unwrap_err();
        assert!(err.contains("cannot read"));
    }
}
