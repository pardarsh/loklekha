//! The compiled `loklekha` binary: argument parsing, exit codes and output.

use std::process::Command;

fn loklekha(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_loklekha")).args(args).output().expect("binary runs")
}

#[test]
fn hash_token_succeeds() {
    let out = loklekha(&["hash-token", "secret"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), loklekha::identity::hash_token("secret"));
}

#[test]
fn help_and_version() {
    let help = loklekha(&["--help"]);
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout).unwrap();
    for cmd in ["demo-config", "serve", "export", "hash-token"] {
        assert!(text.contains(cmd), "{cmd}");
    }
    let version = loklekha(&["--version"]);
    assert!(String::from_utf8(version.stdout).unwrap().contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn usage_errors_exit_with_code_2() {
    for args in [&[][..], &["frobnicate"], &["export", "not-an-id"]] {
        let out = loklekha(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(!out.stderr.is_empty());
    }
}

#[test]
fn runtime_errors_exit_with_code_1() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.json");
    let out = loklekha(&["serve", "--config", missing.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stderr).unwrap().contains("cannot read"));
}

#[test]
fn demo_config_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.json");
    let out = loklekha(&["demo-config", "--out", path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(path.exists());
    let again = loklekha(&["demo-config", "--out", path.to_str().unwrap()]);
    assert_eq!(again.status.code(), Some(1));
}
