//! # Loklekha
//!
//! A public civic issue ledger built on [`pardarsh_core`]. This crate owns
//! everything application-specific: issue intake, contribution and response
//! journeys, the status workflow and its permissions, accounts, moderation,
//! search, the HTTP API and pages. Records, history, provenance, relations,
//! validation, storage and export come from `pardarsh-core`.

pub mod api;
pub mod auth;
pub mod config;
pub mod error;
pub mod identity;
pub mod server;
pub mod service;
pub mod ui;
pub mod users;
pub mod vocab;
pub mod workflow;
