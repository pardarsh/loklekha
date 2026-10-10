//! # Loklekha
//!
//! A public civic issue ledger built on [`pardarsh_core`]. This crate owns
//! everything application-specific: issue intake, contribution and response
//! journeys, the status workflow and its permissions, accounts, moderation,
//! search, the HTTP API and pages. Records, history, provenance, relations,
//! validation, storage and export come from `pardarsh-core`.

pub mod error;
pub mod vocab;
pub mod workflow;
