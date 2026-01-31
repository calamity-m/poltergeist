//! JWT handling for the Poltergeist OIDC shim.
//!
//! This module is divided into two parts:
//! - [`upstream`]: Handles decoding and optional validation of tokens received from the Ingress.
//! - [`downstream`]: Handles the creation and signing of new tokens issued to the application.

pub mod downstream;
pub mod upstream;
