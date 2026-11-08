#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Cairn `admin` crate: the `/_cairn/v1` REST API ([`api::router`]), the [`AdminEngine`] trait
//! the storage engine implements, and the `cairn admin` CLI ([`cli::cli`], [`cli::run`]).
//! See DESIGN §7.3, §8, §9.

pub mod api;
pub mod cli;
pub mod client;
pub mod engine;
pub mod error;

pub use api::{AdminState, Caller, PREFIX, router};
pub use client::{AdminClient, ClientError};
pub use engine::{AdminEngine, MockAdminEngine};
pub use error::{AdminError, REQUEST_ID_HEADER};

#[cfg(test)]
mod tests;
