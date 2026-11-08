#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Cairn core domain types, S3 error codes and configuration. See docs/DESIGN.md §3–§4.

pub mod checksum;
pub mod config;
pub mod error;
pub mod ids;
pub mod time;

pub use checksum::ChecksumAlgo;
pub use config::Config;
pub use error::{S3Error, S3ErrorCode, S3Result};
pub use ids::{BlobId, BucketId, BucketName, ObjectKey, PrincipalId, VersionId};
pub use time::Ts;
