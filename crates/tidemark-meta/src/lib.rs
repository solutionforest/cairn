#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Tidemark metadata store: redb tables (DESIGN §4.3), a single serialised writer thread with group
//! commit, read transactions, list iterators with common-prefix skipping and PITR queries (§7.4).

pub mod keys;
pub mod list;
pub mod migrate;
pub mod pitr;
pub mod records;
mod store;
pub mod tables;

pub use records::*;
pub use store::{
    DEFAULT_CACHE_BYTES, Flow, MetaStore, ReadTxn, Reader, RedbMetaStore, ScanFn, WriteTxn,
};
pub use tables::{ReadExt, Table};

/// Metadata store errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum MetaError {
    /// redb failure.
    #[error("metadata database error: {0}")]
    Db(String),
    /// A record failed to decode.
    #[error("corrupt metadata record: {0}")]
    Corrupt(String),
    /// The writer thread is gone.
    #[error("metadata writer stopped")]
    Closed,
    /// A write job panicked.
    #[error("metadata write job panicked")]
    Panicked,
}

impl From<MetaError> for tidemark_core::S3Error {
    fn from(e: MetaError) -> Self {
        tidemark_core::S3Error::internal(e)
    }
}

macro_rules! db_err {
    ($($t:ty),*) => {$(
        impl From<$t> for MetaError {
            fn from(e: $t) -> Self { MetaError::Db(e.to_string()) }
        }
    )*};
}
db_err!(
    redb::Error,
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError
);
