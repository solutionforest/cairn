//! Error types.

/// Errors from parsing or validating a policy document.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// Not valid JSON or wrong shape.
    #[error("malformed policy: {0}")]
    Malformed(String),
    /// Document larger than the size limit.
    #[error("policy document is {0} bytes; limit is {1}")]
    TooLarge(usize, usize),
    /// Unknown or unmatched action.
    #[error("unknown action: {0}")]
    UnknownAction(String),
    /// Malformed resource ARN.
    #[error("invalid resource: {0}")]
    InvalidResource(String),
    /// Malformed principal.
    #[error("invalid principal: {0}")]
    InvalidPrincipal(String),
    /// Unknown condition operator or bad condition value.
    #[error("invalid condition: {0}")]
    InvalidCondition(String),
    /// Unsupported Version.
    #[error("unsupported policy version: {0}")]
    UnsupportedVersion(String),
    /// Element required/forbidden for this policy kind.
    #[error("{0}")]
    Kind(String),
}

/// Errors from the credential store and STS.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Backend I/O failure.
    #[error("credential backend: {0}")]
    Backend(String),
    /// A stored record could not be decoded.
    #[error("corrupt credential record: {0}")]
    Corrupt(String),
    /// Encryption/decryption failure (wrong master key or tampering).
    #[error("secret decryption failed")]
    Crypto,
    /// Entity not found.
    #[error("{kind} not found: {name}")]
    NotFound {
        /// Entity kind ("user", "role", ...).
        kind: &'static str,
        /// Entity name.
        name: String,
    },
    /// Entity already exists.
    #[error("{kind} already exists: {name}")]
    AlreadyExists {
        /// Entity kind.
        kind: &'static str,
        /// Entity name.
        name: String,
    },
    /// Invalid argument (name, duration, cidr...).
    #[error("invalid argument: {0}")]
    Invalid(String),
    /// Policy failed to parse/validate.
    #[error(transparent)]
    Policy(#[from] PolicyError),
    /// Caller is not permitted (e.g. trust policy denies AssumeRole).
    #[error("access denied: {0}")]
    AccessDenied(String),
    /// Limit exceeded (e.g. too many access keys).
    #[error("limit exceeded: {0}")]
    LimitExceeded(String),
}

/// Errors from presigning.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PresignError {
    /// Expiry outside 1 s ..= 7 days.
    #[error("presign expiry must be between 1 second and 7 days")]
    Expiry,
    /// URL has no host.
    #[error("url has no host")]
    NoHost,
    /// Invalid header name or value.
    #[error("invalid header: {0}")]
    Header(String),
}
