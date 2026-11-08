//! S3 error codes (with HTTP status) and the `S3Error` value used across crates.

use std::fmt;

macro_rules! codes {
    ($($name:ident = $status:literal, $msg:literal;)*) => {
        /// The S3 error code list (AWS S3 API reference "Error responses") plus Cairn additions.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum S3ErrorCode { $($name,)* }

        impl S3ErrorCode {
            /// The code string as it appears in `<Code>`.
            pub fn as_str(&self) -> &'static str {
                match self { $(S3ErrorCode::$name => stringify!($name),)* }
            }
            /// The HTTP status code S3 returns for this error.
            pub fn http_status(&self) -> u16 {
                match self { $(S3ErrorCode::$name => $status,)* }
            }
            /// A default human readable message.
            pub fn default_message(&self) -> &'static str {
                match self { $(S3ErrorCode::$name => $msg,)* }
            }
            /// Parse a code string.
            pub fn parse(s: &str) -> Option<S3ErrorCode> {
                match s { $(stringify!($name) => Some(S3ErrorCode::$name),)* _ => None }
            }
            /// Every known code.
            pub const ALL: &'static [S3ErrorCode] = &[$(S3ErrorCode::$name,)*];
        }
    };
}

codes! {
    AccessDenied = 403, "Access Denied";
    AccountProblem = 403, "There is a problem with your account that prevents the operation from completing successfully.";
    AllAccessDisabled = 403, "All access to this Amazon S3 resource has been disabled.";
    AmbiguousGrantByEmailAddress = 400, "The email address you provided is associated with more than one account.";
    AuthorizationHeaderMalformed = 400, "The authorization header you provided is invalid.";
    BadDigest = 400, "The Content-MD5 or checksum value that you specified did not match what the server received.";
    BucketAlreadyExists = 409, "The requested bucket name is not available.";
    BucketAlreadyOwnedByYou = 409, "The bucket that you tried to create already exists, and you own it.";
    BucketNotEmpty = 409, "The bucket that you tried to delete is not empty.";
    CredentialsNotSupported = 400, "This request does not support credentials.";
    CrossLocationLoggingProhibited = 403, "Cross-location logging not allowed.";
    EntityTooSmall = 400, "Your proposed upload is smaller than the minimum allowed object size.";
    EntityTooLarge = 400, "Your proposed upload exceeds the maximum allowed object size.";
    ExpiredToken = 400, "The provided token has expired.";
    IllegalLocationConstraintException = 400, "The specified location constraint is not valid.";
    IllegalVersioningConfigurationException = 400, "The versioning configuration specified in the request is invalid.";
    IncompleteBody = 400, "You did not provide the number of bytes specified by the Content-Length HTTP header.";
    IncorrectNumberOfFilesInPostRequest = 400, "POST requires exactly one file upload per request.";
    InsufficientStorage = 507, "Insufficient storage space.";
    InlineDataTooLarge = 400, "Inline data exceeds the maximum allowed size.";
    InternalError = 500, "We encountered an internal error. Please try again.";
    InvalidAccessKeyId = 403, "The AWS access key ID that you provided does not exist in our records.";
    InvalidArgument = 400, "Invalid Argument";
    InvalidBucketName = 400, "The specified bucket is not valid.";
    InvalidBucketState = 409, "The request is not valid for the current state of the bucket.";
    InvalidDigest = 400, "The Content-MD5 or checksum value that you specified is not valid.";
    InvalidEncryptionAlgorithmError = 400, "The encryption request that you specified is not valid.";
    InvalidLocationConstraint = 400, "The specified location constraint is not valid.";
    InvalidObjectState = 403, "The operation is not valid for the current state of the object.";
    InvalidPart = 400, "One or more of the specified parts could not be found.";
    InvalidPartOrder = 400, "The list of parts was not in ascending order.";
    InvalidPartNumber = 416, "The requested partnumber is not satisfiable.";
    InvalidPayer = 403, "All access to this object has been disabled.";
    InvalidPolicyDocument = 400, "The content of the form does not meet the conditions specified in the policy document.";
    InvalidRange = 416, "The requested range cannot be satisfied.";
    InvalidRequest = 400, "Invalid Request";
    InvalidSecurity = 403, "The provided security credentials are not valid.";
    InvalidStorageClass = 400, "The storage class you specified is not valid.";
    InvalidTag = 400, "The tag provided was not a valid tag.";
    InvalidTargetBucketForLogging = 400, "The target bucket for logging does not exist.";
    InvalidToken = 400, "The provided token is malformed or otherwise invalid.";
    InvalidURI = 400, "Couldn't parse the specified URI.";
    KeyTooLongError = 400, "Your key is too long.";
    MalformedACLError = 400, "The ACL that you provided was not well formed.";
    MalformedPOSTRequest = 400, "The body of your POST request is not well-formed multipart/form-data.";
    MalformedXML = 400, "The XML you provided was not well-formed or did not validate against our published schema.";
    MalformedPolicy = 400, "Policy has invalid resource.";
    MaxMessageLengthExceeded = 400, "Your request was too big.";
    MaxPostPreDataLengthExceededError = 400, "Your POST request fields preceding the upload file were too large.";
    MetadataTooLarge = 400, "Your metadata headers exceed the maximum allowed metadata size.";
    MethodNotAllowed = 405, "The specified method is not allowed against this resource.";
    MissingContentLength = 411, "You must provide the Content-Length HTTP header.";
    MissingRequestBodyError = 400, "Request Body is empty.";
    MissingSecurityElement = 400, "The SOAP 1.1 request is missing a security element.";
    MissingSecurityHeader = 400, "Your request is missing a required header.";
    NoLoggingStatusForKey = 400, "There is no such thing as a logging status subresource for a key.";
    NoSuchBucket = 404, "The specified bucket does not exist.";
    NoSuchBucketPolicy = 404, "The bucket policy does not exist.";
    NoSuchCORSConfiguration = 404, "The CORS configuration does not exist.";
    NoSuchKey = 404, "The specified key does not exist.";
    NoSuchLifecycleConfiguration = 404, "The lifecycle configuration does not exist.";
    NoSuchObjectLockConfiguration = 404, "The specified object does not have an ObjectLock configuration.";
    NoSuchPublicAccessBlockConfiguration = 404, "The public access block configuration was not found.";
    NoSuchTagSet = 404, "The TagSet does not exist.";
    NoSuchUpload = 404, "The specified multipart upload does not exist.";
    NoSuchVersion = 404, "The specified version does not exist.";
    NoSuchWebsiteConfiguration = 404, "The specified bucket does not have a website configuration.";
    NotImplemented = 501, "A header you provided implies functionality that is not implemented.";
    NotModified = 304, "Not Modified";
    NotSignedUp = 403, "Your account is not signed up for the Amazon S3 service.";
    ObjectLockConfigurationNotFoundError = 404, "Object Lock configuration does not exist for this bucket.";
    OperationAborted = 409, "A conflicting conditional operation is currently in progress against this resource.";
    OwnershipControlsNotFoundError = 404, "The bucket ownership controls were not found.";
    PermanentRedirect = 301, "The bucket that you are attempting to access must be addressed using the specified endpoint.";
    PreconditionFailed = 412, "At least one of the preconditions that you specified did not hold.";
    QuotaExceeded = 507, "The bucket quota has been exceeded.";
    Redirect = 307, "Temporary redirect.";
    ReplicationConfigurationNotFoundError = 404, "The replication configuration was not found.";
    RequestHeaderSectionTooLarge = 400, "The request header and query parameters used to make the request exceed the maximum allowed size.";
    RequestIsNotMultiPartContent = 400, "Bucket POST must be of the enclosure-type multipart/form-data.";
    RequestTimeout = 400, "Your socket connection to the server was not read from or written to within the timeout period.";
    RequestTimeTooSkewed = 403, "The difference between the request time and the server's time is too large.";
    RequestTorrentOfBucketError = 400, "Requesting the torrent file of a bucket is not permitted.";
    RestoreAlreadyInProgress = 409, "Object restore is already in progress.";
    ServerSideEncryptionConfigurationNotFoundError = 404, "The server side encryption configuration was not found.";
    ServiceUnavailable = 503, "Service is unable to handle request.";
    SignatureDoesNotMatch = 403, "The request signature that the server calculated does not match the signature that you provided.";
    SlowDown = 503, "Please reduce your request rate.";
    TemporaryRedirect = 307, "You are being redirected to the bucket while DNS updates.";
    TokenRefreshRequired = 400, "The provided token must be refreshed.";
    TooManyBuckets = 400, "You have attempted to create more buckets than allowed.";
    TooManyParts = 400, "You have exceeded the maximum number of parts.";
    UnexpectedContent = 400, "This request does not support content.";
    UnresolvableGrantByEmailAddress = 400, "The email address that you provided does not match any account on record.";
    UserKeyMustBeSpecified = 400, "The bucket POST request must contain the specified field name.";
    XAmzContentSHA256Mismatch = 400, "The provided 'x-amz-content-sha256' header does not match what was computed.";
}

/// An S3-level error: code, message, optional resource and request id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Error {
    /// The S3 error code.
    pub code: S3ErrorCode,
    /// Human readable message.
    pub message: String,
    /// The bucket/key the error refers to.
    pub resource: Option<String>,
    /// Request id, filled in by the protocol layer.
    pub request_id: Option<String>,
    /// Extra response headers (e.g. `x-amz-delete-marker`, `Content-Range`).
    pub headers: Vec<(String, String)>,
}

/// Result alias with `S3Error`.
pub type S3Result<T> = Result<T, S3Error>;

impl S3Error {
    /// New error with message.
    pub fn new(code: S3ErrorCode, message: impl Into<String>) -> S3Error {
        S3Error {
            code,
            message: message.into(),
            resource: None,
            request_id: None,
            headers: Vec::new(),
        }
    }

    /// New error with the code's default message.
    pub fn code(code: S3ErrorCode) -> S3Error {
        S3Error::new(code, code.default_message())
    }

    /// Attach a resource.
    pub fn with_resource(mut self, r: impl Into<String>) -> S3Error {
        self.resource = Some(r.into());
        self
    }

    /// Attach a response header.
    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> S3Error {
        self.headers.push((name.to_string(), value.into()));
        self
    }

    /// Internal error from any displayable cause.
    pub fn internal(e: impl fmt::Display) -> S3Error {
        S3Error::new(S3ErrorCode::InternalError, format!("internal error: {e}"))
    }

    /// HTTP status for this error.
    pub fn http_status(&self) -> u16 {
        self.code.http_status()
    }
}

impl fmt::Display for S3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for S3Error {}

impl From<S3ErrorCode> for S3Error {
    fn from(c: S3ErrorCode) -> S3Error {
        S3Error::code(c)
    }
}

impl From<std::io::Error> for S3Error {
    fn from(e: std::io::Error) -> S3Error {
        S3Error::internal(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_and_round_trip() {
        assert_eq!(S3ErrorCode::NoSuchKey.http_status(), 404);
        assert_eq!(S3ErrorCode::PreconditionFailed.http_status(), 412);
        assert_eq!(S3ErrorCode::InvalidRange.http_status(), 416);
        assert_eq!(S3ErrorCode::NotImplemented.http_status(), 501);
        for c in S3ErrorCode::ALL {
            assert_eq!(S3ErrorCode::parse(c.as_str()), Some(*c));
            assert!((300..600).contains(&c.http_status()));
        }
        assert!(S3ErrorCode::ALL.len() > 90);
    }
}
