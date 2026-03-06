use hyper::StatusCode;

/// S3-compatible error types.
#[derive(Debug, Clone)]
pub enum S3Error {
    NoSuchBucket,
    NoSuchKey,
    BucketAlreadyExists,
    BucketNotEmpty,
    InvalidBucketName,
    AccessDenied,
    SignatureDoesNotMatch,
    NoSuchBucketPolicy,
    NoSuchCORSConfiguration,
    MalformedPolicy,
    MalformedXML,
    NoSuchUpload,
    InvalidPart,
    InvalidPartOrder,
    InvalidObjectKey,
    EntityTooLarge,
    RequestTimeTooSkewed,
    ExpiredToken,
    NoSuchVersion,
    MethodNotAllowed,
    InvalidEncryptionAlgorithmError,
    MissingSecurityHeader,
    InvalidArgument(String),
    ServerSideEncryptionConfigurationNotFoundError,
    InternalError(String),
}

impl S3Error {
    /// Returns the S3 error code string, HTTP status code, and human-readable message.
    pub fn as_s3_error(&self) -> (&str, StatusCode, &str) {
        match self {
            S3Error::NoSuchBucket => (
                "NoSuchBucket",
                StatusCode::NOT_FOUND,
                "The specified bucket does not exist.",
            ),
            S3Error::NoSuchKey => (
                "NoSuchKey",
                StatusCode::NOT_FOUND,
                "The specified key does not exist.",
            ),
            S3Error::BucketAlreadyExists => (
                "BucketAlreadyOwnedByYou",
                StatusCode::CONFLICT,
                "Your previous request to create the named bucket succeeded and you already own it.",
            ),
            S3Error::BucketNotEmpty => (
                "BucketNotEmpty",
                StatusCode::CONFLICT,
                "The bucket you tried to delete is not empty.",
            ),
            S3Error::InvalidBucketName => (
                "InvalidBucketName",
                StatusCode::BAD_REQUEST,
                "The specified bucket is not valid.",
            ),
            S3Error::AccessDenied => ("AccessDenied", StatusCode::FORBIDDEN, "Access Denied"),
            S3Error::SignatureDoesNotMatch => (
                "SignatureDoesNotMatch",
                StatusCode::FORBIDDEN,
                "The request signature we calculated does not match the signature you provided.",
            ),
            S3Error::NoSuchBucketPolicy => (
                "NoSuchBucketPolicy",
                StatusCode::NOT_FOUND,
                "The bucket policy does not exist.",
            ),
            S3Error::NoSuchCORSConfiguration => (
                "NoSuchCORSConfiguration",
                StatusCode::NOT_FOUND,
                "The CORS configuration does not exist for this bucket.",
            ),
            S3Error::MalformedPolicy => (
                "MalformedPolicy",
                StatusCode::BAD_REQUEST,
                "The policy is not valid JSON or has invalid structure.",
            ),
            S3Error::MalformedXML => (
                "MalformedXML",
                StatusCode::BAD_REQUEST,
                "The XML you provided was not well-formed.",
            ),
            S3Error::NoSuchUpload => (
                "NoSuchUpload",
                StatusCode::NOT_FOUND,
                "The specified multipart upload does not exist.",
            ),
            S3Error::InvalidPart => (
                "InvalidPart",
                StatusCode::BAD_REQUEST,
                "One or more of the specified parts could not be found.",
            ),
            S3Error::InvalidPartOrder => (
                "InvalidPartOrder",
                StatusCode::BAD_REQUEST,
                "The list of parts was not in ascending order.",
            ),
            S3Error::InvalidObjectKey => (
                "InvalidArgument",
                StatusCode::BAD_REQUEST,
                "The specified key is not valid.",
            ),
            S3Error::EntityTooLarge => (
                "EntityTooLarge",
                StatusCode::PAYLOAD_TOO_LARGE,
                "Your proposed upload exceeds the maximum allowed size.",
            ),
            S3Error::RequestTimeTooSkewed => (
                "RequestTimeTooSkewed",
                StatusCode::FORBIDDEN,
                "The difference between the request time and the server\u{2019}s time is too large.",
            ),
            S3Error::ExpiredToken => (
                "ExpiredToken",
                StatusCode::FORBIDDEN,
                "The provided token has expired.",
            ),
            S3Error::NoSuchVersion => (
                "NoSuchVersion",
                StatusCode::NOT_FOUND,
                "The specified version does not exist.",
            ),
            S3Error::MethodNotAllowed => (
                "MethodNotAllowed",
                StatusCode::METHOD_NOT_ALLOWED,
                "The specified method is not allowed against this resource.",
            ),
            S3Error::InvalidEncryptionAlgorithmError => (
                "InvalidEncryptionAlgorithmError",
                StatusCode::BAD_REQUEST,
                "The encryption algorithm specified is not valid.",
            ),
            S3Error::MissingSecurityHeader => (
                "MissingSecurityHeader",
                StatusCode::BAD_REQUEST,
                "A required security header is missing.",
            ),
            S3Error::InvalidArgument(_) => (
                "InvalidArgument",
                StatusCode::BAD_REQUEST,
                "The provided argument is not valid.",
            ),
            S3Error::ServerSideEncryptionConfigurationNotFoundError => (
                "ServerSideEncryptionConfigurationNotFoundError",
                StatusCode::BAD_REQUEST,
                "Server-side encryption is not configured on this server.",
            ),
            S3Error::InternalError(msg) => {
                let _ = msg;
                (
                    "InternalError",
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "We encountered an internal error. Please try again.",
                )
            }
        }
    }
}

impl std::fmt::Display for S3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (code, _, message) = self.as_s3_error();
        write!(f, "{}: {}", code, message)
    }
}

impl std::error::Error for S3Error {}
