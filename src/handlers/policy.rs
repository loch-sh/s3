use std::sync::Arc;

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use super::{BoxBody, empty_response, error_response, json_response, read_body_limited};
use crate::policy;
use crate::storage::Storage;

/// PUT /{bucket}?policy -- Set bucket policy.
pub async fn put_bucket_policy(
    storage: Arc<Storage>,
    bucket: &str,
    req: Request<Incoming>,
) -> Response<BoxBody> {
    // Limit policy body to 20 KB
    let body = match read_body_limited(req.into_body(), 20 * 1024).await {
        Ok(data) => data,
        Err(e) => return error_response(e, &format!("/{}", bucket)),
    };

    // Validate the policy JSON
    let validated = match policy::parse_policy(&body) {
        Ok(p) => p,
        Err(e) => return error_response(e, &format!("/{}", bucket)),
    };

    // Store the validated (re-serialized) JSON
    let json = serde_json::to_vec(&validated).unwrap();
    match storage.put_bucket_policy(bucket, &json).await {
        Ok(()) => empty_response(StatusCode::NO_CONTENT),
        Err(e) => error_response(e, &format!("/{}", bucket)),
    }
}

/// GET /{bucket}?policy -- Get bucket policy.
pub async fn get_bucket_policy(storage: Arc<Storage>, bucket: &str) -> Response<BoxBody> {
    match storage.get_bucket_policy(bucket).await {
        Ok(data) => json_response(StatusCode::OK, String::from_utf8(data).unwrap_or_default()),
        Err(e) => error_response(e, &format!("/{}", bucket)),
    }
}

/// DELETE /{bucket}?policy -- Delete bucket policy.
pub async fn delete_bucket_policy(storage: Arc<Storage>, bucket: &str) -> Response<BoxBody> {
    match storage.delete_bucket_policy(bucket).await {
        Ok(()) => empty_response(StatusCode::NO_CONTENT),
        Err(e) => error_response(e, &format!("/{}", bucket)),
    }
}
