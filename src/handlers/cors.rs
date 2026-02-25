use std::sync::Arc;

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use super::{BoxBody, empty_response, error_response, read_body_limited, xml_response};
use crate::cors;
use crate::error::S3Error;
use crate::storage::Storage;

/// PUT /{bucket}?cors -- Set CORS configuration (XML input).
pub async fn put_bucket_cors(
    storage: Arc<Storage>,
    bucket: &str,
    req: Request<Incoming>,
) -> Response<BoxBody> {
    // Limit CORS body to 64 KB
    let body = match read_body_limited(req.into_body(), 64 * 1024).await {
        Ok(data) => data,
        Err(e) => return error_response(e, &format!("/{}", bucket)),
    };

    // Parse XML input into internal representation
    let config = match cors::parse_cors_xml(&body) {
        Ok(c) => c,
        Err(e) => return error_response(e, &format!("/{}", bucket)),
    };

    // Store as JSON internally
    let json = serde_json::to_vec(&config).unwrap();
    match storage.put_bucket_cors(bucket, &json).await {
        Ok(()) => empty_response(StatusCode::OK),
        Err(e) => error_response(e, &format!("/{}", bucket)),
    }
}

/// GET /{bucket}?cors -- Get CORS configuration (XML output).
pub async fn get_bucket_cors(storage: Arc<Storage>, bucket: &str) -> Response<BoxBody> {
    match storage.get_bucket_cors(bucket).await {
        Ok(data) => {
            let config: cors::CorsConfiguration = match serde_json::from_slice(&data) {
                Ok(c) => c,
                Err(_) => {
                    return error_response(
                        S3Error::InternalError("corrupt CORS data".to_string()),
                        &format!("/{}", bucket),
                    );
                }
            };
            let output = cors::to_cors_xml(&config);
            xml_response(StatusCode::OK, output)
        }
        Err(e) => error_response(e, &format!("/{}", bucket)),
    }
}

/// DELETE /{bucket}?cors -- Delete CORS configuration.
pub async fn delete_bucket_cors(storage: Arc<Storage>, bucket: &str) -> Response<BoxBody> {
    match storage.delete_bucket_cors(bucket).await {
        Ok(()) => empty_response(StatusCode::NO_CONTENT),
        Err(e) => error_response(e, &format!("/{}", bucket)),
    }
}
