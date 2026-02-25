use std::sync::Arc;

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use super::{BoxBody, empty_response, error_response, read_body_limited, xml_response};
use crate::error::S3Error;
use crate::storage::Storage;
use crate::xml;

/// PUT /{bucket}?encryption -- Set bucket default encryption configuration (XML input).
pub async fn put_bucket_encryption(
    storage: Arc<Storage>,
    bucket: &str,
    req: Request<Incoming>,
) -> Response<BoxBody> {
    let resource = format!("/{}", bucket);

    let body = match read_body_limited(req.into_body(), 64 * 1024).await {
        Ok(data) => data,
        Err(e) => return error_response(e, &resource),
    };

    // Parse XML input
    let config: xml::ServerSideEncryptionConfiguration =
        match quick_xml::de::from_str(&String::from_utf8_lossy(&body)) {
            Ok(c) => c,
            Err(_) => return error_response(S3Error::MalformedXML, &resource),
        };

    // Validate: we only support AES256 (SSE-S3)
    if config.rule.apply_default.sse_algorithm != "AES256" {
        return error_response(
            S3Error::InvalidArgument(format!(
                "Unsupported SSE algorithm: {}",
                config.rule.apply_default.sse_algorithm
            )),
            &resource,
        );
    }

    // Store as JSON internally
    let json = serde_json::to_vec(&config).unwrap();
    match storage.put_bucket_encryption(bucket, &json).await {
        Ok(()) => empty_response(StatusCode::OK),
        Err(e) => error_response(e, &resource),
    }
}

/// GET /{bucket}?encryption -- Get bucket default encryption configuration (XML output).
pub async fn get_bucket_encryption(storage: Arc<Storage>, bucket: &str) -> Response<BoxBody> {
    let resource = format!("/{}", bucket);

    match storage.get_bucket_encryption(bucket).await {
        Ok(data) => {
            let mut config: xml::ServerSideEncryptionConfiguration =
                match serde_json::from_slice(&data) {
                    Ok(c) => c,
                    Err(_) => {
                        return error_response(
                            S3Error::InternalError("corrupt encryption config".to_string()),
                            &resource,
                        );
                    }
                };
            config.xmlns = xml::S3_XMLNS.to_string();
            xml_response(StatusCode::OK, xml::to_xml(&config))
        }
        Err(e) => error_response(e, &resource),
    }
}

/// DELETE /{bucket}?encryption -- Delete bucket default encryption configuration.
pub async fn delete_bucket_encryption(storage: Arc<Storage>, bucket: &str) -> Response<BoxBody> {
    match storage.delete_bucket_encryption(bucket).await {
        Ok(()) => empty_response(StatusCode::NO_CONTENT),
        Err(e) => error_response(e, &format!("/{}", bucket)),
    }
}
