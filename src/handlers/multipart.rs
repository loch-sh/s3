use std::sync::Arc;

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use super::{
    BoxBody, empty_response, error_response, etag_response, read_body_limited, xml_response,
};
use crate::ServerConfig;
use crate::encryption::{self, SseRequest};
use crate::error::S3Error;
use crate::storage::Storage;
use crate::storage::bucket::format_system_time;
use crate::xml;

/// POST /{bucket}/{key}?uploads -- Initiate a multipart upload.
pub async fn create_multipart_upload(
    config: Arc<ServerConfig>,
    bucket: &str,
    key: &str,
    req: Request<Incoming>,
) -> Response<BoxBody> {
    let storage = &config.storage;
    let resource = format!("/{}/{}", bucket, key);

    // Parse and validate SSE headers
    let sse_request =
        match crate::handlers::object::parse_and_validate_sse(req.headers(), &config, &resource) {
            Ok(r) => r,
            Err(resp) => return resp,
        };

    // Apply bucket default encryption if no SSE headers specified
    let sse_request = crate::handlers::object::apply_bucket_default_encryption(
        sse_request,
        storage,
        &config,
        bucket,
    )
    .await;

    let (sse_algorithm, sse_customer_key_md5) = match sse_request {
        SseRequest::None => (None, None),
        SseRequest::SseS3 => (Some("AES256".to_string()), None),
        SseRequest::SseC { key_md5, .. } => (Some("SSE-C".to_string()), Some(key_md5)),
    };

    match storage
        .create_multipart_upload(bucket, key, sse_algorithm, sse_customer_key_md5)
        .await
    {
        Ok(upload_id) => {
            let result = xml::InitiateMultipartUploadResult {
                xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
                bucket: bucket.to_string(),
                key: key.to_string(),
                upload_id,
            };
            xml_response(StatusCode::OK, xml::to_xml(&result))
        }
        Err(e) => error_response(e, &resource),
    }
}

/// PUT /{bucket}/{key}?partNumber=N&uploadId=X -- Upload a part.
pub async fn upload_part(
    config: Arc<ServerConfig>,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: u32,
    req: Request<Incoming>,
) -> Response<BoxBody> {
    let storage = &config.storage;
    let resource = format!("/{}/{}", bucket, key);

    // If upload uses SSE-C, verify the key matches
    let upload_meta = match storage.get_upload_meta(bucket, upload_id).await {
        Ok(m) => m,
        Err(e) => return error_response(e, &resource),
    };

    if upload_meta.sse_algorithm.as_deref() == Some("SSE-C") {
        // Parse SSE-C headers from the request and verify MD5 matches
        let sse_request = match encryption::parse_sse_headers(req.headers()) {
            Ok(r) => r,
            Err(e) => return error_response(e, &resource),
        };
        match sse_request {
            SseRequest::SseC { key_md5, .. } => {
                if let Some(ref stored_md5) = upload_meta.sse_customer_key_md5 {
                    if key_md5 != *stored_md5 {
                        return error_response(
                            S3Error::InvalidArgument(
                                "SSE-C key does not match the one used at upload initiation."
                                    .to_string(),
                            ),
                            &resource,
                        );
                    }
                }
            }
            _ => {
                return error_response(S3Error::MissingSecurityHeader, &resource);
            }
        }
    }

    let aws_chunked = crate::handlers::object::is_aws_chunked(&req);
    let body = req.into_body();
    // Parts are stored as plaintext; encryption happens at CompleteMultipartUpload
    match storage
        .upload_part(bucket, upload_id, part_number, body, aws_chunked)
        .await
    {
        Ok(etag) => etag_response(&etag),
        Err(e) => error_response(e, &resource),
    }
}

/// POST /{bucket}/{key}?uploadId=X -- Complete a multipart upload.
pub async fn complete_multipart_upload(
    config: Arc<ServerConfig>,
    bucket: &str,
    key: &str,
    upload_id: &str,
    req: Request<Incoming>,
) -> Response<BoxBody> {
    let storage = &config.storage;
    let resource = format!("/{}/{}", bucket, key);

    // Read upload metadata to check SSE settings
    let upload_meta = match storage.get_upload_meta(bucket, upload_id).await {
        Ok(m) => m,
        Err(e) => return error_response(e, &resource),
    };

    // For SSE-C, require customer key headers at CompleteMultipartUpload
    let sse_c_key: Option<([u8; 32], String)> =
        if upload_meta.sse_algorithm.as_deref() == Some("SSE-C") {
            let sse_request = match encryption::parse_sse_headers(req.headers()) {
                Ok(r) => r,
                Err(e) => return error_response(e, &resource),
            };
            match sse_request {
                SseRequest::SseC { key, key_md5 } => {
                    if let Some(ref stored_md5) = upload_meta.sse_customer_key_md5 {
                        if key_md5 != *stored_md5 {
                            return error_response(
                                S3Error::InvalidArgument("SSE-C key does not match.".to_string()),
                                &resource,
                            );
                        }
                    }
                    Some((key, key_md5))
                }
                _ => {
                    return error_response(S3Error::MissingSecurityHeader, &resource);
                }
            }
        } else {
            None
        };

    // Read the XML body listing parts (limit 10 MB)
    let body_bytes = match read_body_limited(req.into_body(), 10 * 1024 * 1024).await {
        Ok(data) => data,
        Err(e) => return error_response(e, &resource),
    };

    // Parse the CompleteMultipartUpload XML
    let request: xml::CompleteMultipartUploadRequest =
        match quick_xml::de::from_reader(body_bytes.as_ref()) {
            Ok(r) => r,
            Err(_) => return error_response(S3Error::MalformedXML, &resource),
        };

    let parts: Vec<(u32, String)> = request
        .parts
        .into_iter()
        .map(|p| (p.part_number, p.etag))
        .collect();

    match storage
        .complete_multipart_upload(bucket, upload_id, parts)
        .await
    {
        Ok((completed_key, etag)) => {
            // Encrypt the assembled file if SSE was requested
            let encryption_meta = match upload_meta.sse_algorithm.as_deref() {
                Some("AES256") => {
                    // SSE-S3
                    let enc_config = match config.encryption.as_ref() {
                        Some(c) => c,
                        None => {
                            return error_response(
                                S3Error::ServerSideEncryptionConfigurationNotFoundError,
                                &resource,
                            );
                        }
                    };
                    let object_path = match storage.object_path(bucket, &completed_key) {
                        Ok(p) => p,
                        Err(e) => return error_response(e, &resource),
                    };
                    match encryption::encrypt_sse_s3(&object_path, &enc_config.master_key).await {
                        Ok(meta) => Some(meta),
                        Err(e) => return error_response(e, &resource),
                    }
                }
                Some("SSE-C") => {
                    // SSE-C
                    let (cust_key, cust_md5) = sse_c_key.unwrap();
                    let object_path = match storage.object_path(bucket, &completed_key) {
                        Ok(p) => p,
                        Err(e) => return error_response(e, &resource),
                    };
                    match encryption::encrypt_sse_c(&object_path, &cust_key, &cust_md5).await {
                        Ok(meta) => Some(meta),
                        Err(e) => return error_response(e, &resource),
                    }
                }
                _ => None,
            };

            // Store encryption metadata if applicable
            if let Some(ref enc) = encryption_meta {
                let mut stored = storage
                    .get_stored_metadata(bucket, &completed_key)
                    .await
                    .unwrap_or_default();
                stored.encryption = Some(enc.clone());
                stored.etag = Some(etag.clone());
                let _ = storage
                    .put_object_metadata(bucket, &completed_key, &stored)
                    .await;
            }

            let result = xml::CompleteMultipartUploadResult {
                xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
                location: format!("/{}/{}", bucket, completed_key),
                bucket: bucket.to_string(),
                key: completed_key,
                etag,
            };
            xml_response(StatusCode::OK, xml::to_xml(&result))
        }
        Err(e) => error_response(e, &resource),
    }
}

/// DELETE /{bucket}/{key}?uploadId=X -- Abort a multipart upload.
pub async fn abort_multipart_upload(
    storage: Arc<Storage>,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> Response<BoxBody> {
    match storage.abort_multipart_upload(bucket, upload_id).await {
        Ok(()) => empty_response(StatusCode::NO_CONTENT),
        Err(e) => error_response(e, &format!("/{}/{}", bucket, key)),
    }
}

/// GET /{bucket}/{key}?uploadId=X -- List parts of a multipart upload.
pub async fn list_parts(
    storage: Arc<Storage>,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> Response<BoxBody> {
    match storage.list_parts(bucket, upload_id).await {
        Ok((_key, parts)) => {
            let result = xml::ListPartsResult {
                xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
                bucket: bucket.to_string(),
                key: key.to_string(),
                upload_id: upload_id.to_string(),
                is_truncated: false,
                parts: parts
                    .into_iter()
                    .map(|p| xml::PartEntry {
                        part_number: p.part_number,
                        last_modified: format_system_time(p.last_modified),
                        etag: p.etag,
                        size: p.size,
                    })
                    .collect(),
            };
            xml_response(StatusCode::OK, xml::to_xml(&result))
        }
        Err(e) => error_response(e, &format!("/{}/{}", bucket, key)),
    }
}

/// GET /{bucket}?uploads -- List in-progress multipart uploads.
pub async fn list_multipart_uploads(storage: Arc<Storage>, bucket: &str) -> Response<BoxBody> {
    match storage.list_multipart_uploads(bucket).await {
        Ok(uploads) => {
            let result = xml::ListMultipartUploadsResult {
                xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
                bucket: bucket.to_string(),
                is_truncated: false,
                uploads: uploads
                    .into_iter()
                    .map(|u| xml::UploadEntry {
                        key: u.key,
                        upload_id: u.upload_id,
                        initiated: u.initiated,
                    })
                    .collect(),
            };
            xml_response(StatusCode::OK, xml::to_xml(&result))
        }
        Err(e) => error_response(e, &format!("/{}", bucket)),
    }
}
