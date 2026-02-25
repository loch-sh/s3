use std::sync::Arc;

use futures_util::TryStreamExt;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response, StatusCode};
use tokio_util::io::ReaderStream;

use super::{BoxBody, empty_response, error_response, full_body, xml_response};
use crate::ServerConfig;
use crate::encryption::{self, EncryptionMeta, SseAlgorithm, SseRequest};
use crate::error::S3Error;
use crate::storage::bucket::format_system_time;
use crate::storage::object::{ObjectMetadata, StoredMetadata};
use crate::storage::versioning::{VersionMeta, VersioningStatus};
use crate::storage::{Storage, guess_content_type};
use crate::xml;

/// Extract S3 metadata headers from the request.
fn extract_metadata(req: &Request<Incoming>) -> StoredMetadata {
    let headers = req.headers();
    let mut user_metadata = std::collections::HashMap::new();

    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if let Some(meta_key) = name_str.strip_prefix("x-amz-meta-") {
            if let Ok(v) = value.to_str() {
                user_metadata.insert(meta_key.to_string(), v.to_string());
            }
        }
    }

    let get_header = |name: &str| -> Option<String> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    };

    // Filter out aws-chunked from content-encoding (transport, not user metadata)
    let content_encoding = get_header("content-encoding")
        .map(|v| {
            v.split(',')
                .map(|s| s.trim())
                .filter(|s| !s.eq_ignore_ascii_case("aws-chunked"))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|v| !v.is_empty());

    StoredMetadata {
        content_type: get_header("content-type"),
        cache_control: get_header("cache-control"),
        content_disposition: get_header("content-disposition"),
        content_encoding,
        content_language: get_header("content-language"),
        expires: get_header("expires"),
        user_metadata,
        encryption: None,
        etag: None,
    }
}

/// Apply stored metadata headers to a response builder.
fn apply_stored_metadata_headers(
    mut builder: hyper::http::response::Builder,
    stored: &StoredMetadata,
) -> hyper::http::response::Builder {
    if let Some(ref v) = stored.cache_control {
        builder = builder.header("Cache-Control", v.as_str());
    }
    if let Some(ref v) = stored.content_disposition {
        builder = builder.header("Content-Disposition", v.as_str());
    }
    if let Some(ref v) = stored.content_encoding {
        builder = builder.header("Content-Encoding", v.as_str());
    }
    if let Some(ref v) = stored.content_language {
        builder = builder.header("Content-Language", v.as_str());
    }
    if let Some(ref v) = stored.expires {
        builder = builder.header("Expires", v.as_str());
    }
    for (k, v) in &stored.user_metadata {
        builder = builder.header(format!("x-amz-meta-{}", k), v.as_str());
    }
    builder
}

/// Parse SSE headers from a request and validate SSE-S3 availability.
/// Returns the parsed SseRequest, or an error response if invalid.
pub(crate) fn parse_and_validate_sse(
    headers: &hyper::header::HeaderMap,
    config: &ServerConfig,
    resource: &str,
) -> Result<SseRequest, Response<BoxBody>> {
    let sse_request =
        encryption::parse_sse_headers(headers).map_err(|e| error_response(e, resource))?;

    if matches!(sse_request, SseRequest::SseS3) && config.encryption.is_none() {
        return Err(error_response(
            S3Error::ServerSideEncryptionConfigurationNotFoundError,
            resource,
        ));
    }

    Ok(sse_request)
}

/// If no SSE headers were sent, check bucket default encryption configuration.
/// If the bucket has AES256 default encryption and the server has a master key, upgrade to SSE-S3.
pub(crate) async fn apply_bucket_default_encryption(
    sse_request: SseRequest,
    storage: &Storage,
    config: &ServerConfig,
    bucket: &str,
) -> SseRequest {
    if !matches!(sse_request, SseRequest::None) {
        return sse_request;
    }
    if config.encryption.is_none() {
        return SseRequest::None;
    }
    if let Ok(data) = storage.get_bucket_encryption(bucket).await {
        if let Ok(enc) =
            serde_json::from_slice::<crate::xml::ServerSideEncryptionConfiguration>(&data)
        {
            if enc.rule.apply_default.sse_algorithm == "AES256" {
                return SseRequest::SseS3;
            }
        }
    }
    SseRequest::None
}

/// Determine the version ID to use based on versioning status.
/// Returns None for Unversioned, Some(generated_id) for Enabled, Some("null") for Suspended.
fn version_id_for_status(status: &VersioningStatus) -> Option<String> {
    match status {
        VersioningStatus::Enabled => Some(Storage::generate_version_id()),
        VersioningStatus::Suspended => Some("null".to_string()),
        VersioningStatus::Unversioned => None,
    }
}

/// Store a new version of an object and return a response with ETag and version-id headers.
/// Used by put_object and copy_object to avoid duplicating Enabled/Suspended logic.
async fn store_version_and_respond(
    storage: &Storage,
    bucket: &str,
    key: &str,
    vid: &str,
    etag: &str,
    resource: &str,
) -> Response<BoxBody> {
    let object_path = match storage.object_path(bucket, key) {
        Ok(p) => p,
        Err(e) => return error_response(e, resource),
    };

    let file_meta = match tokio::fs::symlink_metadata(&object_path).await {
        Ok(m) => m,
        Err(e) => return error_response(S3Error::InternalError(e.to_string()), resource),
    };

    let stored = storage
        .get_stored_metadata(bucket, key)
        .await
        .unwrap_or_default();
    let content_type = stored
        .content_type
        .clone()
        .unwrap_or_else(|| guess_content_type(key));

    let meta = VersionMeta::from_stored(
        etag.to_string(),
        content_type,
        format_system_time(
            file_meta
                .modified()
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH),
        ),
        file_meta.len(),
        stored,
    );

    if let Err(e) = storage
        .store_version(bucket, key, vid, &object_path, &meta)
        .await
    {
        return error_response(e, resource);
    }

    Response::builder()
        .status(StatusCode::OK)
        .header("ETag", etag)
        .header("x-amz-version-id", vid)
        .body(full_body(bytes::Bytes::new()))
        .unwrap()
}

/// Create a delete marker and return the appropriate response.
/// Used by delete_object to avoid duplicating Enabled/Suspended logic.
async fn create_delete_marker_and_respond(
    storage: &Storage,
    bucket: &str,
    key: &str,
    vid: &str,
    resource: &str,
) -> Response<BoxBody> {
    if let Err(e) = storage.migrate_pre_versioning_object(bucket, key).await {
        return error_response(e, resource);
    }

    if let Err(e) = storage.store_delete_marker(bucket, key, vid).await {
        return error_response(e, resource);
    }

    // Remove normal path file
    let _ = storage.delete_object(bucket, key).await;

    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("x-amz-version-id", vid)
        .header("x-amz-delete-marker", "true")
        .body(full_body(bytes::Bytes::new()))
        .unwrap()
}

/// Store a version for a copy destination, returning the version ID if applicable.
async fn store_destination_version(
    storage: &Storage,
    bucket: &str,
    key: &str,
    vid: &str,
    etag: &str,
    content_type: &str,
    last_modified: std::time::SystemTime,
    size: u64,
    dst_path: &std::path::Path,
) {
    let stored = storage
        .get_stored_metadata(bucket, key)
        .await
        .unwrap_or_default();
    let meta = VersionMeta::from_stored(
        etag.to_string(),
        content_type.to_string(),
        format_system_time(last_modified),
        size,
        stored,
    );
    let _ = storage
        .store_version(bucket, key, vid, dst_path, &meta)
        .await;
}

/// PUT /{bucket}/{key+} — Upload an object (streams body to disk).
pub async fn put_object(
    config: Arc<ServerConfig>,
    bucket: &str,
    key: &str,
    req: Request<Incoming>,
) -> Response<BoxBody> {
    let resource = format!("/{}/{}", bucket, key);
    let storage = &config.storage;

    // Parse and validate SSE headers
    let sse_request = match parse_and_validate_sse(req.headers(), &config, &resource) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Apply bucket default encryption if no SSE headers specified
    let sse_request = apply_bucket_default_encryption(sse_request, storage, &config, bucket).await;

    let aws_chunked = is_aws_chunked(&req);
    let mut metadata = extract_metadata(&req);
    let body = req.into_body();

    // Stream body to disk (plaintext) with MD5
    let etag = match storage.put_object(bucket, key, body, aws_chunked).await {
        Ok(etag) => etag,
        Err(e) => return error_response(e, &resource),
    };

    // Encrypt if requested
    let encryption_meta = match sse_request {
        SseRequest::None => None,
        SseRequest::SseS3 => {
            let enc_config = config.encryption.as_ref().unwrap();
            let object_path = match storage.object_path(bucket, key) {
                Ok(p) => p,
                Err(e) => return error_response(e, &resource),
            };
            match encryption::encrypt_sse_s3(&object_path, &enc_config.master_key).await {
                Ok(meta) => Some(meta),
                Err(e) => return error_response(e, &resource),
            }
        }
        SseRequest::SseC {
            key: ref cust_key,
            ref key_md5,
        } => {
            let object_path = match storage.object_path(bucket, key) {
                Ok(p) => p,
                Err(e) => return error_response(e, &resource),
            };
            match encryption::encrypt_sse_c(&object_path, cust_key, key_md5).await {
                Ok(meta) => Some(meta),
                Err(e) => return error_response(e, &resource),
            }
        }
    };

    // Store encryption metadata and plaintext ETag
    metadata.encryption = encryption_meta.clone();
    if encryption_meta.is_some() {
        metadata.etag = Some(etag.clone());
    }

    // Persist object metadata sidecar
    if let Err(e) = storage.put_object_metadata(bucket, key, &metadata).await {
        return error_response(e, &resource);
    }

    // Check versioning status and store version if needed
    let versioning = storage
        .get_versioning(bucket)
        .await
        .unwrap_or(VersioningStatus::Unversioned);

    match version_id_for_status(&versioning) {
        Some(vid) => store_version_and_respond(storage, bucket, key, &vid, &etag, &resource).await,
        None => {
            let builder = Response::builder()
                .status(StatusCode::OK)
                .header("ETag", &etag);
            let builder = apply_sse_headers_to_builder(builder, &encryption_meta);
            builder.body(full_body(bytes::Bytes::new())).unwrap()
        }
    }
}

/// Check if the request uses AWS chunked transfer encoding.
pub(crate) fn is_aws_chunked(req: &Request<Incoming>) -> bool {
    req.headers()
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("aws-chunked"))
        .unwrap_or(false)
}

/// Apply standard object metadata headers to a response builder.
fn object_meta_headers(
    mut builder: hyper::http::response::Builder,
    meta: &ObjectMetadata,
) -> hyper::http::response::Builder {
    builder = builder
        .header("Content-Length", meta.content_length.to_string())
        .header("Content-Type", &meta.content_type)
        .header("ETag", &meta.etag)
        .header("Last-Modified", format_http_date(meta.last_modified))
        .header("Accept-Ranges", "bytes");

    if let Some(ref v) = meta.cache_control {
        builder = builder.header("Cache-Control", v.as_str());
    }
    if let Some(ref v) = meta.content_disposition {
        builder = builder.header("Content-Disposition", v.as_str());
    }
    if let Some(ref v) = meta.content_encoding {
        builder = builder.header("Content-Encoding", v.as_str());
    }
    if let Some(ref v) = meta.content_language {
        builder = builder.header("Content-Language", v.as_str());
    }
    if let Some(ref v) = meta.expires {
        builder = builder.header("Expires", v.as_str());
    }
    for (k, v) in &meta.user_metadata {
        builder = builder.header(format!("x-amz-meta-{}", k), v.as_str());
    }
    builder
}

/// Apply SSE response headers to a response builder.
fn apply_sse_headers_to_builder(
    mut builder: hyper::http::response::Builder,
    encryption: &Option<EncryptionMeta>,
) -> hyper::http::response::Builder {
    if let Some(enc) = encryption {
        match enc.algorithm {
            SseAlgorithm::SseS3 => {
                builder = builder.header("x-amz-server-side-encryption", "AES256");
            }
            SseAlgorithm::SseC => {
                builder =
                    builder.header("x-amz-server-side-encryption-customer-algorithm", "AES256");
                if let Some(ref md5) = enc.customer_key_md5 {
                    builder = builder.header(
                        "x-amz-server-side-encryption-customer-key-md5",
                        md5.as_str(),
                    );
                }
            }
        }
    }
    builder
}

/// Build a streaming response body, decrypting if the object is encrypted.
async fn build_object_body(
    config: &ServerConfig,
    file_path: &std::path::Path,
    encryption: &Option<EncryptionMeta>,
    req_headers: &hyper::header::HeaderMap,
    resource: &str,
) -> Result<(BoxBody, Option<EncryptionMeta>), Response<BoxBody>> {
    match encryption {
        None => {
            // Unencrypted: stream directly
            let file = match tokio::fs::File::open(file_path).await {
                Ok(f) => f,
                Err(e) => {
                    return Err(error_response(
                        S3Error::InternalError(e.to_string()),
                        resource,
                    ));
                }
            };
            let reader_stream = ReaderStream::new(file);
            let stream_body = StreamBody::new(reader_stream.map_ok(Frame::data)).boxed();
            Ok((stream_body, None))
        }
        Some(enc) => {
            match enc.algorithm {
                SseAlgorithm::SseS3 => {
                    // Derive key from master key + salt
                    let key = match encryption::resolve_decryption_key(
                        enc,
                        config.encryption.as_ref(),
                        None,
                    ) {
                        Ok(k) => k,
                        Err(e) => return Err(error_response(e, resource)),
                    };
                    let nonce = match encryption::decode_nonce(enc) {
                        Ok(n) => n,
                        Err(e) => return Err(error_response(e, resource)),
                    };
                    let file = match tokio::fs::File::open(file_path).await {
                        Ok(f) => f,
                        Err(e) => {
                            return Err(error_response(
                                S3Error::InternalError(e.to_string()),
                                resource,
                            ));
                        }
                    };
                    let body =
                        encryption::build_decrypting_body(file, key, nonce, enc.plaintext_size);
                    Ok((body, Some(enc.clone())))
                }
                SseAlgorithm::SseC => {
                    // Parse SSE-C headers from the GET/HEAD request
                    let (cust_key, cust_md5) =
                        match encryption::parse_sse_c_get_headers(req_headers) {
                            Ok(Some(k)) => k,
                            Ok(None) => {
                                return Err(error_response(
                                    S3Error::MissingSecurityHeader,
                                    resource,
                                ));
                            }
                            Err(e) => return Err(error_response(e, resource)),
                        };
                    // Verify customer key MD5 matches stored
                    if let Some(ref stored_md5) = enc.customer_key_md5 {
                        if cust_md5 != *stored_md5 {
                            return Err(error_response(S3Error::AccessDenied, resource));
                        }
                    }
                    let nonce = match encryption::decode_nonce(enc) {
                        Ok(n) => n,
                        Err(e) => return Err(error_response(e, resource)),
                    };
                    let file = match tokio::fs::File::open(file_path).await {
                        Ok(f) => f,
                        Err(e) => {
                            return Err(error_response(
                                S3Error::InternalError(e.to_string()),
                                resource,
                            ));
                        }
                    };
                    let body = encryption::build_decrypting_body(
                        file,
                        cust_key,
                        nonce,
                        enc.plaintext_size,
                    );
                    Ok((body, Some(enc.clone())))
                }
            }
        }
    }
}

/// GET /{bucket}/{key+} — Download an object (streams file from disk).
pub async fn get_object(
    config: Arc<ServerConfig>,
    bucket: &str,
    key: &str,
    req: &Request<Incoming>,
    version_id: Option<&str>,
) -> Response<BoxBody> {
    let resource = format!("/{}/{}", bucket, key);
    let storage = &config.storage;
    let req_headers = req.headers();

    // GET with specific versionId — read from .versions/
    if let Some(vid) = version_id {
        match storage.is_version_delete_marker(bucket, key, vid).await {
            Ok(true) => {
                return Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .header("x-amz-version-id", vid)
                    .header("x-amz-delete-marker", "true")
                    .body(full_body(bytes::Bytes::new()))
                    .unwrap();
            }
            Ok(false) => {}
            Err(e) => return error_response(e, &resource),
        }

        let ver_meta = match storage.get_version_meta(bucket, key, vid).await {
            Ok(m) => m,
            Err(e) => return error_response(e, &resource),
        };

        let data_path = match storage.get_version_data_path(bucket, key, vid).await {
            Ok(p) => p,
            Err(e) => return error_response(e, &resource),
        };

        // Build body (decrypt if encrypted)
        let (stream_body, enc) = match build_object_body(
            &config,
            &data_path,
            &ver_meta.encryption,
            req_headers,
            &resource,
        )
        .await
        {
            Ok(r) => r,
            Err(resp) => return resp,
        };

        let content_length = ver_meta
            .encryption
            .as_ref()
            .map_or(ver_meta.size, |e| e.plaintext_size);

        let mut builder = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Length", content_length.to_string())
            .header("Content-Type", &ver_meta.content_type)
            .header("ETag", &ver_meta.etag)
            .header("Last-Modified", &ver_meta.last_modified)
            .header("Accept-Ranges", "bytes")
            .header("x-amz-version-id", vid);
        if let Some(ref m) = ver_meta.metadata {
            builder = apply_stored_metadata_headers(builder, m);
        }
        builder = apply_sse_headers_to_builder(builder, &enc);
        return builder.body(stream_body).unwrap();
    }

    // GET without versionId — check versioning for headers
    let versioning = storage
        .get_versioning(bucket)
        .await
        .unwrap_or(VersioningStatus::Unversioned);

    if versioning != VersioningStatus::Unversioned {
        match storage.get_latest_version(bucket, key).await {
            Ok(Some((vid, true))) => {
                return Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header("x-amz-version-id", &vid)
                    .header("x-amz-delete-marker", "true")
                    .body(full_body(bytes::Bytes::new()))
                    .unwrap();
            }
            Ok(Some((vid, false))) => match storage.get_object_meta(bucket, key).await {
                Ok((meta, file_path)) => {
                    let (stream_body, enc) = match build_object_body(
                        &config,
                        &file_path,
                        &meta.encryption,
                        req_headers,
                        &resource,
                    )
                    .await
                    {
                        Ok(r) => r,
                        Err(resp) => return resp,
                    };

                    let builder =
                        object_meta_headers(Response::builder().status(StatusCode::OK), &meta)
                            .header("x-amz-version-id", &vid);
                    let builder = apply_sse_headers_to_builder(builder, &enc);
                    return builder.body(stream_body).unwrap();
                }
                Err(e) => return error_response(e, &resource),
            },
            Ok(None) => {}
            Err(e) => return error_response(e, &resource),
        }
    }

    // Normal GET (unversioned)
    match storage.get_object_meta(bucket, key).await {
        Ok((meta, file_path)) => {
            let (stream_body, enc) = match build_object_body(
                &config,
                &file_path,
                &meta.encryption,
                req_headers,
                &resource,
            )
            .await
            {
                Ok(r) => r,
                Err(resp) => return resp,
            };

            let builder = object_meta_headers(Response::builder().status(StatusCode::OK), &meta);
            let builder = apply_sse_headers_to_builder(builder, &enc);
            builder.body(stream_body).unwrap()
        }
        Err(e) => error_response(e, &resource),
    }
}

/// HEAD /{bucket}/{key+} — Get object metadata.
pub async fn head_object(
    config: Arc<ServerConfig>,
    bucket: &str,
    key: &str,
    req: &Request<Incoming>,
    version_id: Option<&str>,
) -> Response<BoxBody> {
    let resource = format!("/{}/{}", bucket, key);
    let storage = &config.storage;

    // For SSE-C HEAD, validate customer key if object is encrypted
    let validate_sse_c = |enc: &Option<EncryptionMeta>| -> Result<(), Response<BoxBody>> {
        if let Some(e) = enc {
            if e.algorithm == SseAlgorithm::SseC {
                let (_, cust_md5) = match encryption::parse_sse_c_get_headers(req.headers()) {
                    Ok(Some(k)) => k,
                    Ok(None) => {
                        return Err(error_response(S3Error::MissingSecurityHeader, &resource));
                    }
                    Err(err) => return Err(error_response(err, &resource)),
                };
                if let Some(stored_md5) = &e.customer_key_md5 {
                    if cust_md5 != *stored_md5 {
                        return Err(error_response(S3Error::AccessDenied, &resource));
                    }
                }
            }
        }
        Ok(())
    };

    // HEAD with specific versionId
    if let Some(vid) = version_id {
        match storage.is_version_delete_marker(bucket, key, vid).await {
            Ok(true) => {
                return Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .header("x-amz-version-id", vid)
                    .header("x-amz-delete-marker", "true")
                    .body(full_body(bytes::Bytes::new()))
                    .unwrap();
            }
            Ok(false) => {}
            Err(e) => return error_response(e, &resource),
        }

        let ver_meta = match storage.get_version_meta(bucket, key, vid).await {
            Ok(m) => m,
            Err(e) => return error_response(e, &resource),
        };

        if let Err(resp) = validate_sse_c(&ver_meta.encryption) {
            return resp;
        }

        let content_length = ver_meta
            .encryption
            .as_ref()
            .map_or(ver_meta.size, |e| e.plaintext_size);

        let mut builder = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Length", content_length.to_string())
            .header("Content-Type", &ver_meta.content_type)
            .header("ETag", &ver_meta.etag)
            .header("Last-Modified", &ver_meta.last_modified)
            .header("Accept-Ranges", "bytes")
            .header("x-amz-version-id", vid);
        if let Some(ref m) = ver_meta.metadata {
            builder = apply_stored_metadata_headers(builder, m);
        }
        builder = apply_sse_headers_to_builder(builder, &ver_meta.encryption);
        return builder.body(full_body(bytes::Bytes::new())).unwrap();
    }

    // HEAD without versionId — check versioning
    let versioning = storage
        .get_versioning(bucket)
        .await
        .unwrap_or(VersioningStatus::Unversioned);

    if versioning != VersioningStatus::Unversioned {
        match storage.get_latest_version(bucket, key).await {
            Ok(Some((vid, true))) => {
                return Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header("x-amz-version-id", &vid)
                    .header("x-amz-delete-marker", "true")
                    .body(full_body(bytes::Bytes::new()))
                    .unwrap();
            }
            Ok(Some((vid, false))) => match storage.head_object(bucket, key).await {
                Ok(meta) => {
                    if let Err(resp) = validate_sse_c(&meta.encryption) {
                        return resp;
                    }
                    let builder =
                        object_meta_headers(Response::builder().status(StatusCode::OK), &meta)
                            .header("x-amz-version-id", &vid);
                    let builder = apply_sse_headers_to_builder(builder, &meta.encryption);
                    return builder.body(full_body(bytes::Bytes::new())).unwrap();
                }
                Err(e) => return error_response(e, &resource),
            },
            Ok(None) => {}
            Err(e) => return error_response(e, &resource),
        }
    }

    // Normal HEAD (unversioned)
    match storage.head_object(bucket, key).await {
        Ok(meta) => {
            if let Err(resp) = validate_sse_c(&meta.encryption) {
                return resp;
            }
            let builder = object_meta_headers(Response::builder().status(StatusCode::OK), &meta);
            let builder = apply_sse_headers_to_builder(builder, &meta.encryption);
            builder.body(full_body(bytes::Bytes::new())).unwrap()
        }
        Err(e) => error_response(e, &resource),
    }
}

/// DELETE /{bucket}/{key+} — Delete an object.
pub async fn delete_object(
    storage: Arc<Storage>,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> Response<BoxBody> {
    let resource = format!("/{}/{}", bucket, key);

    // DELETE with specific versionId — permanent delete of that version
    if let Some(vid) = version_id {
        let was_marker = match storage.delete_version(bucket, key, vid).await {
            Ok(was_marker) => was_marker,
            Err(e) => return error_response(e, &resource),
        };

        // Sync normal path after version removal
        if let Err(e) = storage.sync_normal_path(bucket, key).await {
            return error_response(e, &resource);
        }

        let mut builder = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("x-amz-version-id", vid);
        if was_marker {
            builder = builder.header("x-amz-delete-marker", "true");
        }
        return builder.body(full_body(bytes::Bytes::new())).unwrap();
    }

    // Check versioning status
    let versioning = storage
        .get_versioning(bucket)
        .await
        .unwrap_or(VersioningStatus::Unversioned);

    match version_id_for_status(&versioning) {
        Some(vid) => create_delete_marker_and_respond(&storage, bucket, key, &vid, &resource).await,
        None => match storage.delete_object(bucket, key).await {
            Ok(()) => empty_response(StatusCode::NO_CONTENT),
            Err(e) => error_response(e, &resource),
        },
    }
}

/// PUT /{bucket}/{key+} with x-amz-copy-source — Copy an object.
pub async fn copy_object(
    config: Arc<ServerConfig>,
    bucket: &str,
    key: &str,
    copy_source: &str,
    req: Request<Incoming>,
) -> Response<BoxBody> {
    let storage = &config.storage;
    let resource = format!("/{}/{}", bucket, key);

    // Check metadata directive: REPLACE means use headers from this request,
    // COPY (default) means preserve source metadata.
    let metadata_directive = req
        .headers()
        .get("x-amz-metadata-directive")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("COPY")
        .to_uppercase();
    let replace_metadata = metadata_directive == "REPLACE";
    let override_metadata = if replace_metadata {
        Some(extract_metadata(&req))
    } else {
        None
    };

    // Parse and validate destination SSE headers
    let dst_sse = match parse_and_validate_sse(req.headers(), &config, &resource) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Parse SSE-C copy source headers (for decrypting SSE-C source)
    let src_sse_c = match encryption::parse_sse_c_copy_source_headers(req.headers()) {
        Ok(r) => r,
        Err(e) => return error_response(e, &resource),
    };

    // Parse x-amz-copy-source: /source-bucket/source-key[?versionId=X]
    let source = copy_source.trim_start_matches('/');

    // Extract versionId from copy source if present
    let (source_path, source_version_id) = if let Some(pos) = source.find("?versionId=") {
        (&source[..pos], Some(&source[pos + 11..]))
    } else {
        (source, None)
    };

    let (src_bucket, src_key) = match source_path.find('/') {
        Some(pos) => (&source_path[..pos], &source_path[pos + 1..]),
        None => {
            return error_response(
                S3Error::InternalError("Invalid copy source".to_string()),
                &resource,
            );
        }
    };

    // URL-decode the source key (AWS CLI may encode it)
    let src_key = url_decode(src_key);

    // Resolve source data path and encryption metadata
    let (src_data_path, src_enc_meta, src_stored_meta) = if let Some(vid) = source_version_id {
        // Check it is not a delete marker
        match storage
            .is_version_delete_marker(src_bucket, &src_key, vid)
            .await
        {
            Ok(true) => return error_response(S3Error::MethodNotAllowed, &resource),
            Ok(false) => {}
            Err(e) => return error_response(e, &resource),
        }

        let data_path = match storage
            .get_version_data_path(src_bucket, &src_key, vid)
            .await
        {
            Ok(p) => p,
            Err(e) => return error_response(e, &resource),
        };

        let ver_meta = match storage.get_version_meta(src_bucket, &src_key, vid).await {
            Ok(m) => m,
            Err(e) => return error_response(e, &resource),
        };

        let stored = ver_meta.metadata.unwrap_or_default();
        (data_path, ver_meta.encryption, stored)
    } else {
        let src_path = match storage.object_path(src_bucket, &src_key) {
            Ok(p) => p,
            Err(e) => return error_response(e, &resource),
        };

        if !crate::storage::is_regular_file(&src_path).await {
            return error_response(S3Error::NoSuchKey, &resource);
        }

        let stored = storage
            .get_stored_metadata(src_bucket, &src_key)
            .await
            .unwrap_or_default();
        let enc = stored.encryption.clone();
        (src_path, enc, stored)
    };

    // Prepare destination path
    let dst_path = match storage.object_path(bucket, key) {
        Ok(p) => p,
        Err(e) => return error_response(e, &resource),
    };
    if let Some(parent) = dst_path.parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            return error_response(S3Error::InternalError(e.to_string()), &resource);
        }
    }

    let tmp_path = crate::storage::atomic_tmp_path(&dst_path);

    // Determine if source needs decryption
    let needs_decrypt = src_enc_meta.is_some();
    if needs_decrypt {
        let enc = src_enc_meta.as_ref().unwrap();
        // Resolve source decryption key
        let src_key_bytes = match enc.algorithm {
            SseAlgorithm::SseS3 => {
                match encryption::resolve_decryption_key(enc, config.encryption.as_ref(), None) {
                    Ok(k) => k,
                    Err(e) => return error_response(e, &resource),
                }
            }
            SseAlgorithm::SseC => {
                // Require copy-source SSE-C headers
                let src_cust = match src_sse_c {
                    Some(ref c) => c,
                    None => return error_response(S3Error::MissingSecurityHeader, &resource),
                };
                // Verify key MD5 matches stored
                if let Some(ref stored_md5) = enc.customer_key_md5 {
                    if src_cust.key_md5 != *stored_md5 {
                        return error_response(S3Error::AccessDenied, &resource);
                    }
                }
                src_cust.key
            }
        };
        let nonce = match encryption::decode_nonce(enc) {
            Ok(n) => n,
            Err(e) => return error_response(e, &resource),
        };

        // Decrypt source to temp file (plaintext)
        if let Err(e) = encryption::decrypt_file_to(
            &src_data_path,
            &tmp_path,
            &src_key_bytes,
            &nonce,
            enc.plaintext_size,
        )
        .await
        {
            return error_response(e, &resource);
        }
    } else {
        // No decryption needed: raw copy
        if let Err(e) = tokio::fs::copy(&src_data_path, &tmp_path).await {
            return error_response(S3Error::InternalError(e.to_string()), &resource);
        }
    }

    // Compute plaintext ETag (tmp_path is now plaintext)
    let etag = match crate::storage::object::compute_file_md5(&tmp_path).await {
        Ok(e) => e,
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return error_response(e, &resource);
        }
    };

    // Atomic rename to destination
    if let Err(e) = tokio::fs::rename(&tmp_path, &dst_path).await {
        return error_response(S3Error::InternalError(e.to_string()), &resource);
    }

    // Encrypt destination if requested
    let dst_enc_meta = match dst_sse {
        SseRequest::None => None,
        SseRequest::SseS3 => {
            let enc_config = config.encryption.as_ref().unwrap();
            match encryption::encrypt_sse_s3(&dst_path, &enc_config.master_key).await {
                Ok(meta) => Some(meta),
                Err(e) => return error_response(e, &resource),
            }
        }
        SseRequest::SseC {
            ref key,
            ref key_md5,
        } => match encryption::encrypt_sse_c(&dst_path, key, key_md5).await {
            Ok(meta) => Some(meta),
            Err(e) => return error_response(e, &resource),
        },
    };

    // Build destination metadata
    let mut dst_metadata = if let Some(ref meta) = override_metadata {
        meta.clone()
    } else {
        // Copy source metadata but strip source encryption info
        let mut m = src_stored_meta.clone();
        m.encryption = None;
        m.etag = None;
        m
    };

    dst_metadata.encryption = dst_enc_meta.clone();
    if dst_metadata.encryption.is_some() {
        dst_metadata.etag = Some(etag.clone());
    }

    let _ = storage
        .put_object_metadata(bucket, key, &dst_metadata)
        .await;

    let file_meta = match tokio::fs::symlink_metadata(&dst_path).await {
        Ok(m) => m,
        Err(e) => return error_response(S3Error::InternalError(e.to_string()), &resource),
    };
    let last_modified = file_meta
        .modified()
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);

    // If destination is versioned, create a version
    let dst_versioning = storage
        .get_versioning(bucket)
        .await
        .unwrap_or(VersioningStatus::Unversioned);
    let dst_vid = if let Some(vid) = version_id_for_status(&dst_versioning) {
        let ct = dst_metadata
            .content_type
            .clone()
            .unwrap_or_else(|| guess_content_type(key));
        store_destination_version(
            &storage,
            bucket,
            key,
            &vid,
            &etag,
            &ct,
            last_modified,
            file_meta.len(),
            &dst_path,
        )
        .await;
        Some(vid)
    } else {
        None
    };

    let result = xml::CopyObjectResult {
        last_modified: format_system_time(last_modified),
        etag,
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/xml");
    if let Some(vid) = &dst_vid {
        builder = builder.header("x-amz-version-id", vid.as_str());
    }
    builder = apply_sse_headers_to_builder(builder, &dst_enc_meta);
    builder.body(full_body(xml::to_xml(&result))).unwrap()
}

/// GET /{bucket}?list-type=2 — List objects in a bucket.
pub async fn list_objects(storage: Arc<Storage>, bucket: &str, query: &str) -> Response<BoxBody> {
    let params = parse_query(query);
    let prefix = params.get("prefix").map(|s| s.as_str()).unwrap_or("");
    let delimiter = params.get("delimiter").map(|s| s.as_str()).unwrap_or("");
    // Cap max_keys at 1000 (AWS spec maximum)
    let max_keys: usize = params
        .get("max-keys")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000)
        .min(1000);
    let start_after = params
        .get("start-after")
        .or_else(|| params.get("continuation-token"))
        .map(|s| s.as_str())
        .unwrap_or("");

    match storage
        .list_objects(bucket, prefix, delimiter, max_keys, start_after)
        .await
    {
        Ok(result) => {
            let mut xml_result = xml::ListBucketResult::new(result.name, result.prefix);
            xml_result.delimiter = result.delimiter;
            xml_result.max_keys = result.max_keys;
            xml_result.is_truncated = result.is_truncated;
            xml_result.next_continuation_token = result.next_continuation_token;
            xml_result.key_count = result.objects.len();

            xml_result.contents = result
                .objects
                .into_iter()
                .map(|o| xml::ObjectEntry {
                    key: o.key,
                    last_modified: format_system_time(o.last_modified),
                    etag: o.etag,
                    size: o.size,
                    storage_class: "STANDARD".to_string(),
                })
                .collect();

            xml_result.common_prefixes = result
                .common_prefixes
                .into_iter()
                .map(|p| xml::CommonPrefix { prefix: p })
                .collect();

            xml_response(StatusCode::OK, xml::to_xml(&xml_result))
        }
        Err(e) => error_response(e, &format!("/{}", bucket)),
    }
}

/// Parse query string into key-value pairs.
pub(crate) fn parse_query(query: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(url_decode(k), url_decode(v));
        } else if !pair.is_empty() {
            map.insert(url_decode(pair), String::new());
        }
    }
    map
}

/// Simple URL percent-decoding.
fn url_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next().unwrap_or(b'0');
            let lo = chars.next().unwrap_or(b'0');
            let byte = hex_val(hi) * 16 + hex_val(lo);
            result.push(byte as char);
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// Format a SystemTime as an HTTP date (RFC 7231).
fn format_http_date(time: std::time::SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Utc> = time.into();
    dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}
