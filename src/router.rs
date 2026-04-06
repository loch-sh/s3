use std::sync::Arc;

use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::{Method, Request, Response, StatusCode};

use crate::ServerConfig;
use crate::auth::{self, AuthenticatedUser};
use crate::cors::CorsConfiguration;
use crate::error::S3Error;
use crate::handlers::{self, BoxBody, empty_response, full_body, read_body_limited};
use crate::policy::S3Action;
use crate::storage::Storage;
use crate::users::UserStore;

/// Route an incoming HTTP request to the appropriate S3 handler.
pub async fn route(
    req: Request<Incoming>,
    config: Arc<ServerConfig>,
) -> Result<Response<BoxBody>, std::convert::Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();

    // Log incoming request
    let uri = if query.is_empty() {
        path.clone()
    } else {
        format!("{}?{}", path, query)
    };
    eprintln!("--> {} {}", method, uri);
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            eprintln!("    {}: {}", name, v);
        }
    }
    let origin = req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let storage = config.storage.clone();

    // Parse path: /{bucket} or /{bucket}/{key...}
    // URL-decode the key so percent-encoded characters (e.g. %20 for spaces) are resolved.
    let trimmed = path.trim_start_matches('/');
    let (bucket, key) = if trimmed.is_empty() {
        (String::new(), String::new())
    } else if let Some(pos) = trimmed.find('/') {
        (
            trimmed[..pos].to_string(),
            percent_decode(&trimmed[pos + 1..]),
        )
    } else {
        (trimmed.to_string(), String::new())
    };

    let has_bucket = !bucket.is_empty();
    let has_key = !key.is_empty();

    // Detect sub-resource query parameters
    let query_params = crate::handlers::object::parse_query(&query);
    let is_policy_request = query_params.contains_key("policy");
    let is_cors_request = query_params.contains_key("cors");
    let is_uploads_request = query_params.contains_key("uploads");
    let has_upload_id = query_params.get("uploadId");
    let has_part_number = query_params.get("partNumber");
    let is_versioning_request = query_params.contains_key("versioning");
    let is_versions_request = query_params.contains_key("versions");
    let version_id = query_params.get("versionId").cloned();
    let is_acl_request = query_params.contains_key("acl");
    let is_encryption_request = query_params.contains_key("encryption");
    let is_acl_write = is_acl_request && method == Method::PUT;
    let is_versioning_write = is_versioning_request && method == Method::PUT;
    let is_management_request =
        is_policy_request || is_cors_request || is_encryption_request || is_acl_write || is_versioning_write;

    // Handle OPTIONS preflight (no auth required)
    if method == Method::OPTIONS && has_bucket {
        let response = handle_preflight(&storage, &bucket, &req).await;
        eprintln!("<-- {} {}", response.status().as_u16(), uri);
        return Ok(response);
    }

    // Route user management API before auth check (uses its own Bearer auth)
    if path == "/_loch/users" || path.starts_with("/_loch/users/") {
        let response = handlers::users::route_users_api(req, &config, &path).await;
        eprintln!("<-- {} {}", response.status().as_u16(), uri);
        return Ok(response);
    }

    // Check authentication
    let is_presigned = auth::is_presigned_request(&query);
    let auth_result = auth::verify_request(&req, &config.user_store).await;
    let caller_user_id: Option<String> = match &auth_result {
        Ok(Some(user)) => Some(user.user_id.clone()),
        _ => None,
    };
    let caller_is_root: bool = matches!(&auth_result, Ok(Some(user)) if user.is_root);
    if let Some(deny) = check_auth(
        &auth_result,
        &config,
        &storage,
        &method,
        &path,
        &bucket,
        &key,
        has_bucket,
        has_key,
        is_management_request,
        is_presigned,
    )
    .await
    {
        eprintln!("<-- {} {}", deny.status().as_u16(), uri);
        return Ok(deny);
    }

    // Route policy sub-resource endpoints
    if is_policy_request && has_bucket && !has_key {
        let response = match &method {
            &Method::PUT => {
                handlers::policy::put_bucket_policy(storage.clone(), &bucket, req).await
            }
            &Method::GET => handlers::policy::get_bucket_policy(storage.clone(), &bucket).await,
            &Method::DELETE => {
                handlers::policy::delete_bucket_policy(storage.clone(), &bucket).await
            }
            _ => empty_response(StatusCode::METHOD_NOT_ALLOWED),
        };
        let response =
            maybe_add_cors_headers(response, &storage, &bucket, &method, origin.as_deref()).await;
        eprintln!("<-- {} {}", response.status().as_u16(), uri);
        return Ok(response);
    }

    // Route CORS sub-resource endpoints
    if is_cors_request && has_bucket && !has_key {
        let response = match &method {
            &Method::PUT => handlers::cors::put_bucket_cors(storage.clone(), &bucket, req).await,
            &Method::GET => handlers::cors::get_bucket_cors(storage.clone(), &bucket).await,
            &Method::DELETE => handlers::cors::delete_bucket_cors(storage.clone(), &bucket).await,
            _ => empty_response(StatusCode::METHOD_NOT_ALLOWED),
        };
        let response =
            maybe_add_cors_headers(response, &storage, &bucket, &method, origin.as_deref()).await;
        eprintln!("<-- {} {}", response.status().as_u16(), uri);
        return Ok(response);
    }

    // Route encryption sub-resource endpoints
    if is_encryption_request && has_bucket && !has_key {
        let response = match &method {
            &Method::PUT => {
                handlers::encryption::put_bucket_encryption(storage.clone(), &bucket, req).await
            }
            &Method::GET => {
                handlers::encryption::get_bucket_encryption(storage.clone(), &bucket).await
            }
            &Method::DELETE => {
                handlers::encryption::delete_bucket_encryption(storage.clone(), &bucket).await
            }
            _ => empty_response(StatusCode::METHOD_NOT_ALLOWED),
        };
        let response =
            maybe_add_cors_headers(response, &storage, &bucket, &method, origin.as_deref()).await;
        eprintln!("<-- {} {}", response.status().as_u16(), uri);
        return Ok(response);
    }

    // Try multipart upload routing (returns the request back if not matched)
    let mut req = req;
    if has_bucket {
        match route_multipart(
            &method,
            &config,
            &bucket,
            &key,
            has_key,
            is_uploads_request,
            has_upload_id,
            has_part_number,
            req,
            origin.as_deref(),
            caller_user_id.as_deref(),
        )
        .await
        {
            Ok(response) => {
                eprintln!("<-- {} {}", response.status().as_u16(), uri);
                return Ok(response);
            }
            Err(returned_req) => req = returned_req,
        }
    }

    // Versioning configuration
    if is_versioning_request && has_bucket && !has_key {
        let response = match &method {
            &Method::PUT => {
                handlers::versioning::put_bucket_versioning(storage.clone(), &bucket, req).await
            }
            &Method::GET => {
                handlers::versioning::get_bucket_versioning(storage.clone(), &bucket).await
            }
            _ => empty_response(StatusCode::METHOD_NOT_ALLOWED),
        };
        let response =
            maybe_add_cors_headers(response, &storage, &bucket, &method, origin.as_deref()).await;
        eprintln!("<-- {} {}", response.status().as_u16(), uri);
        return Ok(response);
    }

    // List object versions
    if is_versions_request && has_bucket && !has_key && method == Method::GET {
        let response =
            handlers::versioning::list_object_versions(storage.clone(), &bucket, &query).await;
        let response =
            maybe_add_cors_headers(response, &storage, &bucket, &method, origin.as_deref()).await;
        eprintln!("<-- {} {}", response.status().as_u16(), uri);
        return Ok(response);
    }

    // ACL: stored per-bucket or per-object. Returns a default if none has been set.
    // Supports both XML body and canned ACL via x-amz-acl header.
    if is_acl_request && has_bucket {
        // Check for canned ACL header before consuming the request body
        let canned_acl = req
            .headers()
            .get("x-amz-acl")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let response = match (&method, has_key) {
            (&Method::GET, false) => match storage.get_bucket_acl(&bucket).await {
                Ok(Some(data)) => handlers::xml_response(
                    StatusCode::OK,
                    String::from_utf8_lossy(&data).to_string(),
                ),
                Ok(None) => handlers::xml_response(StatusCode::OK, default_acl_xml()),
                Err(e) => handlers::error_response(e, &format!("/{}", bucket)),
            },
            (&Method::PUT, false) => {
                let acl_xml = resolve_acl_put(canned_acl, req, &format!("/{}", bucket)).await;
                match acl_xml {
                    Ok(xml) => match storage.put_bucket_acl(&bucket, xml.as_bytes()).await {
                        Ok(()) => empty_response(StatusCode::OK),
                        Err(e) => handlers::error_response(e, &format!("/{}", bucket)),
                    },
                    Err(resp) => resp,
                }
            }
            (&Method::GET, true) => match storage.get_object_acl(&bucket, &key).await {
                Ok(Some(data)) => handlers::xml_response(
                    StatusCode::OK,
                    String::from_utf8_lossy(&data).to_string(),
                ),
                Ok(None) => handlers::xml_response(StatusCode::OK, default_acl_xml()),
                Err(e) => handlers::error_response(e, &format!("/{}/{}", bucket, key)),
            },
            (&Method::PUT, true) => {
                let acl_xml =
                    resolve_acl_put(canned_acl, req, &format!("/{}/{}", bucket, key)).await;
                match acl_xml {
                    Ok(xml) => match storage.put_object_acl(&bucket, &key, xml.as_bytes()).await {
                        Ok(()) => empty_response(StatusCode::OK),
                        Err(e) => handlers::error_response(e, &format!("/{}/{}", bucket, key)),
                    },
                    Err(resp) => resp,
                }
            }
            _ => empty_response(StatusCode::METHOD_NOT_ALLOWED),
        };
        let response =
            maybe_add_cors_headers(response, &storage, &bucket, &method, origin.as_deref()).await;
        eprintln!("<-- {} {}", response.status().as_u16(), uri);
        return Ok(response);
    }

    // Standard S3 operations
    let response = match (&method, has_bucket, has_key) {
        // GET / — ListBuckets
        (&Method::GET, false, false) => {
            handlers::bucket::list_buckets(
                storage.clone(),
                caller_user_id.as_deref(),
                caller_is_root,
            )
            .await
        }

        // PUT /{bucket} — CreateBucket
        (&Method::PUT, true, false) => {
            handlers::bucket::create_bucket(storage.clone(), &bucket, caller_user_id.as_deref())
                .await
        }

        // HEAD /{bucket} — HeadBucket
        (&Method::HEAD, true, false) => {
            handlers::bucket::head_bucket(storage.clone(), &bucket).await
        }

        // DELETE /{bucket} — DeleteBucket
        (&Method::DELETE, true, false) => {
            handlers::bucket::delete_bucket(storage.clone(), &bucket).await
        }

        // GET /{bucket} — ListObjectsV2
        (&Method::GET, true, false) => {
            handlers::object::list_objects(storage.clone(), &bucket, &query).await
        }

        // PUT /{bucket}/{key+} — PutObject or CopyObject
        (&Method::PUT, true, true) => {
            if let Some(copy_source) = req.headers().get("x-amz-copy-source") {
                let source = copy_source.to_str().unwrap_or("").to_string();

                // If the request is anonymous (auth failed, but destination bucket policy
                // allowed the PUT), also verify that the source bucket/key allows anonymous
                // GET. Without this check, an anonymous user could copy private objects into
                // a world-writable bucket.
                if config.user_store.is_some() && !matches!(&auth_result, Ok(Some(_))) {
                    let src = source.trim_start_matches('/');
                    let src_path = src.split('?').next().unwrap_or(src);
                    if let Some(sep) = src_path.find('/') {
                        let src_bucket = &src_path[..sep];
                        let src_key = &src_path[sep + 1..];
                        let policy_ok = check_anonymous_access(
                            &storage,
                            src_bucket,
                            src_key,
                            S3Action::GetObject,
                        )
                        .await;
                        let acl_ok = check_acl_anonymous(
                            &storage,
                            src_bucket,
                            src_key,
                            true,
                            &Method::GET,
                        )
                        .await;
                        if !policy_ok && !acl_ok {
                            let path = format!("/{}/{}", bucket, key);
                            let deny = handlers::error_response(S3Error::AccessDenied, &path);
                            let response = maybe_add_cors_headers(
                                deny,
                                &storage,
                                &bucket,
                                &method,
                                origin.as_deref(),
                            )
                            .await;
                            eprintln!("<-- 403 {}", uri);
                            return Ok(response);
                        }
                    }
                }

                handlers::object::copy_object(
                    config.clone(),
                    &bucket,
                    &key,
                    &source,
                    req,
                    caller_user_id.as_deref(),
                )
                .await
            } else {
                handlers::object::put_object(
                    config.clone(),
                    &bucket,
                    &key,
                    req,
                    caller_user_id.as_deref(),
                )
                .await
            }
        }

        // GET /{bucket}/{key+} — GetObject
        (&Method::GET, true, true) => {
            handlers::object::get_object(config.clone(), &bucket, &key, &req, version_id.as_deref())
                .await
        }

        // HEAD /{bucket}/{key+} — HeadObject
        (&Method::HEAD, true, true) => {
            handlers::object::head_object(
                config.clone(),
                &bucket,
                &key,
                &req,
                version_id.as_deref(),
            )
            .await
        }

        // DELETE /{bucket}/{key+} — DeleteObject
        (&Method::DELETE, true, true) => {
            handlers::object::delete_object(storage.clone(), &bucket, &key, version_id.as_deref())
                .await
        }

        // Unsupported method/path combination
        _ => empty_response(StatusCode::METHOD_NOT_ALLOWED),
    };

    // Add CORS headers if Origin is present
    let response =
        maybe_add_cors_headers(response, &storage, &bucket, &method, origin.as_deref()).await;
    eprintln!("<-- {} {}", response.status().as_u16(), uri);
    Ok(response)
}

/// Check authentication and authorization. Returns Some(response) if the request should be denied.
async fn check_auth(
    auth_result: &Result<Option<AuthenticatedUser>, S3Error>,
    config: &ServerConfig,
    storage: &Storage,
    method: &Method,
    path: &str,
    bucket: &str,
    key: &str,
    has_bucket: bool,
    has_key: bool,
    is_management_request: bool,
    is_presigned: bool,
) -> Option<Response<BoxBody>> {
    // No user store configured: open access
    if config.user_store.is_none() {
        return None;
    }

    match auth_result {
        // Authenticated user
        Ok(Some(user)) => {
            // Root user: allow everything
            if user.is_root {
                return None;
            }

            // Check if user is bucket owner (if we have a bucket)
            if has_bucket {
                let owner = match storage.get_bucket_owner(bucket).await {
                    Ok(o) => o,
                    Err(e) => return Some(handlers::error_response(e, path)),
                };
                if owner.as_deref() == Some(&user.user_id) {
                    return None; // bucket owner has full access
                }
            }

            // Management endpoints: only root or bucket owner (already checked above)
            if is_management_request {
                return Some(handlers::error_response(S3Error::AccessDenied, path));
            }

            // Bucket create: any authenticated user can create
            if !has_key && *method == Method::PUT && has_bucket {
                return None;
            }

            // Bucket delete: only root or owner (already checked)
            if !has_key && *method == Method::DELETE {
                return Some(handlers::error_response(S3Error::AccessDenied, path));
            }

            // ListBuckets: any authenticated user
            if !has_bucket {
                return None;
            }

            // For data endpoints, check bucket policy for this user
            let action = determine_action(method, has_key);
            if let Some(action) = action {
                let user_arn = UserStore::arn_for(&user.user_id);
                if check_user_access(storage, bucket, key, action, &user_arn).await {
                    return None;
                }
            }

            Some(handlers::error_response(S3Error::AccessDenied, path))
        }

        // verify_request only returns Ok(None) when user_store is None,
        // which is already handled at the top. Deny defensively.
        Ok(None) => Some(handlers::error_response(S3Error::AccessDenied, path)),

        // Auth error (bad signature, expired, etc.)
        Err(auth_err) => {
            // Presigned URL auth failure: deny immediately, no anonymous fallback
            if is_presigned {
                return Some(handlers::error_response(auth_err.clone(), path));
            }

            // Management endpoints always require auth
            if is_management_request || !has_bucket {
                return Some(handlers::error_response(auth_err.clone(), path));
            }

            // Bucket create/delete require auth
            if !has_key && (*method == Method::PUT || *method == Method::DELETE) {
                return Some(handlers::error_response(auth_err.clone(), path));
            }

            // For data endpoints, check bucket policy and ACLs for anonymous access
            let action = determine_action(method, has_key);
            let allowed = if let Some(action) = action {
                let policy_ok = check_anonymous_access(storage, bucket, key, action).await;
                let acl_ok = check_acl_anonymous(storage, bucket, key, has_key, method).await;
                policy_ok || acl_ok
            } else {
                false
            };

            if !allowed {
                Some(handlers::error_response(auth_err.clone(), path))
            } else {
                None
            }
        }
    }
}

/// Check if the bucket policy allows access for a specific user ARN.
async fn check_user_access(
    storage: &Storage,
    bucket: &str,
    key: &str,
    action: S3Action,
    user_arn: &str,
) -> bool {
    let policy_data = match storage.get_bucket_policy(bucket).await {
        Ok(data) => data,
        Err(_) => return false,
    };

    let policy: crate::policy::BucketPolicy = match serde_json::from_slice(&policy_data) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let resource = if key.is_empty() {
        format!("arn:loch:s3:::{}", bucket)
    } else {
        format!("arn:loch:s3:::{}/{}", bucket, key)
    };

    policy.is_allowed_for_user(user_arn, action, &resource)
}

/// Try to route a multipart upload operation.
/// Returns Ok(response) if matched, or Err(req) to return the unconsumed request.
async fn route_multipart(
    method: &Method,
    config: &Arc<ServerConfig>,
    bucket: &str,
    key: &str,
    has_key: bool,
    is_uploads_request: bool,
    has_upload_id: Option<&String>,
    has_part_number: Option<&String>,
    req: Request<Incoming>,
    origin: Option<&str>,
    owner: Option<&str>,
) -> Result<Response<BoxBody>, Request<Incoming>> {
    let storage = &config.storage;

    // POST /{bucket}/{key}?uploads -- Initiate multipart upload
    if *method == Method::POST && has_key && is_uploads_request {
        let response =
            handlers::multipart::create_multipart_upload(config.clone(), bucket, key, req).await;
        return Ok(maybe_add_cors_headers(response, storage, bucket, method, origin).await);
    }

    // PUT /{bucket}/{key}?partNumber=N&uploadId=X -- Upload part
    if *method == Method::PUT && has_key {
        if let (Some(upload_id), Some(part_str)) = (has_upload_id, has_part_number) {
            let part_number: u32 = match part_str.parse() {
                Ok(n) if (1..=10000).contains(&n) => n,
                _ => return Ok(empty_response(StatusCode::BAD_REQUEST)),
            };
            let response = handlers::multipart::upload_part(
                config.clone(),
                bucket,
                key,
                upload_id,
                part_number,
                req,
            )
            .await;
            return Ok(maybe_add_cors_headers(response, storage, bucket, method, origin).await);
        }
    }

    // POST /{bucket}/{key}?uploadId=X -- Complete multipart upload
    if *method == Method::POST && has_key {
        if let Some(upload_id) = has_upload_id {
            let response = handlers::multipart::complete_multipart_upload(
                config.clone(),
                bucket,
                key,
                upload_id,
                req,
                owner,
            )
            .await;
            return Ok(maybe_add_cors_headers(response, storage, bucket, method, origin).await);
        }
    }

    // DELETE /{bucket}/{key}?uploadId=X -- Abort multipart upload
    if *method == Method::DELETE && has_key {
        if let Some(upload_id) = has_upload_id {
            let response = handlers::multipart::abort_multipart_upload(
                storage.clone(),
                bucket,
                key,
                upload_id,
            )
            .await;
            return Ok(maybe_add_cors_headers(response, storage, bucket, method, origin).await);
        }
    }

    // GET /{bucket}/{key}?uploadId=X -- List parts
    if *method == Method::GET && has_key {
        if let Some(upload_id) = has_upload_id {
            let response =
                handlers::multipart::list_parts(storage.clone(), bucket, key, upload_id).await;
            return Ok(maybe_add_cors_headers(response, storage, bucket, method, origin).await);
        }
    }

    // GET /{bucket}?uploads -- List multipart uploads
    if *method == Method::GET && !has_key && is_uploads_request {
        let response = handlers::multipart::list_multipart_uploads(storage.clone(), bucket).await;
        return Ok(maybe_add_cors_headers(response, storage, bucket, method, origin).await);
    }

    Err(req)
}

/// Determine the S3 action for the current request.
fn determine_action(method: &Method, has_key: bool) -> Option<S3Action> {
    match (method, has_key) {
        (&Method::GET, true) | (&Method::HEAD, true) => Some(S3Action::GetObject),
        (&Method::PUT, true) | (&Method::POST, true) => Some(S3Action::PutObject),
        (&Method::DELETE, true) => Some(S3Action::DeleteObject),
        (&Method::GET, false) => Some(S3Action::ListBucket),
        (&Method::HEAD, false) => Some(S3Action::GetBucketLocation),
        _ => None,
    }
}

/// Check if the bucket policy allows anonymous access for the given action.
async fn check_anonymous_access(
    storage: &Storage,
    bucket: &str,
    key: &str,
    action: S3Action,
) -> bool {
    let policy_data = match storage.get_bucket_policy(bucket).await {
        Ok(data) => data,
        Err(_) => return false,
    };

    let policy: crate::policy::BucketPolicy = match serde_json::from_slice(&policy_data) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Build the ARN-style resource string
    let resource = if key.is_empty() {
        format!("arn:loch:s3:::{}", bucket)
    } else {
        format!("arn:loch:s3:::{}/{}", bucket, key)
    };

    policy.is_allowed_for_anonymous(action, &resource)
}

const ALL_USERS_URI: &str = "http://acs.amazonaws.com/groups/global/AllUsers";

/// Check if stored ACLs allow anonymous access for the request.
/// Checks object-level ACL first (if key is set), then falls back to bucket-level ACL.
async fn check_acl_anonymous(
    storage: &Storage,
    bucket: &str,
    key: &str,
    has_key: bool,
    method: &Method,
) -> bool {
    let needed = match *method {
        Method::GET | Method::HEAD => "READ",
        Method::PUT | Method::POST => "WRITE",
        Method::DELETE => "WRITE",
        _ => return false,
    };

    // Check object-level ACL
    if has_key {
        if let Ok(Some(data)) = storage.get_object_acl(bucket, key).await {
            if acl_grants_to_all_users(&data, needed) {
                return true;
            }
        }
    }

    // Check bucket-level ACL
    if let Ok(Some(data)) = storage.get_bucket_acl(bucket).await {
        if acl_grants_to_all_users(&data, needed) {
            return true;
        }
    }

    false
}

/// Parse ACL XML and check if AllUsers group has the required permission.
fn acl_grants_to_all_users(acl_xml: &[u8], needed: &str) -> bool {
    let xml = String::from_utf8_lossy(acl_xml);
    // Parse grants looking for AllUsers group with matching permission
    // We use a simple state-machine approach over XML events
    let mut reader = quick_xml::Reader::from_str(&xml);
    let mut buf = Vec::new();
    let mut in_grant = false;
    let mut in_grantee = false;
    let mut is_all_users = false;
    let mut current_permission = String::new();
    let mut in_uri = false;
    let mut in_permission = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e)) => {
                let name = e.name();
                let local = local_name(name.as_ref());
                match local {
                    b"Grant" => {
                        in_grant = true;
                        is_all_users = false;
                        current_permission.clear();
                    }
                    b"Grantee" if in_grant => in_grantee = true,
                    b"URI" if in_grantee => in_uri = true,
                    b"Permission" if in_grant => in_permission = true,
                    _ => {}
                }
            }
            Ok(quick_xml::events::Event::End(ref e)) => {
                let name = e.name();
                let local = local_name(name.as_ref());
                match local {
                    b"Grant" => {
                        if is_all_users
                            && (current_permission == needed
                                || current_permission == "FULL_CONTROL")
                        {
                            return true;
                        }
                        in_grant = false;
                    }
                    b"Grantee" => in_grantee = false,
                    b"URI" => in_uri = false,
                    b"Permission" => in_permission = false,
                    _ => {}
                }
            }
            Ok(quick_xml::events::Event::Text(ref e)) => {
                if let Ok(text) = e.decode() {
                    let text = text.trim();
                    if in_uri && text == ALL_USERS_URI {
                        is_all_users = true;
                    } else if in_permission {
                        current_permission = text.to_string();
                    }
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    false
}

/// Extract the local name from a possibly namespaced XML tag.
fn local_name(name: &[u8]) -> &[u8] {
    match name.iter().position(|&b| b == b':') {
        Some(pos) => &name[pos + 1..],
        None => name,
    }
}

/// Handle an OPTIONS preflight request by checking the bucket CORS config.
async fn handle_preflight(
    storage: &Storage,
    bucket: &str,
    req: &Request<Incoming>,
) -> Response<BoxBody> {
    let origin = match req.headers().get("origin").and_then(|v| v.to_str().ok()) {
        Some(o) => o,
        None => return empty_response(StatusCode::FORBIDDEN),
    };

    let request_method = req
        .headers()
        .get("access-control-request-method")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let cors_data = match storage.get_bucket_cors(bucket).await {
        Ok(data) => data,
        Err(_) => return empty_response(StatusCode::FORBIDDEN),
    };

    let config: CorsConfiguration = match serde_json::from_slice(&cors_data) {
        Ok(c) => c,
        Err(_) => return empty_response(StatusCode::FORBIDDEN),
    };

    match config.find_matching_rule(origin, request_method) {
        Some(rule) => {
            let mut builder = Response::builder()
                .status(StatusCode::OK)
                .header("Access-Control-Allow-Origin", origin)
                .header(
                    "Access-Control-Allow-Methods",
                    rule.allowed_methods.join(", "),
                )
                .header("Vary", "Origin");

            if !rule.allowed_headers.is_empty() {
                builder = builder.header(
                    "Access-Control-Allow-Headers",
                    rule.allowed_headers.join(", "),
                );
            }

            if let Some(max_age) = rule.max_age_seconds {
                builder = builder.header("Access-Control-Max-Age", max_age.to_string());
            }

            builder.body(full_body(bytes::Bytes::new())).unwrap()
        }
        None => empty_response(StatusCode::FORBIDDEN),
    }
}

/// Add CORS headers to a response if the bucket has CORS configured and the Origin matches.
async fn maybe_add_cors_headers(
    response: Response<BoxBody>,
    storage: &Storage,
    bucket: &str,
    method: &Method,
    origin: Option<&str>,
) -> Response<BoxBody> {
    let origin = match origin {
        Some(o) if !bucket.is_empty() => o,
        _ => return response,
    };

    let cors_data = match storage.get_bucket_cors(bucket).await {
        Ok(data) => data,
        Err(_) => return response,
    };

    let config: CorsConfiguration = match serde_json::from_slice(&cors_data) {
        Ok(c) => c,
        Err(_) => return response,
    };

    // Match origin + method against CORS rules
    match config.find_matching_rule(origin, method.as_str()) {
        Some(rule) => add_cors_to_response(response, origin, &rule.expose_headers),
        None => {
            // Try matching just origin (for rules with broad method allowance)
            match config.find_rule_for_origin(origin) {
                Some(rule) => add_cors_to_response(response, origin, &rule.expose_headers),
                None => response,
            }
        }
    }
}

/// Insert CORS headers into a response, skipping invalid header values instead of panicking.
fn add_cors_to_response(
    response: Response<BoxBody>,
    origin: &str,
    expose_headers: &[String],
) -> Response<BoxBody> {
    let origin_value = match HeaderValue::from_str(origin) {
        Ok(v) => v,
        Err(_) => return response,
    };
    let (mut parts, body) = response.into_parts();
    parts
        .headers
        .insert("access-control-allow-origin", origin_value);
    parts
        .headers
        .insert("vary", HeaderValue::from_static("Origin"));
    if !expose_headers.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&expose_headers.join(", ")) {
            parts.headers.insert("access-control-expose-headers", v);
        }
    }
    Response::from_parts(parts, body)
}

/// Resolve the ACL XML for a PUT ?acl request.
/// Uses the canned ACL header if present, otherwise reads the XML body.
async fn resolve_acl_put(
    canned_acl: Option<String>,
    req: Request<Incoming>,
    resource: &str,
) -> Result<String, Response<BoxBody>> {
    if let Some(canned) = canned_acl {
        Ok(canned_acl_xml(&canned))
    } else {
        match read_body_limited(req.into_body(), 64 * 1024).await {
            Ok(body) if !body.is_empty() => Ok(String::from_utf8_lossy(&body).to_string()),
            Ok(_) => Ok(default_acl_xml()),
            Err(e) => Err(handlers::error_response(e, resource)),
        }
    }
}

/// Generate ACL XML from a canned ACL name.
fn canned_acl_xml(canned: &str) -> String {
    let owner_grant = "\
        <Grant>\
        <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
        <ID>owner</ID><DisplayName>owner</DisplayName></Grantee>\
        <Permission>FULL_CONTROL</Permission>\
        </Grant>";

    let all_users_read = "\
        <Grant>\
        <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
        <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee>\
        <Permission>READ</Permission>\
        </Grant>";

    let all_users_write = "\
        <Grant>\
        <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
        <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee>\
        <Permission>WRITE</Permission>\
        </Grant>";

    let grants = match canned {
        "public-read" => format!("{}{}", owner_grant, all_users_read),
        "public-read-write" => format!("{}{}{}", owner_grant, all_users_read, all_users_write),
        // "private" and anything else: owner only
        _ => owner_grant.to_string(),
    };

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
        <AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
        <Owner><ID>owner</ID><DisplayName>owner</DisplayName></Owner>\
        <AccessControlList>{}</AccessControlList>\
        </AccessControlPolicy>",
        grants
    )
}

/// Default ACL XML: owner with FULL_CONTROL.
fn default_acl_xml() -> String {
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
    <AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
    <Owner><ID>owner</ID><DisplayName>owner</DisplayName></Owner>\
    <AccessControlList>\
    <Grant>\
    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
    <ID>owner</ID><DisplayName>owner</DisplayName></Grantee>\
    <Permission>FULL_CONTROL</Permission>\
    </Grant>\
    </AccessControlList>\
    </AccessControlPolicy>"
        .to_string()
}

/// Percent-decode a URL path segment (RFC 3986).
/// Only decodes %XX sequences; does NOT treat '+' as space (that is query-string only).
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_val(bytes[i + 1]);
            let lo = hex_val(bytes[i + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                result.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(result).unwrap_or_else(|_| input.to_string())
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
