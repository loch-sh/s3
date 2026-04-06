use std::sync::Arc;

use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::{BoxBody, empty_response, error_response, json_response, read_body_limited};
use crate::ServerConfig;
use crate::error::S3Error;
use crate::users::UserRecord;

/// Public user info returned by the API (secret_access_key is never exposed).
#[derive(Serialize)]
struct UserResponse {
    user_id: String,
    display_name: String,
    access_key_id: String,
    is_root: bool,
}

#[derive(Serialize)]
struct UsersListResponse {
    users: Vec<UserResponse>,
}

/// Request body for creating/updating a user.
/// Note: is_root is not accepted via the API — it can only be set in the users file directly.
#[derive(Deserialize)]
struct UserPutRequest {
    display_name: String,
    access_key_id: String,
    secret_access_key: String,
}

impl From<&UserRecord> for UserResponse {
    fn from(r: &UserRecord) -> Self {
        Self {
            user_id: r.user_id.clone(),
            display_name: r.display_name.clone(),
            access_key_id: r.access_key_id.clone(),
            is_root: r.is_root,
        }
    }
}

/// Route a request to /_loch/users/... to the appropriate handler.
pub async fn route_users_api(
    req: Request<Incoming>,
    config: &Arc<ServerConfig>,
    path: &str,
) -> Response<BoxBody> {
    // Check that admin API key is configured
    let api_key = match &config.admin_api_key {
        Some(key) => key,
        None => {
            return error_response(S3Error::AccessDenied, path);
        }
    };

    // Check that user store has a file (not env-var mode)
    let user_store = match &config.user_store {
        Some(store) => {
            let s = store.read().await;
            if !s.has_file() {
                return error_response(S3Error::MethodNotAllowed, path);
            }
            drop(s);
            store.clone()
        }
        None => {
            return error_response(S3Error::AccessDenied, path);
        }
    };

    // Verify Bearer token
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let token = auth_header.strip_prefix("Bearer ").unwrap_or("");
    // Constant-time comparison — the reference key is server-side only, length is not a secret
    if token.is_empty()
        || token.len() != api_key.len()
        || !bool::from(token.as_bytes().ct_eq(api_key.as_bytes()))
    {
        return error_response(S3Error::AccessDenied, path);
    }

    // Parse user_id from path: /_loch/users or /_loch/users/{user_id}
    let rest = path
        .strip_prefix("/_loch/users")
        .unwrap_or("")
        .trim_start_matches('/');
    let user_id = if rest.is_empty() { None } else { Some(rest) };

    // Validate user_id: alphanumeric, hyphens, underscores only, max 128 chars
    if let Some(uid) = user_id {
        if uid.is_empty()
            || uid.len() > 128
            || !uid
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return error_response(
                S3Error::InvalidArgument(
                    "user_id must be 1-128 alphanumeric, hyphen or underscore characters"
                        .to_string(),
                ),
                path,
            );
        }
    }

    let method = req.method().clone();

    match (&method, user_id) {
        // GET /_loch/users — List all users
        (&Method::GET, None) => {
            let store = user_store.read().await;
            let users: Vec<UserResponse> = store.list_users().iter().map(|u| (*u).into()).collect();
            let body = serde_json::to_string(&UsersListResponse { users }).unwrap();
            json_response(StatusCode::OK, body)
        }

        // GET /_loch/users/{user_id} — Get one user
        (&Method::GET, Some(uid)) => {
            let store = user_store.read().await;
            match store.get_user(uid) {
                Some(user) => {
                    let body = serde_json::to_string(&UserResponse::from(user)).unwrap();
                    json_response(StatusCode::OK, body)
                }
                None => error_response(
                    S3Error::InvalidArgument(format!("User '{}' not found", uid)),
                    path,
                ),
            }
        }

        // PUT /_loch/users/{user_id} — Create or update a user
        (&Method::PUT, Some(uid)) => {
            let body = match read_body_limited(req.into_body(), 64 * 1024).await {
                Ok(b) => b,
                Err(e) => return error_response(e, path),
            };

            let put_req: UserPutRequest = match serde_json::from_slice(&body) {
                Ok(r) => r,
                Err(e) => {
                    return error_response(
                        S3Error::InvalidArgument(format!("Invalid JSON: {}", e)),
                        path,
                    );
                }
            };

            let record = UserRecord {
                user_id: uid.to_string(),
                display_name: put_req.display_name,
                access_key_id: put_req.access_key_id,
                secret_access_key: put_req.secret_access_key,
                is_root: false,
            };

            let mut store = user_store.write().await;

            // Reject updates to the root user via the API
            if let Some(existing) = store.get_user(uid) {
                if existing.is_root {
                    return error_response(
                        S3Error::InvalidArgument("Root user cannot be modified via API".to_string()),
                        path,
                    );
                }
            }

            let is_update = store.get_user(uid).is_some();
            match store.add_user(record).await {
                Ok(()) => {
                    let status = if is_update {
                        StatusCode::OK
                    } else {
                        StatusCode::CREATED
                    };
                    empty_response(status)
                }
                Err(e) => error_response(e, path),
            }
        }

        // DELETE /_loch/users/{user_id} — Delete a user
        (&Method::DELETE, Some(uid)) => {
            let mut store = user_store.write().await;
            match store.delete_user(uid).await {
                Ok(()) => empty_response(StatusCode::NO_CONTENT),
                Err(e) => error_response(e, path),
            }
        }

        _ => empty_response(StatusCode::METHOD_NOT_ALLOWED),
    }
}
