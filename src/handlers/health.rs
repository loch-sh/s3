use std::sync::Arc;

use hyper::body::Incoming;
use hyper::{Method, Request, StatusCode};
use serde::Serialize;

use super::{BoxBody, empty_response, error_response, json_response};
use crate::ServerConfig;
use crate::auth;
use crate::error::S3Error;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    /// "ok" or "exceeded" when a quota is configured; absent when unlimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    quota: Option<&'static str>,
}

#[derive(Serialize)]
struct UsageResponse {
    /// Bytes stored in the data directory (objects, versions, pending parts, metadata).
    used_bytes: u64,
    /// Bytes reserved by uploads in progress.
    reserved_bytes: u64,
    /// Configured quota in bytes, `null` when unlimited.
    limit_bytes: Option<u64>,
}

/// GET/HEAD /_loch/health — unauthenticated liveness probe.
/// Returns 200 `{"status":"ok"}` when the data directory is reachable, 503
/// `{"status":"error"}` otherwise. When a quota is configured, `quota` is
/// "ok" or "exceeded" (no figures). Reveals no secret, bucket or user name.
pub async fn health(method: &Method, config: &ServerConfig) -> hyper::Response<BoxBody> {
    if method != Method::GET && method != Method::HEAD {
        return empty_response(StatusCode::METHOD_NOT_ALLOWED);
    }

    let data_dir_ok = crate::storage::is_real_dir(&config.storage.data_dir).await;
    let quota_cfg = &config.storage.quota;
    let quota = quota_cfg.limit().map(|_| {
        if quota_cfg.is_exceeded() {
            "exceeded"
        } else {
            "ok"
        }
    });
    let body = HealthResponse {
        status: if data_dir_ok { "ok" } else { "error" },
        quota,
    };
    let status = if data_dir_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    if method == Method::HEAD {
        return empty_response(status);
    }
    json_response(status, serde_json::to_string(&body).expect("serializable"))
}

/// GET /_loch/usage — storage usage and quota, root only (SigV4-signed request).
/// Open access when no user store is configured, like the rest of the S3 API.
pub async fn usage(
    req: &Request<Incoming>,
    config: &Arc<ServerConfig>,
) -> hyper::Response<BoxBody> {
    let path = req.uri().path().to_string();
    if req.method() != Method::GET {
        return empty_response(StatusCode::METHOD_NOT_ALLOWED);
    }
    match auth::verify_request(req, &config.user_store).await {
        Ok(None) => {} // no user store: open access
        Ok(Some(user)) if user.is_root => {}
        Ok(Some(_)) => return error_response(S3Error::AccessDenied, &path),
        Err(e) => return error_response(e, &path),
    }
    let usage = config.storage.quota.usage();
    let body = UsageResponse {
        used_bytes: usage.used_bytes,
        reserved_bytes: usage.reserved_bytes,
        limit_bytes: usage.limit_bytes,
    };
    json_response(
        StatusCode::OK,
        serde_json::to_string(&body).expect("serializable"),
    )
}
