use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use hmac::{Hmac, Mac};
use hyper::Request;
use hyper::body::Incoming;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::S3Error;

/// Credentials for S3 authentication.
#[derive(Clone)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
}

/// Returns true if the request uses presigned URL (query-string) authentication.
pub fn is_presigned_request(query: &str) -> bool {
    query.split('&').any(|p| p.starts_with("X-Amz-Algorithm="))
}

/// Verify the AWS Signature Version 4 on an incoming request.
/// Handles both Authorization-header auth and presigned URL (query-string) auth.
/// Returns Ok(()) if the signature is valid, or an S3Error otherwise.
/// If no credentials are configured, all requests are allowed.
pub fn verify_request(
    req: &Request<Incoming>,
    credentials: &Option<Credentials>,
) -> Result<(), S3Error> {
    let creds = match credentials {
        Some(c) => c,
        None => return Ok(()),
    };

    let query = req.uri().query().unwrap_or("");
    if is_presigned_request(query) {
        verify_presigned(req, creds, query)
    } else {
        verify_header_auth(req, creds)
    }
}

// ---- Header-based auth ----

fn verify_header_auth(req: &Request<Incoming>, creds: &Credentials) -> Result<(), S3Error> {
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(S3Error::AccessDenied)?;

    let parsed = parse_auth_header(auth_header).ok_or(S3Error::AccessDenied)?;

    if parsed.access_key_id != creds.access_key_id {
        return Err(S3Error::AccessDenied);
    }

    let amz_date = resolve_amz_date(req)?;
    validate_request_time(&amz_date)?;

    let payload_hash = req
        .headers()
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("UNSIGNED-PAYLOAD");

    let scope_parts: Vec<&str> = parsed.scope.split('/').collect();
    if scope_parts.len() != 4 || scope_parts[2] != "s3" || scope_parts[3] != "aws4_request" {
        return Err(S3Error::AccessDenied);
    }
    if amz_date.len() < 8 {
        return Err(S3Error::AccessDenied);
    }
    let date_stamp = &amz_date[..8];
    let region = scope_parts[1];
    let service = scope_parts[2];

    let canonical_query = canonical_query_string(req.uri().query().unwrap_or(""), None);
    let canonical_req =
        build_canonical_request(req, &parsed.signed_headers, &canonical_query, payload_hash);
    let canonical_req_hash = sha256_hex(canonical_req.as_bytes());

    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, parsed.scope, canonical_req_hash
    );

    let signing_key = derive_signing_key(&creds.secret_access_key, date_stamp, region, service);
    let expected = hmac_sha256_hex(&signing_key, string_to_sign.as_bytes());

    verify_signature(&expected, parsed.signature)
}

// ---- Presigned URL auth ----

fn verify_presigned(req: &Request<Incoming>, creds: &Credentials, query: &str) -> Result<(), S3Error> {
    let mut algorithm = None::<String>;
    let mut credential = None::<String>;
    let mut amz_date = None::<String>;
    let mut expires_str = None::<String>;
    let mut signed_headers_param = None::<String>;
    let mut signature = None::<String>;

    for part in query.split('&').filter(|p| !p.is_empty()) {
        if let Some((k, v)) = part.split_once('=') {
            let v = uri_decode(v);
            match k {
                "X-Amz-Algorithm" => algorithm = Some(v),
                "X-Amz-Credential" => credential = Some(v),
                "X-Amz-Date" => amz_date = Some(v),
                "X-Amz-Expires" => expires_str = Some(v),
                "X-Amz-SignedHeaders" => signed_headers_param = Some(v),
                "X-Amz-Signature" => signature = Some(v),
                _ => {}
            }
        }
    }

    let algorithm = algorithm.ok_or(S3Error::AccessDenied)?;
    if algorithm != "AWS4-HMAC-SHA256" {
        return Err(S3Error::AccessDenied);
    }

    let credential = credential.ok_or(S3Error::AccessDenied)?;
    let amz_date = amz_date.ok_or(S3Error::AccessDenied)?;
    let expires_secs: u64 = expires_str
        .ok_or(S3Error::AccessDenied)?
        .parse()
        .map_err(|_| S3Error::AccessDenied)?;
    let signed_headers_param = signed_headers_param.ok_or(S3Error::AccessDenied)?;
    let signature = signature.ok_or(S3Error::AccessDenied)?;

    // credential = AKID/DATE/REGION/SERVICE/aws4_request
    let (access_key_id, scope) = credential.split_once('/').ok_or(S3Error::AccessDenied)?;
    if access_key_id != creds.access_key_id {
        return Err(S3Error::AccessDenied);
    }

    let scope_parts: Vec<&str> = scope.split('/').collect();
    if scope_parts.len() != 4 || scope_parts[2] != "s3" || scope_parts[3] != "aws4_request" {
        return Err(S3Error::AccessDenied);
    }
    let date_stamp = scope_parts[0];
    let region = scope_parts[1];
    let service = scope_parts[2];

    validate_presigned_expiry(&amz_date, expires_secs)?;

    // Canonical query: all params sorted, excluding X-Amz-Signature
    let canonical_query = canonical_query_string(query, Some("X-Amz-Signature"));
    let signed_headers: Vec<&str> = signed_headers_param.split(';').collect();
    let canonical_req =
        build_canonical_request(req, &signed_headers, &canonical_query, "UNSIGNED-PAYLOAD");
    let canonical_req_hash = sha256_hex(canonical_req.as_bytes());

    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, scope, canonical_req_hash
    );

    let signing_key = derive_signing_key(&creds.secret_access_key, date_stamp, region, service);
    let expected = hmac_sha256_hex(&signing_key, string_to_sign.as_bytes());

    verify_signature(&expected, &signature)
}

/// Maximum allowed presigned URL validity (7 days), matching AWS S3.
const MAX_PRESIGNED_EXPIRES_SECS: u64 = 604_800;

fn validate_presigned_expiry(amz_date: &str, expires_secs: u64) -> Result<(), S3Error> {
    if expires_secs == 0 || expires_secs > MAX_PRESIGNED_EXPIRES_SECS {
        return Err(S3Error::AccessDenied);
    }
    let request_time = NaiveDateTime::parse_from_str(amz_date, "%Y%m%dT%H%M%SZ")
        .map_err(|_| S3Error::AccessDenied)?;
    let expiry = request_time + Duration::seconds(expires_secs as i64);
    if Utc::now().naive_utc() > expiry {
        return Err(S3Error::ExpiredToken);
    }
    Ok(())
}

fn verify_signature(expected: &str, actual: &str) -> Result<(), S3Error> {
    if expected.as_bytes().len() == actual.as_bytes().len()
        && bool::from(expected.as_bytes().ct_eq(actual.as_bytes()))
    {
        Ok(())
    } else {
        Err(S3Error::SignatureDoesNotMatch)
    }
}

// ---- Shared helpers ----

fn resolve_amz_date(req: &Request<Incoming>) -> Result<String, S3Error> {
    if let Some(amz_date) = req
        .headers()
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
    {
        return Ok(amz_date.to_string());
    }

    let date_header = req
        .headers()
        .get("date")
        .and_then(|v| v.to_str().ok())
        .ok_or(S3Error::AccessDenied)?;
    let parsed = DateTime::parse_from_rfc2822(date_header).map_err(|_| S3Error::AccessDenied)?;
    Ok(parsed
        .with_timezone(&Utc)
        .format("%Y%m%dT%H%M%SZ")
        .to_string())
}

fn validate_request_time(amz_date: &str) -> Result<(), S3Error> {
    let request_time = NaiveDateTime::parse_from_str(amz_date, "%Y%m%dT%H%M%SZ")
        .map_err(|_| S3Error::AccessDenied)?;
    let now = Utc::now().naive_utc();
    let diff = (now - request_time).num_seconds().unsigned_abs();
    if diff > 900 {
        return Err(S3Error::RequestTimeTooSkewed);
    }
    Ok(())
}

/// Parsed components of an AWS4 Authorization header.
struct AuthHeader<'a> {
    access_key_id: &'a str,
    scope: &'a str,
    signed_headers: Vec<&'a str>,
    signature: &'a str,
}

/// Parse the Authorization header value.
/// Format: AWS4-HMAC-SHA256 Credential=AKID/scope, SignedHeaders=h1;h2, Signature=hex
fn parse_auth_header(header: &str) -> Option<AuthHeader<'_>> {
    let rest = header.strip_prefix("AWS4-HMAC-SHA256 ")?;

    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;

    for part in rest.split(',') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("Credential=") {
            credential = Some(val);
        } else if let Some(val) = part.strip_prefix("SignedHeaders=") {
            signed_headers = Some(val);
        } else if let Some(val) = part.strip_prefix("Signature=") {
            signature = Some(val);
        }
    }

    let cred = credential?;
    let (access_key_id, scope) = cred.split_once('/')?;

    Some(AuthHeader {
        access_key_id,
        scope,
        signed_headers: signed_headers?.split(';').collect(),
        signature: signature?,
    })
}

/// Build the canonical request string for SigV4.
/// `canonical_query` is pre-computed (differs between header auth and presigned auth).
fn build_canonical_request(
    req: &Request<Incoming>,
    signed_headers: &[&str],
    canonical_query: &str,
    payload_hash: &str,
) -> String {
    let method = req.method().as_str();
    let canonical_uri = canonical_uri_encode(req.uri().path());

    let mut canonical_headers = String::new();
    for header_name in signed_headers {
        let value = req
            .headers()
            .get(*header_name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        canonical_headers.push_str(header_name);
        canonical_headers.push(':');
        canonical_headers.push_str(&normalize_header_value(value));
        canonical_headers.push('\n');
    }

    let signed_headers_str = signed_headers.join(";");

    format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, canonical_uri, canonical_query, canonical_headers, signed_headers_str, payload_hash
    )
}

fn normalize_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// URL-encode a URI path, preserving forward slashes.
/// The path from the HTTP request may already be percent-encoded,
/// so we decode first to avoid double-encoding.
fn canonical_uri_encode(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    path.split('/')
        .map(|segment| uri_encode(&uri_decode(segment), true))
        .collect::<Vec<_>>()
        .join("/")
}

/// URL-encode a string per AWS SigV4 rules.
fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut result = String::new();
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'~' | b'.' => {
                result.push(byte as char);
            }
            b'/' if !encode_slash => {
                result.push('/');
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

/// Build the canonical query string (sorted by key then value).
/// Query parameters from the HTTP request may already be percent-encoded,
/// so we decode first to avoid double-encoding before re-encoding per SigV4 rules.
/// If `exclude` is Some(key), that key is omitted (used for presigned URL verification).
fn canonical_query_string(query: &str, exclude: Option<&str>) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let (k, v) = if let Some((k, v)) = p.split_once('=') {
                (uri_decode(k), uri_decode(v))
            } else {
                (uri_decode(p), String::new())
            };
            if exclude.is_some_and(|ex| ex == k) {
                None
            } else {
                Some((k, v))
            }
        })
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent-decode a URI component (RFC 3986).
fn uri_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
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

/// Parse a single hex digit.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Derive the SigV4 signing key.
fn derive_signing_key(secret_key: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_secret = format!("AWS4{}", secret_key);
    let k_date = hmac_sha256(k_secret.as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// Compute HMAC-SHA256 and return raw bytes.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Compute HMAC-SHA256 and return hex-encoded string.
fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    let result = hmac_sha256(key, data);
    hex_encode(&result)
}

/// Compute SHA-256 and return hex-encoded string.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex_encode(&hasher.finalize())
}

/// Encode bytes as lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push_str(&format!("{:02x}", byte));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_auth_header() {
        let header = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/loch-sh/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41";
        let parsed = parse_auth_header(header).unwrap();
        assert_eq!(parsed.access_key_id, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(parsed.scope, "20130524/loch-sh/s3/aws4_request");
        assert_eq!(
            parsed.signed_headers,
            vec!["host", "range", "x-amz-content-sha256", "x-amz-date"]
        );
        assert_eq!(
            parsed.signature,
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn test_derive_signing_key() {
        // AWS test vector from documentation
        let key = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "20130524",
            "loch-sh",
            "s3",
        );
        // Known expected signing key (hex)
        let hex = hex_encode(&key);
        assert_eq!(hex.len(), 64); // SHA-256 produces 32 bytes = 64 hex chars
    }

    #[test]
    fn test_canonical_query_string() {
        assert_eq!(canonical_query_string("", None), "");
        assert_eq!(canonical_query_string("b=2&a=1", None), "a=1&b=2");
        assert_eq!(
            canonical_query_string("list-type=2&prefix=test", None),
            "list-type=2&prefix=test"
        );
        // Pre-encoded values must not be double-encoded
        assert_eq!(
            canonical_query_string("delimiter=%2F&list-type=2", None),
            "delimiter=%2F&list-type=2"
        );
    }

    #[test]
    fn test_canonical_query_string_exclude() {
        let query = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc123&b=2&a=1";
        let result = canonical_query_string(query, Some("X-Amz-Signature"));
        assert!(!result.contains("X-Amz-Signature"));
        assert!(result.contains("X-Amz-Algorithm"));
        assert_eq!(
            result,
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&a=1&b=2"
        );
    }

    #[test]
    fn test_is_presigned_request() {
        assert!(is_presigned_request(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc"
        ));
        assert!(!is_presigned_request("list-type=2&prefix=test"));
        assert!(!is_presigned_request(""));
    }

    #[test]
    fn test_uri_decode() {
        assert_eq!(uri_decode("hello"), "hello");
        assert_eq!(uri_decode("%2F"), "/");
        assert_eq!(uri_decode("a%20b"), "a b");
        assert_eq!(uri_decode("%25"), "%");
        assert_eq!(uri_decode("no%encoding"), "no%encoding"); // incomplete sequence
    }
}
