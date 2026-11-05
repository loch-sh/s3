use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use s3::ServerConfig;
use s3::auth::Credentials;
use s3::encryption::EncryptionConfig;
use s3::storage::Storage;
use s3::users::UserStore;

const TEST_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const TEST_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

/// Start a test server without authentication on a random port.
async fn start_server() -> (String, std::path::PathBuf) {
    start_server_with_auth(None).await
}

/// Start a test server with optional authentication on a random port.
async fn start_server_with_auth(credentials: Option<Credentials>) -> (String, std::path::PathBuf) {
    let user_store =
        credentials.map(|c| Arc::new(RwLock::new(UserStore::from_single_credentials(c))));
    start_server_full(user_store, None, None).await
}

/// Start a test server with optional auth and optional encryption on a random port.
async fn start_server_full(
    user_store: Option<Arc<RwLock<UserStore>>>,
    admin_api_key: Option<String>,
    encryption: Option<EncryptionConfig>,
) -> (String, std::path::PathBuf) {
    let tmp_dir = std::env::temp_dir().join(format!("s3-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp_dir).unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let config = Arc::new(ServerConfig {
        storage: Arc::new(Storage::new(tmp_dir.clone())),
        user_store,
        admin_api_key,
        upload_ttl_secs: 86400,
        encryption,
    });

    tokio::spawn(async move {
        s3::serve(listener, config).await;
    });

    // Give the server a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    (format!("http://127.0.0.1:{}", port), tmp_dir)
}

/// Start a test server with SSE-S3 encryption enabled.
async fn start_server_with_encryption() -> (String, std::path::PathBuf, [u8; 32]) {
    let master_key = [0x42u8; 32]; // deterministic test key
    let (url, tmp) = start_server_full(
        None,
        None,
        Some(EncryptionConfig {
            master_key,
            encrypt_by_default: false,
        }),
    )
    .await;
    (url, tmp, master_key)
}

/// Generate a random 32-byte customer key and its base64-encoded MD5.
fn generate_customer_key() -> ([u8; 32], String, String) {
    let key = [0xABu8; 32]; // deterministic test key
    let key_b64 = BASE64.encode(key);
    let key_md5 = BASE64.encode(md5::compute(&key).as_ref());
    (key, key_b64, key_md5)
}

/// Generate a second, different customer key.
fn generate_customer_key_2() -> ([u8; 32], String, String) {
    let key = [0xCDu8; 32];
    let key_b64 = BASE64.encode(key);
    let key_md5 = BASE64.encode(md5::compute(&key).as_ref());
    (key, key_b64, key_md5)
}

/// Clean up test data directory.
fn cleanup(tmp_dir: &std::path::Path) {
    let _ = std::fs::remove_dir_all(tmp_dir);
}

const ADMIN_API_KEY: &str = "test-admin-api-key-12345";
const ALICE_ACCESS_KEY: &str = "AKIAALICEEXAMPLE";
const ALICE_SECRET_KEY: &str = "AliceSecretKeyExample1234567890AB";
const BOB_ACCESS_KEY: &str = "AKIABOBEXAMPLE00";
const BOB_SECRET_KEY: &str = "BobSecretKeyExample12345678901234";

/// Start a multi-user test server with root + alice + bob.
async fn start_multi_user_server() -> (String, std::path::PathBuf) {
    let tmp_dir = std::env::temp_dir().join(format!("s3-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp_dir).unwrap();

    // Write users file
    let users_file = tmp_dir.join(".users.json");
    let users_json = serde_json::json!({
        "users": [
            {
                "user_id": "root",
                "display_name": "Root Admin",
                "access_key_id": TEST_ACCESS_KEY,
                "secret_access_key": TEST_SECRET_KEY,
                "is_root": true
            },
            {
                "user_id": "alice",
                "display_name": "Alice",
                "access_key_id": ALICE_ACCESS_KEY,
                "secret_access_key": ALICE_SECRET_KEY
            },
            {
                "user_id": "bob",
                "display_name": "Bob",
                "access_key_id": BOB_ACCESS_KEY,
                "secret_access_key": BOB_SECRET_KEY
            }
        ]
    });
    std::fs::write(
        &users_file,
        serde_json::to_string_pretty(&users_json).unwrap(),
    )
    .unwrap();

    let store = UserStore::load_from_file(&users_file).unwrap();
    let user_store = Some(Arc::new(RwLock::new(store)));

    start_server_full(user_store, Some(ADMIN_API_KEY.to_string()), None).await
}

// ---- Helper: sign a request with AWS SigV4 ----

/// Sign an HTTP request using AWS Signature Version 4.
fn sign_request(
    builder: reqwest::RequestBuilder,
    method: &str,
    path: &str,
    query: &str,
    host: &str,
    body: &[u8],
    access_key: &str,
    secret_key: &str,
) -> reqwest::RequestBuilder {
    sign_request_with_headers(
        builder,
        method,
        path,
        query,
        host,
        body,
        &[],
        access_key,
        secret_key,
    )
}

/// Same as `sign_request`, also adding and signing `extra_headers`
/// (header names are lowercased for signing).
fn sign_request_with_headers(
    builder: reqwest::RequestBuilder,
    method: &str,
    path: &str,
    query: &str,
    host: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
    access_key: &str,
    secret_key: &str,
) -> reqwest::RequestBuilder {
    let now = chrono::Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();

    let region = "loch-sh";
    let service = "s3";
    let scope = format!("{}/{}/{}/aws4_request", date_stamp, region, service);

    // Hash the payload
    let payload_hash = sha256_hex(body);

    // Build canonical headers (sorted)
    let mut headers: Vec<(String, String)> = vec![
        ("host".to_string(), host.to_string()),
        ("x-amz-content-sha256".to_string(), payload_hash.clone()),
        ("x-amz-date".to_string(), amz_date.clone()),
    ];
    for (name, value) in extra_headers {
        headers.push((name.to_lowercase(), value.trim().to_string()));
    }
    headers.sort();
    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v))
        .collect();
    let signed_headers = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let mut builder = builder;
    for (name, value) in extra_headers {
        builder = builder.header(*name, *value);
    }

    // Build canonical query string (sorted)
    let canonical_query = if query.is_empty() {
        String::new()
    } else {
        let mut pairs: Vec<(&str, &str)> = query
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| p.split_once('=').unwrap_or((p, "")))
            .collect();
        pairs.sort();
        pairs
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&")
    };

    // Build canonical request
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, path, canonical_query, canonical_headers, signed_headers, payload_hash
    );
    let canonical_request_hash = sha256_hex(canonical_request.as_bytes());

    // Build string to sign
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, scope, canonical_request_hash
    );

    // Derive signing key
    let signing_key = derive_signing_key(secret_key, &date_stamp, region, service);

    // Calculate signature
    let signature = hmac_sha256_hex(&signing_key, string_to_sign.as_bytes());

    // Build Authorization header
    let auth_header = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        access_key, scope, signed_headers, signature
    );

    builder
        .header("Authorization", auth_header)
        .header("x-amz-date", amz_date)
        .header("x-amz-content-sha256", payload_hash)
}

fn derive_signing_key(secret_key: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_secret = format!("AWS4{}", secret_key);
    let k_date = hmac_sha256(k_secret.as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    hex_encode(&hmac_sha256(key, data))
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ======== Tests without authentication (backward compatible) ========

#[tokio::test]
async fn test_bucket_crud() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .put(format!("{}/test-bucket", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "CreateBucket should return 200");

    let resp = client
        .head(format!("{}/test-bucket", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "HeadBucket should return 200");

    let resp = client.get(&base_url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Name>test-bucket</Name>"));

    let resp = client
        .delete(format!("{}/test-bucket", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "DeleteBucket should return 204");

    let resp = client
        .head(format!("{}/test-bucket", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_bucket_already_exists() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/dup-bucket", base_url))
        .send()
        .await
        .unwrap();
    let resp = client
        .put(format!("{}/dup-bucket", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_delete_non_empty_bucket() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/full-bucket", base_url))
        .send()
        .await
        .unwrap();
    client
        .put(format!("{}/full-bucket/file.txt", base_url))
        .body("hello")
        .send()
        .await
        .unwrap();

    let resp = client
        .delete(format!("{}/full-bucket", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_object_crud() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/obj-bucket", base_url))
        .send()
        .await
        .unwrap();

    let content = b"Hello, S3!";
    let resp = client
        .put(format!("{}/obj-bucket/hello.txt", base_url))
        .body(&content[..])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("etag").is_some());

    let resp = client
        .get(format!("{}/obj-bucket/hello.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "text/plain"
    );
    assert_eq!(&resp.bytes().await.unwrap()[..], content);

    let resp = client
        .head(format!("{}/obj-bucket/hello.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-length")
            .unwrap()
            .to_str()
            .unwrap(),
        "10"
    );

    let resp = client
        .get(format!("{}/obj-bucket?list-type=2", base_url))
        .send()
        .await
        .unwrap();
    assert!(resp.text().await.unwrap().contains("<Key>hello.txt</Key>"));

    let resp = client
        .delete(format!("{}/obj-bucket/hello.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let resp = client
        .get(format!("{}/obj-bucket/hello.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_nested_object_keys() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/nested-bucket", base_url))
        .send()
        .await
        .unwrap();
    client
        .put(format!("{}/nested-bucket/a/b/c/deep.txt", base_url))
        .body("nested content")
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!("{}/nested-bucket/a/b/c/deep.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "nested content");

    let resp = client
        .get(format!(
            "{}/nested-bucket?list-type=2&prefix=a/b/",
            base_url
        ))
        .send()
        .await
        .unwrap();
    assert!(
        resp.text()
            .await
            .unwrap()
            .contains("<Key>a/b/c/deep.txt</Key>")
    );

    client
        .delete(format!("{}/nested-bucket/a/b/c/deep.txt", base_url))
        .send()
        .await
        .unwrap();
    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_copy_object() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/copy-bucket", base_url))
        .send()
        .await
        .unwrap();
    client
        .put(format!("{}/copy-bucket/original.txt", base_url))
        .body("copy me")
        .send()
        .await
        .unwrap();

    let resp = client
        .put(format!("{}/copy-bucket/copied.txt", base_url))
        .header("x-amz-copy-source", "/copy-bucket/original.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("<CopyObjectResult>"));

    assert_eq!(
        client
            .get(format!("{}/copy-bucket/original.txt", base_url))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "copy me"
    );
    assert_eq!(
        client
            .get(format!("{}/copy-bucket/copied.txt", base_url))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "copy me"
    );

    client
        .delete(format!("{}/copy-bucket/original.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        client
            .get(format!("{}/copy-bucket/copied.txt", base_url))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_get_nonexistent_object() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/err-bucket", base_url))
        .send()
        .await
        .unwrap();
    let resp = client
        .get(format!("{}/err-bucket/nope.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    assert!(
        resp.text()
            .await
            .unwrap()
            .contains("<Code>NoSuchKey</Code>")
    );

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_get_from_nonexistent_bucket() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/no-such-bucket/file.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    assert!(
        resp.text()
            .await
            .unwrap()
            .contains("<Code>NoSuchBucket</Code>")
    );

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_delete_nonexistent_object_returns_204() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/del-bucket", base_url))
        .send()
        .await
        .unwrap();
    let resp = client
        .delete(format!("{}/del-bucket/ghost.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_list_objects_with_delimiter() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/delim-bucket", base_url))
        .send()
        .await
        .unwrap();

    for key in &[
        "photos/2024/jan.jpg",
        "photos/2024/feb.jpg",
        "photos/2025/mar.jpg",
        "readme.txt",
    ] {
        client
            .put(format!("{}/delim-bucket/{}", base_url, key))
            .body("data")
            .send()
            .await
            .unwrap();
    }

    let resp = client
        .get(format!("{}/delim-bucket?list-type=2&delimiter=/", base_url))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Key>readme.txt</Key>"));
    assert!(body.contains("<Prefix>photos/</Prefix>"));

    let resp = client
        .get(format!(
            "{}/delim-bucket?list-type=2&prefix=photos/&delimiter=/",
            base_url
        ))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Prefix>photos/2024/</Prefix>"));
    assert!(body.contains("<Prefix>photos/2025/</Prefix>"));

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_concurrent_uploads() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/conc-bucket", base_url))
        .send()
        .await
        .unwrap();

    let mut handles = Vec::new();
    for i in 0..20 {
        let client = client.clone();
        let url = format!("{}/conc-bucket/file-{}.txt", base_url, i);
        let body = format!("content-{}", i);
        handles.push(tokio::spawn(async move {
            let resp = client.put(&url).body(body).send().await.unwrap();
            assert_eq!(resp.status(), 200);
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }

    let resp = client
        .get(format!("{}/conc-bucket?list-type=2", base_url))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    for i in 0..20 {
        assert!(body.contains(&format!("<Key>file-{}.txt</Key>", i)));
    }

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_concurrent_upload_and_delete() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/race-bucket", base_url))
        .send()
        .await
        .unwrap();
    for i in 0..10 {
        client
            .put(format!("{}/race-bucket/pre-{}.txt", base_url, i))
            .body("pre-existing")
            .send()
            .await
            .unwrap();
    }

    let mut handles = Vec::new();
    for i in 0..10 {
        let client = client.clone();
        let url = format!("{}/race-bucket/new-{}.txt", base_url, i);
        handles.push(tokio::spawn(async move {
            client.put(&url).body("new").send().await.unwrap();
        }));
    }
    for i in 0..10 {
        let client = client.clone();
        let url = format!("{}/race-bucket/pre-{}.txt", base_url, i);
        handles.push(tokio::spawn(async move {
            client.delete(&url).send().await.unwrap();
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }

    for i in 0..10 {
        assert_eq!(
            client
                .get(format!("{}/race-bucket/new-{}.txt", base_url, i))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(
            client
                .head(format!("{}/race-bucket/pre-{}.txt", base_url, i))
                .send()
                .await
                .unwrap()
                .status(),
            404
        );
    }

    cleanup(&tmp_dir);
}

// ======== Authentication tests ========

#[tokio::test]
async fn test_auth_rejects_unauthenticated_request() {
    let (base_url, tmp_dir) = start_server_with_auth(Some(Credentials {
        access_key_id: TEST_ACCESS_KEY.to_string(),
        secret_access_key: TEST_SECRET_KEY.to_string(),
    }))
    .await;
    let client = reqwest::Client::new();

    // Request without Authorization header should be rejected
    let resp = client.get(&base_url).send().await.unwrap();
    assert_eq!(
        resp.status(),
        403,
        "Unauthenticated request should return 403"
    );
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_auth_rejects_wrong_access_key() {
    let (base_url, tmp_dir) = start_server_with_auth(Some(Credentials {
        access_key_id: TEST_ACCESS_KEY.to_string(),
        secret_access_key: TEST_SECRET_KEY.to_string(),
    }))
    .await;
    let client = reqwest::Client::new();

    let host = base_url.strip_prefix("http://").unwrap();
    let req = sign_request(
        client.get(&base_url),
        "GET",
        "/",
        "",
        host,
        b"",
        "WRONGACCESSKEY",
        TEST_SECRET_KEY,
    );
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), 403, "Wrong access key should return 403");

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_auth_rejects_wrong_secret_key() {
    let (base_url, tmp_dir) = start_server_with_auth(Some(Credentials {
        access_key_id: TEST_ACCESS_KEY.to_string(),
        secret_access_key: TEST_SECRET_KEY.to_string(),
    }))
    .await;
    let client = reqwest::Client::new();

    let host = base_url.strip_prefix("http://").unwrap();
    let req = sign_request(
        client.get(&base_url),
        "GET",
        "/",
        "",
        host,
        b"",
        TEST_ACCESS_KEY,
        "wrongsecretkey1234567890123456789",
    );
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), 403, "Wrong secret key should return 403");
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"));

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_auth_accepts_valid_signature() {
    let (base_url, tmp_dir) = start_server_with_auth(Some(Credentials {
        access_key_id: TEST_ACCESS_KEY.to_string(),
        secret_access_key: TEST_SECRET_KEY.to_string(),
    }))
    .await;
    let client = reqwest::Client::new();

    let host = base_url.strip_prefix("http://").unwrap();

    // ListBuckets with valid signature
    let req = sign_request(
        client.get(&base_url),
        "GET",
        "/",
        "",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), 200, "Valid signature should be accepted");
    assert!(
        resp.text()
            .await
            .unwrap()
            .contains("<ListAllMyBucketsResult")
    );

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_auth_full_crud_with_signatures() {
    let (base_url, tmp_dir) = start_server_with_auth(Some(Credentials {
        access_key_id: TEST_ACCESS_KEY.to_string(),
        secret_access_key: TEST_SECRET_KEY.to_string(),
    }))
    .await;
    let client = reqwest::Client::new();
    let host = base_url.strip_prefix("http://").unwrap();

    // Create bucket
    let req = sign_request(
        client.put(format!("{}/auth-bucket", base_url)),
        "PUT",
        "/auth-bucket",
        "",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    assert_eq!(req.send().await.unwrap().status(), 200);

    // Upload object
    let body = b"authenticated content";
    let req = sign_request(
        client
            .put(format!("{}/auth-bucket/secret.txt", base_url))
            .body(&body[..]),
        "PUT",
        "/auth-bucket/secret.txt",
        "",
        host,
        body,
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    assert_eq!(req.send().await.unwrap().status(), 200);

    // Get object
    let req = sign_request(
        client.get(format!("{}/auth-bucket/secret.txt", base_url)),
        "GET",
        "/auth-bucket/secret.txt",
        "",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "authenticated content");

    // Delete object
    let req = sign_request(
        client.delete(format!("{}/auth-bucket/secret.txt", base_url)),
        "DELETE",
        "/auth-bucket/secret.txt",
        "",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    assert_eq!(req.send().await.unwrap().status(), 204);

    // Delete bucket
    let req = sign_request(
        client.delete(format!("{}/auth-bucket", base_url)),
        "DELETE",
        "/auth-bucket",
        "",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    assert_eq!(req.send().await.unwrap().status(), 204);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_no_auth_configured_allows_all() {
    // Server started without credentials should accept all requests
    let (base_url, tmp_dir) = start_server_with_auth(None).await;
    let client = reqwest::Client::new();

    let resp = client.get(&base_url).send().await.unwrap();
    assert_eq!(
        resp.status(),
        200,
        "No auth configured should allow all requests"
    );

    cleanup(&tmp_dir);
}

// ======== Presigned URL tests ========

/// Generate a presigned GET URL for a given path.
fn sign_presigned_url(
    base_url: &str,
    method: &str,
    path: &str,
    host: &str,
    expires_secs: u64,
    access_key: &str,
    secret_key: &str,
) -> String {
    sign_presigned_url_at(
        base_url,
        method,
        path,
        host,
        expires_secs,
        access_key,
        secret_key,
        chrono::Utc::now(),
    )
}

fn sign_presigned_url_at(
    base_url: &str,
    method: &str,
    path: &str,
    host: &str,
    expires_secs: u64,
    access_key: &str,
    secret_key: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();
    let region = "loch-sh";
    let service = "s3";
    let scope = format!("{}/{}/{}/aws4_request", date_stamp, region, service);

    // X-Amz-Credential value: slashes URL-encoded
    let credential_raw = format!("{}/{}", access_key, scope);
    let credential_encoded = credential_raw.replace('/', "%2F");

    let signed_headers = "host";

    // Build sorted query params (without X-Amz-Signature)
    let mut params: Vec<(&str, String)> = vec![
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_string()),
        ("X-Amz-Credential", credential_encoded),
        ("X-Amz-Date", amz_date.clone()),
        ("X-Amz-Expires", expires_secs.to_string()),
        ("X-Amz-SignedHeaders", signed_headers.to_string()),
    ];
    params.sort_by(|a, b| a.0.cmp(b.0));

    let query_without_sig = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&");

    // Canonical query: decode %2F back to /, then re-encode with uri_encode
    // For our params, X-Amz-Credential slashes become %2F in both raw and canonical form
    // because uri_encode(encode_slash=true) encodes / as %2F
    // Other params have no special chars, so canonical == raw.
    // We sort alphabetically (already done above).
    let canonical_query = query_without_sig.clone();

    // Canonical headers
    let canonical_headers = format!("host:{}\n", host);

    // Canonical request
    let canonical_req = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, path, canonical_query, canonical_headers, signed_headers, "UNSIGNED-PAYLOAD"
    );
    let canonical_req_hash = sha256_hex(canonical_req.as_bytes());

    // String to sign
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, scope, canonical_req_hash
    );

    // Sign
    let signing_key = derive_signing_key(secret_key, &date_stamp, region, service);
    let signature = hmac_sha256_hex(&signing_key, string_to_sign.as_bytes());

    format!(
        "{}{}?{}&X-Amz-Signature={}",
        base_url, path, query_without_sig, signature
    )
}

#[tokio::test]
async fn test_presigned_url_get() {
    let (base_url, tmp_dir) = start_server_with_auth(Some(Credentials {
        access_key_id: TEST_ACCESS_KEY.to_string(),
        secret_access_key: TEST_SECRET_KEY.to_string(),
    }))
    .await;
    let client = reqwest::Client::new();
    let host = base_url.strip_prefix("http://").unwrap();

    // Create bucket and upload object (signed)
    let req = sign_request(
        client.put(format!("{}/presigned-bucket", base_url)),
        "PUT",
        "/presigned-bucket",
        "",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    assert_eq!(req.send().await.unwrap().status(), 200);

    let content = b"hello presigned world";
    let req = sign_request(
        client
            .put(format!("{}/presigned-bucket/file.txt", base_url))
            .body(&content[..]),
        "PUT",
        "/presigned-bucket/file.txt",
        "",
        host,
        content,
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    assert_eq!(req.send().await.unwrap().status(), 200);

    // GET via presigned URL (no Authorization header)
    let url = sign_presigned_url(
        &base_url,
        "GET",
        "/presigned-bucket/file.txt",
        host,
        3600,
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200, "Presigned GET should return 200");
    assert_eq!(&resp.bytes().await.unwrap()[..], content);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_presigned_url_expired() {
    let (base_url, tmp_dir) = start_server_with_auth(Some(Credentials {
        access_key_id: TEST_ACCESS_KEY.to_string(),
        secret_access_key: TEST_SECRET_KEY.to_string(),
    }))
    .await;
    let client = reqwest::Client::new();
    let host = base_url.strip_prefix("http://").unwrap();

    // Create bucket and object
    let req = sign_request(
        client.put(format!("{}/exp-bucket", base_url)),
        "PUT",
        "/exp-bucket",
        "",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    req.send().await.unwrap();

    let req = sign_request(
        client
            .put(format!("{}/exp-bucket/file.txt", base_url))
            .body("data"),
        "PUT",
        "/exp-bucket/file.txt",
        "",
        host,
        b"data",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    req.send().await.unwrap();

    // Sign URL with timestamp 2 hours in the past, 1-second expiry
    let past = chrono::Utc::now() - chrono::Duration::hours(2);
    let url = sign_presigned_url_at(
        &base_url,
        "GET",
        "/exp-bucket/file.txt",
        host,
        1,
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
        past,
    );
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(
        resp.status(),
        403,
        "Expired presigned URL should return 403"
    );
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>ExpiredToken</Code>"));

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_presigned_url_wrong_secret() {
    let (base_url, tmp_dir) = start_server_with_auth(Some(Credentials {
        access_key_id: TEST_ACCESS_KEY.to_string(),
        secret_access_key: TEST_SECRET_KEY.to_string(),
    }))
    .await;
    let client = reqwest::Client::new();
    let host = base_url.strip_prefix("http://").unwrap();

    // Sign with wrong secret key
    let url = sign_presigned_url(
        &base_url,
        "GET",
        "/some-bucket/file.txt",
        host,
        3600,
        TEST_ACCESS_KEY,
        "WRONGSECRETKEY00000000000000000000000000",
    );
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 403, "Wrong secret should return 403");

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_presigned_url_expires_too_large() {
    let (base_url, tmp_dir) = start_server_with_auth(Some(Credentials {
        access_key_id: TEST_ACCESS_KEY.to_string(),
        secret_access_key: TEST_SECRET_KEY.to_string(),
    }))
    .await;
    let client = reqwest::Client::new();
    let host = base_url.strip_prefix("http://").unwrap();

    // 604801 seconds > 7 days — must be rejected
    let url = sign_presigned_url(
        &base_url,
        "GET",
        "/any-bucket/any-key",
        host,
        604_801,
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 403, "Expires > 7 days should return 403");

    // 0 seconds (unlimited) — must be rejected
    let url = sign_presigned_url(
        &base_url,
        "GET",
        "/any-bucket/any-key",
        host,
        0,
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 403, "Unlimited expires should return 403");

    // Exactly 604800 seconds is allowed (not expired yet, just created)
    let url = sign_presigned_url(
        &base_url,
        "GET",
        "/any-bucket/any-key",
        host,
        604_800,
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    let resp = client.get(&url).send().await.unwrap();
    // Returns 404 (bucket not found), not 403 — the expiry value was accepted
    assert_ne!(
        resp.status(),
        403,
        "Expires = 7 days should not be rejected for expiry"
    );

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_presigned_url_no_anonymous_fallback() {
    // A presigned URL with invalid signature must NOT fall back to anonymous access,
    // even if a public bucket policy is set.
    let (base_url, tmp_dir) = start_server_with_auth(Some(Credentials {
        access_key_id: TEST_ACCESS_KEY.to_string(),
        secret_access_key: TEST_SECRET_KEY.to_string(),
    }))
    .await;
    let client = reqwest::Client::new();
    let host = base_url.strip_prefix("http://").unwrap();

    // Create bucket and set public-read policy
    let req = sign_request(
        client.put(format!("{}/pub-presigned", base_url)),
        "PUT",
        "/pub-presigned",
        "",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    req.send().await.unwrap();

    let req = sign_request(
        client
            .put(format!("{}/pub-presigned/file.txt", base_url))
            .body("public"),
        "PUT",
        "/pub-presigned/file.txt",
        "",
        host,
        b"public",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    req.send().await.unwrap();

    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:loch:s3:::pub-presigned/*"}]
    }"#;
    let req = sign_request(
        client
            .put(format!("{}/pub-presigned?policy", base_url))
            .body(policy_json),
        "PUT",
        "/pub-presigned",
        "policy",
        host,
        policy_json.as_bytes(),
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    req.send().await.unwrap();

    // Sign with wrong secret
    let url = sign_presigned_url(
        &base_url,
        "GET",
        "/pub-presigned/file.txt",
        host,
        3600,
        TEST_ACCESS_KEY,
        "WRONGSECRETKEY00000000000000000000000000",
    );
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(
        resp.status(),
        403,
        "Invalid presigned URL must not fall back to public policy"
    );

    cleanup(&tmp_dir);
}

// ======== Bucket Policy tests ========

#[tokio::test]
async fn test_policy_crud() {
    let (base_url, tmp_dir) = start_server_with_auth(Some(Credentials {
        access_key_id: TEST_ACCESS_KEY.to_string(),
        secret_access_key: TEST_SECRET_KEY.to_string(),
    }))
    .await;
    let client = reqwest::Client::new();
    let host = base_url.strip_prefix("http://").unwrap();

    // Create bucket
    let req = sign_request(
        client.put(format!("{}/policy-bucket", base_url)),
        "PUT",
        "/policy-bucket",
        "",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    assert_eq!(req.send().await.unwrap().status(), 200);

    // PUT policy
    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:loch:s3:::policy-bucket/*"
        }]
    }"#;
    let req = sign_request(
        client
            .put(format!("{}/policy-bucket?policy", base_url))
            .body(policy_json),
        "PUT",
        "/policy-bucket",
        "policy",
        host,
        policy_json.as_bytes(),
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    assert_eq!(req.send().await.unwrap().status(), 204);

    // GET policy
    let req = sign_request(
        client.get(format!("{}/policy-bucket?policy", base_url)),
        "GET",
        "/policy-bucket",
        "policy",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("s3:GetObject"));

    // DELETE policy
    let req = sign_request(
        client.delete(format!("{}/policy-bucket?policy", base_url)),
        "DELETE",
        "/policy-bucket",
        "policy",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    assert_eq!(req.send().await.unwrap().status(), 204);

    // GET policy after delete -> 404
    let req = sign_request(
        client.get(format!("{}/policy-bucket?policy", base_url)),
        "GET",
        "/policy-bucket",
        "policy",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    assert_eq!(req.send().await.unwrap().status(), 404);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_policy_public_read() {
    let (base_url, tmp_dir) = start_server_with_auth(Some(Credentials {
        access_key_id: TEST_ACCESS_KEY.to_string(),
        secret_access_key: TEST_SECRET_KEY.to_string(),
    }))
    .await;
    let client = reqwest::Client::new();
    let host = base_url.strip_prefix("http://").unwrap();

    // Create bucket + upload object (signed)
    let req = sign_request(
        client.put(format!("{}/pub-bucket", base_url)),
        "PUT",
        "/pub-bucket",
        "",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    assert_eq!(req.send().await.unwrap().status(), 200);

    let content = b"public content";
    let req = sign_request(
        client
            .put(format!("{}/pub-bucket/readme.txt", base_url))
            .body(&content[..]),
        "PUT",
        "/pub-bucket/readme.txt",
        "",
        host,
        content,
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    assert_eq!(req.send().await.unwrap().status(), 200);

    // Unauthenticated GET should fail (no policy yet)
    let resp = client
        .get(format!("{}/pub-bucket/readme.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "Should be denied without policy");

    // Set public read policy
    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:loch:s3:::pub-bucket/*"
        }]
    }"#;
    let req = sign_request(
        client
            .put(format!("{}/pub-bucket?policy", base_url))
            .body(policy_json),
        "PUT",
        "/pub-bucket",
        "policy",
        host,
        policy_json.as_bytes(),
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    assert_eq!(req.send().await.unwrap().status(), 204);

    // Unauthenticated GET should now succeed
    let resp = client
        .get(format!("{}/pub-bucket/readme.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "Public read should be allowed by policy"
    );
    assert_eq!(resp.text().await.unwrap(), "public content");

    // Unauthenticated PUT should still fail
    let resp = client
        .put(format!("{}/pub-bucket/hack.txt", base_url))
        .body("nope")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "PUT should still be denied");

    // Unauthenticated DELETE should still fail
    let resp = client
        .delete(format!("{}/pub-bucket/readme.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "DELETE should still be denied");

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_policy_no_admin_access() {
    let (base_url, tmp_dir) = start_server_with_auth(Some(Credentials {
        access_key_id: TEST_ACCESS_KEY.to_string(),
        secret_access_key: TEST_SECRET_KEY.to_string(),
    }))
    .await;
    let client = reqwest::Client::new();
    let host = base_url.strip_prefix("http://").unwrap();

    // Create bucket and set wildcard policy
    let req = sign_request(
        client.put(format!("{}/admin-bucket", base_url)),
        "PUT",
        "/admin-bucket",
        "",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    assert_eq!(req.send().await.unwrap().status(), 200);

    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:loch:s3:::admin-bucket/*"
        }]
    }"#;
    let req = sign_request(
        client
            .put(format!("{}/admin-bucket?policy", base_url))
            .body(policy_json),
        "PUT",
        "/admin-bucket",
        "policy",
        host,
        policy_json.as_bytes(),
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    assert_eq!(req.send().await.unwrap().status(), 204);

    // Unauthenticated ListBuckets should fail
    let resp = client.get(&base_url).send().await.unwrap();
    assert_eq!(resp.status(), 403, "ListBuckets should require auth");

    // Unauthenticated CreateBucket should fail
    let resp = client
        .put(format!("{}/new-bucket", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "CreateBucket should require auth");

    // Unauthenticated PUT policy should fail
    let resp = client
        .put(format!("{}/admin-bucket?policy", base_url))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "PUT policy should require auth");

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_policy_public_list() {
    let (base_url, tmp_dir) = start_server_with_auth(Some(Credentials {
        access_key_id: TEST_ACCESS_KEY.to_string(),
        secret_access_key: TEST_SECRET_KEY.to_string(),
    }))
    .await;
    let client = reqwest::Client::new();
    let host = base_url.strip_prefix("http://").unwrap();

    // Create bucket + upload objects
    let req = sign_request(
        client.put(format!("{}/list-bucket", base_url)),
        "PUT",
        "/list-bucket",
        "",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    assert_eq!(req.send().await.unwrap().status(), 200);

    let req = sign_request(
        client
            .put(format!("{}/list-bucket/a.txt", base_url))
            .body("a"),
        "PUT",
        "/list-bucket/a.txt",
        "",
        host,
        b"a",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    assert_eq!(req.send().await.unwrap().status(), 200);

    // Set policy allowing ListBucket
    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:ListBucket",
            "Resource": "arn:loch:s3:::list-bucket"
        }]
    }"#;
    let req = sign_request(
        client
            .put(format!("{}/list-bucket?policy", base_url))
            .body(policy_json),
        "PUT",
        "/list-bucket",
        "policy",
        host,
        policy_json.as_bytes(),
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    );
    assert_eq!(req.send().await.unwrap().status(), 204);

    // Unauthenticated list should succeed
    let resp = client
        .get(format!("{}/list-bucket?list-type=2", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "ListBucket should be allowed by policy");
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Key>a.txt</Key>"));

    cleanup(&tmp_dir);
}

// ======== CORS tests ========

#[tokio::test]
async fn test_cors_crud() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    // Create bucket
    client
        .put(format!("{}/cors-bucket", base_url))
        .send()
        .await
        .unwrap();

    // PUT CORS
    let cors_xml = r#"<CORSConfiguration>
        <CORSRule>
            <AllowedOrigin>https://example.com</AllowedOrigin>
            <AllowedMethod>GET</AllowedMethod>
            <AllowedMethod>PUT</AllowedMethod>
            <AllowedHeader>*</AllowedHeader>
            <MaxAgeSeconds>3600</MaxAgeSeconds>
            <ExposeHeader>ETag</ExposeHeader>
        </CORSRule>
    </CORSConfiguration>"#;
    let resp = client
        .put(format!("{}/cors-bucket?cors", base_url))
        .body(cors_xml)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "PutBucketCors should return 200");

    // GET CORS
    let resp = client
        .get(format!("{}/cors-bucket?cors", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("CORSConfiguration"));
    assert!(body.contains("https://example.com"));
    assert!(body.contains("GET"));
    assert!(body.contains("PUT"));

    // DELETE CORS
    let resp = client
        .delete(format!("{}/cors-bucket?cors", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // GET CORS after delete -> 404
    let resp = client
        .get(format!("{}/cors-bucket?cors", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_cors_preflight() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/preflight-bucket", base_url))
        .send()
        .await
        .unwrap();

    let cors_xml = r#"<CORSConfiguration>
        <CORSRule>
            <AllowedOrigin>https://example.com</AllowedOrigin>
            <AllowedMethod>GET</AllowedMethod>
            <AllowedMethod>PUT</AllowedMethod>
            <AllowedHeader>*</AllowedHeader>
            <MaxAgeSeconds>3600</MaxAgeSeconds>
        </CORSRule>
    </CORSConfiguration>"#;
    client
        .put(format!("{}/preflight-bucket?cors", base_url))
        .body(cors_xml)
        .send()
        .await
        .unwrap();

    // OPTIONS preflight with matching origin
    let resp = client
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/preflight-bucket/some-key", base_url),
        )
        .header("Origin", "https://example.com")
        .header("Access-Control-Request-Method", "PUT")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "Preflight should return 200");
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        "https://example.com"
    );
    assert!(
        resp.headers()
            .get("access-control-allow-methods")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("PUT")
    );
    assert_eq!(
        resp.headers()
            .get("access-control-max-age")
            .unwrap()
            .to_str()
            .unwrap(),
        "3600"
    );

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_cors_headers_on_get() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/cors-headers-bucket", base_url))
        .send()
        .await
        .unwrap();
    client
        .put(format!("{}/cors-headers-bucket/file.txt", base_url))
        .body("hello")
        .send()
        .await
        .unwrap();

    let cors_xml = r#"<CORSConfiguration>
        <CORSRule>
            <AllowedOrigin>https://app.example.com</AllowedOrigin>
            <AllowedMethod>GET</AllowedMethod>
            <ExposeHeader>ETag</ExposeHeader>
            <ExposeHeader>x-amz-request-id</ExposeHeader>
        </CORSRule>
    </CORSConfiguration>"#;
    client
        .put(format!("{}/cors-headers-bucket?cors", base_url))
        .body(cors_xml)
        .send()
        .await
        .unwrap();

    // GET with Origin header
    let resp = client
        .get(format!("{}/cors-headers-bucket/file.txt", base_url))
        .header("Origin", "https://app.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        "https://app.example.com"
    );
    assert!(resp.headers().get("vary").is_some());
    assert!(
        resp.headers()
            .get("access-control-expose-headers")
            .is_some()
    );

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_cors_preflight_rejected() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/cors-reject-bucket", base_url))
        .send()
        .await
        .unwrap();

    let cors_xml = r#"<CORSConfiguration>
        <CORSRule>
            <AllowedOrigin>https://example.com</AllowedOrigin>
            <AllowedMethod>GET</AllowedMethod>
        </CORSRule>
    </CORSConfiguration>"#;
    client
        .put(format!("{}/cors-reject-bucket?cors", base_url))
        .body(cors_xml)
        .send()
        .await
        .unwrap();

    // OPTIONS with non-matching origin
    let resp = client
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/cors-reject-bucket/file", base_url),
        )
        .header("Origin", "https://evil.com")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "Non-matching origin should be rejected");

    cleanup(&tmp_dir);
}

// ======== Multipart upload tests ========

/// Helper: extract a value from an XML tag in the response body.
fn extract_xml_value(xml: &str, tag: &str) -> String {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open).expect(&format!("tag {} not found", tag)) + open.len();
    let end = xml[start..]
        .find(&close)
        .expect(&format!("closing {} not found", tag));
    xml[start..start + end].to_string()
}

#[tokio::test]
async fn test_multipart_upload_basic() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    // Create bucket
    client
        .put(format!("{}/mp-bucket", base_url))
        .send()
        .await
        .unwrap();

    // Initiate multipart upload
    let resp = client
        .post(format!("{}/mp-bucket/bigfile.txt?uploads", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    let upload_id = extract_xml_value(&body, "UploadId");
    assert!(!upload_id.is_empty());

    // Upload part 1
    let resp = client
        .put(format!(
            "{}/mp-bucket/bigfile.txt?partNumber=1&uploadId={}",
            base_url, upload_id
        ))
        .body("hello ")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let etag1 = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Upload part 2
    let resp = client
        .put(format!(
            "{}/mp-bucket/bigfile.txt?partNumber=2&uploadId={}",
            base_url, upload_id
        ))
        .body("world")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let etag2 = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Complete multipart upload
    let complete_xml = format!(
        "<CompleteMultipartUpload>\
           <Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part>\
           <Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part>\
         </CompleteMultipartUpload>",
        etag1, etag2
    );
    let resp = client
        .post(format!(
            "{}/mp-bucket/bigfile.txt?uploadId={}",
            base_url, upload_id
        ))
        .body(complete_xml)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    let result_etag = extract_xml_value(&body, "ETag");
    assert!(
        result_etag.contains("-2"),
        "Multipart ETag should contain -2 suffix"
    );

    // Verify the assembled object
    let resp = client
        .get(format!("{}/mp-bucket/bigfile.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "hello world");

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_multipart_upload_abort() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/abort-bucket", base_url))
        .send()
        .await
        .unwrap();

    // Initiate
    let resp = client
        .post(format!("{}/abort-bucket/file.txt?uploads", base_url))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    let upload_id = extract_xml_value(&body, "UploadId");

    // Upload a part
    client
        .put(format!(
            "{}/abort-bucket/file.txt?partNumber=1&uploadId={}",
            base_url, upload_id
        ))
        .body("data")
        .send()
        .await
        .unwrap();

    // Abort
    let resp = client
        .delete(format!(
            "{}/abort-bucket/file.txt?uploadId={}",
            base_url, upload_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Verify the object does not exist
    let resp = client
        .get(format!("{}/abort-bucket/file.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Verify no uploads remain
    let resp = client
        .get(format!("{}/abort-bucket?uploads", base_url))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    assert!(
        !body.contains("<Upload>"),
        "No uploads should remain after abort"
    );

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_multipart_upload_list_parts() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/parts-bucket", base_url))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{}/parts-bucket/file.txt?uploads", base_url))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    let upload_id = extract_xml_value(&body, "UploadId");

    // Upload 3 parts
    for i in 1..=3 {
        client
            .put(format!(
                "{}/parts-bucket/file.txt?partNumber={}&uploadId={}",
                base_url, i, upload_id
            ))
            .body(format!("part-{}", i))
            .send()
            .await
            .unwrap();
    }

    // List parts
    let resp = client
        .get(format!(
            "{}/parts-bucket/file.txt?uploadId={}",
            base_url, upload_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();

    // Should contain 3 parts
    let part_count = body.matches("<PartNumber>").count();
    assert_eq!(part_count, 3, "Should list 3 parts");

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_multipart_upload_list_uploads() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/list-up-bucket", base_url))
        .send()
        .await
        .unwrap();

    // Initiate 2 uploads
    let resp = client
        .post(format!("{}/list-up-bucket/a.txt?uploads", base_url))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    let upload_id_a = extract_xml_value(&body, "UploadId");

    let resp = client
        .post(format!("{}/list-up-bucket/b.txt?uploads", base_url))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    let _upload_id_b = extract_xml_value(&body, "UploadId");

    // List uploads — should have 2
    let resp = client
        .get(format!("{}/list-up-bucket?uploads", base_url))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    let upload_count = body.matches("<Upload>").count();
    assert_eq!(upload_count, 2, "Should list 2 uploads");

    // Abort one
    client
        .delete(format!(
            "{}/list-up-bucket/a.txt?uploadId={}",
            base_url, upload_id_a
        ))
        .send()
        .await
        .unwrap();

    // List uploads — should have 1
    let resp = client
        .get(format!("{}/list-up-bucket?uploads", base_url))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    let upload_count = body.matches("<Upload>").count();
    assert_eq!(upload_count, 1, "Should list 1 upload after aborting one");

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_multipart_upload_invalid_part_order() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/order-bucket", base_url))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{}/order-bucket/file.txt?uploads", base_url))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    let upload_id = extract_xml_value(&body, "UploadId");

    // Upload parts 1 and 2
    let resp = client
        .put(format!(
            "{}/order-bucket/file.txt?partNumber=1&uploadId={}",
            base_url, upload_id
        ))
        .body("part1")
        .send()
        .await
        .unwrap();
    let etag1 = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let resp = client
        .put(format!(
            "{}/order-bucket/file.txt?partNumber=2&uploadId={}",
            base_url, upload_id
        ))
        .body("part2")
        .send()
        .await
        .unwrap();
    let etag2 = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Complete with wrong order (2, 1)
    let complete_xml = format!(
        "<CompleteMultipartUpload>\
           <Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part>\
           <Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part>\
         </CompleteMultipartUpload>",
        etag2, etag1
    );
    let resp = client
        .post(format!(
            "{}/order-bucket/file.txt?uploadId={}",
            base_url, upload_id
        ))
        .body(complete_xml)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "Invalid part order should return 400");

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_multipart_upload_no_such_upload() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/nosuch-bucket", base_url))
        .send()
        .await
        .unwrap();

    // Try uploading a part to a non-existent upload
    let resp = client
        .put(format!(
            "{}/nosuch-bucket/file.txt?partNumber=1&uploadId=nonexistent",
            base_url
        ))
        .body("data")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "Non-existent upload should return 404");
    let body = resp.text().await.unwrap();
    assert!(body.contains("NoSuchUpload"));

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_multipart_does_not_appear_in_list_objects() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/hidden-bucket", base_url))
        .send()
        .await
        .unwrap();

    // Upload a regular object
    client
        .put(format!("{}/hidden-bucket/regular.txt", base_url))
        .body("regular content")
        .send()
        .await
        .unwrap();

    // Initiate a multipart upload and upload a part
    let resp = client
        .post(format!("{}/hidden-bucket/multipart.txt?uploads", base_url))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    let upload_id = extract_xml_value(&body, "UploadId");

    client
        .put(format!(
            "{}/hidden-bucket/multipart.txt?partNumber=1&uploadId={}",
            base_url, upload_id
        ))
        .body("part data")
        .send()
        .await
        .unwrap();

    // List objects — only the regular object should appear
    let resp = client
        .get(format!("{}/hidden-bucket?list-type=2", base_url))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Key>regular.txt</Key>"));
    assert!(
        !body.contains(".uploads"),
        "Multipart state should not appear in object listing"
    );
    assert_eq!(
        body.matches("<Key>").count(),
        1,
        "Only the regular object should be listed"
    );

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_streaming_large_object() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/stream-bucket", base_url))
        .send()
        .await
        .unwrap();

    // Create a ~1 MB payload
    let large_data = "x".repeat(1_000_000);

    // Upload
    let resp = client
        .put(format!("{}/stream-bucket/large.bin", base_url))
        .body(large_data.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let etag = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(!etag.is_empty());

    // Download and verify
    let resp = client
        .get(format!("{}/stream-bucket/large.bin", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let downloaded = resp.text().await.unwrap();
    assert_eq!(downloaded.len(), 1_000_000);
    assert_eq!(downloaded, large_data);

    cleanup(&tmp_dir);
}

// ======== Versioning tests ========

/// Helper: enable versioning on a bucket.
async fn enable_versioning(client: &reqwest::Client, base_url: &str, bucket: &str) {
    let xml = "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
        <Status>Enabled</Status></VersioningConfiguration>";
    let resp = client
        .put(format!("{}/{}?versioning", base_url, bucket))
        .body(xml)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "Enable versioning should return 200");
}

#[tokio::test]
async fn test_versioning_enable_get() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/ver-bucket", base_url))
        .send()
        .await
        .unwrap();

    // Default: no versioning status
    let resp = client
        .get(format!("{}/ver-bucket?versioning", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        !body.contains("<Status>"),
        "Default should have no Status element"
    );

    // Enable versioning
    enable_versioning(&client, &base_url, "ver-bucket").await;

    let resp = client
        .get(format!("{}/ver-bucket?versioning", base_url))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Status>Enabled</Status>"));

    // Suspend versioning
    let xml = "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
        <Status>Suspended</Status></VersioningConfiguration>";
    client
        .put(format!("{}/ver-bucket?versioning", base_url))
        .body(xml)
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!("{}/ver-bucket?versioning", base_url))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Status>Suspended</Status>"));

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_versioning_put_creates_versions() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/vput-bucket", base_url))
        .send()
        .await
        .unwrap();
    enable_versioning(&client, &base_url, "vput-bucket").await;

    // PUT 3 versions of the same key
    let mut version_ids = Vec::new();
    for i in 1..=3 {
        let resp = client
            .put(format!("{}/vput-bucket/file.txt", base_url))
            .body(format!("content-v{}", i))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let vid = resp
            .headers()
            .get("x-amz-version-id")
            .expect("PUT should return x-amz-version-id")
            .to_str()
            .unwrap()
            .to_string();
        assert!(!vid.is_empty());
        version_ids.push(vid);

        // Small delay to ensure distinct timestamps
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // All version IDs should be distinct
    assert_ne!(version_ids[0], version_ids[1]);
    assert_ne!(version_ids[1], version_ids[2]);

    // GET without versionId returns latest
    let resp = client
        .get(format!("{}/vput-bucket/file.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let vid_header = resp
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(vid_header, version_ids[2], "Latest version ID should match");
    let body = resp.text().await.unwrap();
    assert_eq!(body, "content-v3");

    // GET with specific versionId returns that version
    let resp = client
        .get(format!(
            "{}/vput-bucket/file.txt?versionId={}",
            base_url, version_ids[0]
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "content-v1");

    let resp = client
        .get(format!(
            "{}/vput-bucket/file.txt?versionId={}",
            base_url, version_ids[1]
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "content-v2");

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_versioning_delete_creates_marker() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/vdel-bucket", base_url))
        .send()
        .await
        .unwrap();
    enable_versioning(&client, &base_url, "vdel-bucket").await;

    // PUT an object
    let resp = client
        .put(format!("{}/vdel-bucket/file.txt", base_url))
        .body("hello")
        .send()
        .await
        .unwrap();
    let put_vid = resp
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // DELETE without versionId
    let resp = client
        .delete(format!("{}/vdel-bucket/file.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let delete_marker = resp
        .headers()
        .get("x-amz-delete-marker")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(delete_marker, "true");
    let del_vid = resp
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(!del_vid.is_empty());
    assert_ne!(del_vid, put_vid);

    // GET without versionId returns 404 with delete marker headers
    let resp = client
        .get(format!("{}/vdel-bucket/file.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    assert_eq!(
        resp.headers()
            .get("x-amz-delete-marker")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );

    // GET with original versionId still works
    let resp = client
        .get(format!(
            "{}/vdel-bucket/file.txt?versionId={}",
            base_url, put_vid
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "hello");

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_versioning_delete_specific_version() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/vdelv-bucket", base_url))
        .send()
        .await
        .unwrap();
    enable_versioning(&client, &base_url, "vdelv-bucket").await;

    // PUT 2 versions
    let resp = client
        .put(format!("{}/vdelv-bucket/file.txt", base_url))
        .body("v1")
        .send()
        .await
        .unwrap();
    let vid1 = resp
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let resp = client
        .put(format!("{}/vdelv-bucket/file.txt", base_url))
        .body("v2")
        .send()
        .await
        .unwrap();
    let vid2 = resp
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // DELETE specific version (vid1)
    let resp = client
        .delete(format!(
            "{}/vdelv-bucket/file.txt?versionId={}",
            base_url, vid1
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // vid1 is gone
    let resp = client
        .get(format!(
            "{}/vdelv-bucket/file.txt?versionId={}",
            base_url, vid1
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "Deleted version should return 404");

    // vid2 still accessible
    let resp = client
        .get(format!(
            "{}/vdelv-bucket/file.txt?versionId={}",
            base_url, vid2
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "v2");

    // GET without versionId returns v2
    let resp = client
        .get(format!("{}/vdelv-bucket/file.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "v2");

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_versioning_delete_marker_removal() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/vdmr-bucket", base_url))
        .send()
        .await
        .unwrap();
    enable_versioning(&client, &base_url, "vdmr-bucket").await;

    // PUT then DELETE (creates marker)
    client
        .put(format!("{}/vdmr-bucket/file.txt", base_url))
        .body("hello")
        .send()
        .await
        .unwrap();

    let resp = client
        .delete(format!("{}/vdmr-bucket/file.txt", base_url))
        .send()
        .await
        .unwrap();
    let marker_vid = resp
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Object is "deleted"
    let resp = client
        .get(format!("{}/vdmr-bucket/file.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // DELETE the delete marker (by versionId)
    let resp = client
        .delete(format!(
            "{}/vdmr-bucket/file.txt?versionId={}",
            base_url, marker_vid
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(
        resp.headers()
            .get("x-amz-delete-marker")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );

    // Object is visible again
    let resp = client
        .get(format!("{}/vdmr-bucket/file.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "hello");

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_versioning_list_versions() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/vlst-bucket", base_url))
        .send()
        .await
        .unwrap();
    enable_versioning(&client, &base_url, "vlst-bucket").await;

    // PUT 2 versions of key A
    client
        .put(format!("{}/vlst-bucket/a.txt", base_url))
        .body("a-v1")
        .send()
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    client
        .put(format!("{}/vlst-bucket/a.txt", base_url))
        .body("a-v2")
        .send()
        .await
        .unwrap();

    // DELETE key A (creates marker)
    client
        .delete(format!("{}/vlst-bucket/a.txt", base_url))
        .send()
        .await
        .unwrap();

    // PUT 1 version of key B
    client
        .put(format!("{}/vlst-bucket/b.txt", base_url))
        .body("b-v1")
        .send()
        .await
        .unwrap();

    // GET ?versions
    let resp = client
        .get(format!("{}/vlst-bucket?versions", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();

    // Should contain 3 Version entries (a-v1, a-v2, b-v1) and 1 DeleteMarker
    let version_count = body.matches("<Version>").count();
    assert_eq!(
        version_count, 3,
        "Should have 3 Version entries, got body: {}",
        body
    );

    let marker_count = body.matches("<DeleteMarker>").count();
    assert_eq!(marker_count, 1, "Should have 1 DeleteMarker entry");

    assert!(body.contains("<Key>a.txt</Key>"));
    assert!(body.contains("<Key>b.txt</Key>"));
    assert!(body.contains("<IsLatest>true</IsLatest>"));

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_versioning_head_with_version_id() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/vhead-bucket", base_url))
        .send()
        .await
        .unwrap();
    enable_versioning(&client, &base_url, "vhead-bucket").await;

    let resp = client
        .put(format!("{}/vhead-bucket/file.txt", base_url))
        .body("hello world")
        .send()
        .await
        .unwrap();
    let vid = resp
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // HEAD with versionId
    let resp = client
        .head(format!(
            "{}/vhead-bucket/file.txt?versionId={}",
            base_url, vid
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-amz-version-id")
            .unwrap()
            .to_str()
            .unwrap(),
        vid
    );
    assert_eq!(
        resp.headers()
            .get("content-length")
            .unwrap()
            .to_str()
            .unwrap(),
        "11"
    );

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_versioning_get_delete_marker_by_version_id() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/vgdm-bucket", base_url))
        .send()
        .await
        .unwrap();
    enable_versioning(&client, &base_url, "vgdm-bucket").await;

    client
        .put(format!("{}/vgdm-bucket/file.txt", base_url))
        .body("data")
        .send()
        .await
        .unwrap();

    let resp = client
        .delete(format!("{}/vgdm-bucket/file.txt", base_url))
        .send()
        .await
        .unwrap();
    let marker_vid = resp
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // GET with the marker's versionId returns 405 with delete marker header
    let resp = client
        .get(format!(
            "{}/vgdm-bucket/file.txt?versionId={}",
            base_url, marker_vid
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 405);
    assert_eq!(
        resp.headers()
            .get("x-amz-delete-marker")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_versioning_does_not_affect_list_objects() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/vlist-bucket", base_url))
        .send()
        .await
        .unwrap();
    enable_versioning(&client, &base_url, "vlist-bucket").await;

    // PUT 3 versions of same key
    for i in 1..=3 {
        client
            .put(format!("{}/vlist-bucket/file.txt", base_url))
            .body(format!("v{}", i))
            .send()
            .await
            .unwrap();
    }

    // PUT another object
    client
        .put(format!("{}/vlist-bucket/other.txt", base_url))
        .body("other")
        .send()
        .await
        .unwrap();

    // ListObjectsV2 should show 2 objects (not 3 versions)
    let resp = client
        .get(format!("{}/vlist-bucket?list-type=2", base_url))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    assert_eq!(body.matches("<Key>").count(), 2, "Should list 2 objects");
    assert!(body.contains("<Key>file.txt</Key>"));
    assert!(body.contains("<Key>other.txt</Key>"));
    assert!(!body.contains(".versions"), ".versions should not appear");
    assert!(
        !body.contains(".versioning.json"),
        ".versioning.json should not appear"
    );

    // DELETE file.txt (creates marker, removes normal path)
    client
        .delete(format!("{}/vlist-bucket/file.txt", base_url))
        .send()
        .await
        .unwrap();

    // ListObjectsV2 should show 1 object
    let resp = client
        .get(format!("{}/vlist-bucket?list-type=2", base_url))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    assert_eq!(
        body.matches("<Key>").count(),
        1,
        "Should list 1 object after delete"
    );
    assert!(body.contains("<Key>other.txt</Key>"));
    assert!(
        !body.contains("<Key>file.txt</Key>"),
        "Deleted object should not appear"
    );

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_versioning_copy_with_version_id() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/vcopy-bucket", base_url))
        .send()
        .await
        .unwrap();
    enable_versioning(&client, &base_url, "vcopy-bucket").await;

    // PUT 2 versions
    let resp = client
        .put(format!("{}/vcopy-bucket/src.txt", base_url))
        .body("version-1")
        .send()
        .await
        .unwrap();
    let vid1 = resp
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    client
        .put(format!("{}/vcopy-bucket/src.txt", base_url))
        .body("version-2")
        .send()
        .await
        .unwrap();

    // Copy the first version to a new key
    let resp = client
        .put(format!("{}/vcopy-bucket/dst.txt", base_url))
        .header(
            "x-amz-copy-source",
            format!("vcopy-bucket/src.txt?versionId={}", vid1),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Verify the copy has the first version's content
    let resp = client
        .get(format!("{}/vcopy-bucket/dst.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "version-1");

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_versioning_pre_existing_object_migration() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/vmig-bucket", base_url))
        .send()
        .await
        .unwrap();

    // PUT object BEFORE enabling versioning
    client
        .put(format!("{}/vmig-bucket/file.txt", base_url))
        .body("pre-versioning")
        .send()
        .await
        .unwrap();

    // Enable versioning
    enable_versioning(&client, &base_url, "vmig-bucket").await;

    // PUT a new version (this triggers migration of the pre-versioning object)
    // But first, DELETE to trigger migration
    let resp = client
        .delete(format!("{}/vmig-bucket/file.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let del_vid = resp
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Object should be "deleted" (delete marker)
    let resp = client
        .get(format!("{}/vmig-bucket/file.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // The pre-versioning object should be accessible via versionId=null
    let resp = client
        .get(format!("{}/vmig-bucket/file.txt?versionId=null", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "pre-versioning");

    // Remove the delete marker to restore the object
    client
        .delete(format!(
            "{}/vmig-bucket/file.txt?versionId={}",
            base_url, del_vid
        ))
        .send()
        .await
        .unwrap();

    // Object should be visible again with pre-versioning content
    let resp = client
        .get(format!("{}/vmig-bucket/file.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "pre-versioning");

    cleanup(&tmp_dir);
}

// ======== Object Metadata Tests ========

#[tokio::test]
async fn test_metadata_roundtrip() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    // Create bucket
    client
        .put(format!("{}/meta-bucket", base_url))
        .send()
        .await
        .unwrap();

    // PUT with metadata headers
    let resp = client
        .put(format!("{}/meta-bucket/doc.txt", base_url))
        .header("Content-Type", "text/plain; charset=utf-8")
        .header("Cache-Control", "max-age=3600")
        .header("Content-Disposition", "attachment; filename=\"doc.txt\"")
        .header("Content-Language", "en-US")
        .header("Expires", "Thu, 01 Dec 2030 16:00:00 GMT")
        .header("x-amz-meta-author", "alice")
        .header("x-amz-meta-project", "loch-s3")
        .body("hello metadata")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // GET and verify all metadata headers
    let resp = client
        .get(format!("{}/meta-bucket/doc.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "text/plain; charset=utf-8"
    );
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap(),
        "max-age=3600"
    );
    assert_eq!(
        resp.headers()
            .get("content-disposition")
            .unwrap()
            .to_str()
            .unwrap(),
        "attachment; filename=\"doc.txt\""
    );
    assert_eq!(
        resp.headers()
            .get("content-language")
            .unwrap()
            .to_str()
            .unwrap(),
        "en-US"
    );
    assert_eq!(
        resp.headers().get("expires").unwrap().to_str().unwrap(),
        "Thu, 01 Dec 2030 16:00:00 GMT"
    );
    assert_eq!(
        resp.headers()
            .get("x-amz-meta-author")
            .unwrap()
            .to_str()
            .unwrap(),
        "alice"
    );
    assert_eq!(
        resp.headers()
            .get("x-amz-meta-project")
            .unwrap()
            .to_str()
            .unwrap(),
        "loch-s3"
    );
    assert_eq!(resp.text().await.unwrap(), "hello metadata");

    // HEAD should also return metadata
    let resp = client
        .head(format!("{}/meta-bucket/doc.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap(),
        "max-age=3600"
    );
    assert_eq!(
        resp.headers()
            .get("x-amz-meta-author")
            .unwrap()
            .to_str()
            .unwrap(),
        "alice"
    );

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_metadata_content_type_override() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/meta-ct-bucket", base_url))
        .send()
        .await
        .unwrap();

    // PUT a .txt file with explicit application/json Content-Type
    client
        .put(format!("{}/meta-ct-bucket/data.txt", base_url))
        .header("Content-Type", "application/json")
        .body("{\"key\": \"value\"}")
        .send()
        .await
        .unwrap();

    // GET should return the explicit Content-Type, not text/plain
    let resp = client
        .get(format!("{}/meta-ct-bucket/data.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/json"
    );

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_metadata_backward_compat() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/meta-compat-bucket", base_url))
        .send()
        .await
        .unwrap();

    // PUT without any special headers
    client
        .put(format!("{}/meta-compat-bucket/image.png", base_url))
        .body(b"fake-png-data".to_vec())
        .send()
        .await
        .unwrap();

    // GET should guess Content-Type from extension
    let resp = client
        .get(format!("{}/meta-compat-bucket/image.png", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "image/png"
    );
    // No Cache-Control should be present
    assert!(resp.headers().get("cache-control").is_none());

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_metadata_copy_preserves() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/meta-copy-bucket", base_url))
        .send()
        .await
        .unwrap();

    // PUT source with metadata
    client
        .put(format!("{}/meta-copy-bucket/source.txt", base_url))
        .header("Content-Type", "text/markdown")
        .header("Cache-Control", "no-cache")
        .header("x-amz-meta-tag", "original")
        .body("copy me")
        .send()
        .await
        .unwrap();

    // COPY (default directive = COPY, preserves metadata)
    let resp = client
        .put(format!("{}/meta-copy-bucket/dest.txt", base_url))
        .header("x-amz-copy-source", "/meta-copy-bucket/source.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // GET destination should have source metadata
    let resp = client
        .get(format!("{}/meta-copy-bucket/dest.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "text/markdown"
    );
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap(),
        "no-cache"
    );
    assert_eq!(
        resp.headers()
            .get("x-amz-meta-tag")
            .unwrap()
            .to_str()
            .unwrap(),
        "original"
    );

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_metadata_copy_replace() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/meta-repl-bucket", base_url))
        .send()
        .await
        .unwrap();

    // PUT source with metadata
    client
        .put(format!("{}/meta-repl-bucket/source.txt", base_url))
        .header("Content-Type", "text/plain")
        .header("Cache-Control", "max-age=60")
        .header("x-amz-meta-old", "value")
        .body("replace me")
        .send()
        .await
        .unwrap();

    // COPY with REPLACE directive and new metadata
    let resp = client
        .put(format!("{}/meta-repl-bucket/replaced.txt", base_url))
        .header("x-amz-copy-source", "/meta-repl-bucket/source.txt")
        .header("x-amz-metadata-directive", "REPLACE")
        .header("Content-Type", "application/octet-stream")
        .header("Cache-Control", "no-store")
        .header("x-amz-meta-new", "replaced")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // GET destination should have the NEW metadata, not source
    let resp = client
        .get(format!("{}/meta-repl-bucket/replaced.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/octet-stream"
    );
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap(),
        "no-store"
    );
    assert_eq!(
        resp.headers()
            .get("x-amz-meta-new")
            .unwrap()
            .to_str()
            .unwrap(),
        "replaced"
    );
    // Old metadata should NOT be present
    assert!(resp.headers().get("x-amz-meta-old").is_none());

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_metadata_deleted_with_object() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/meta-del-bucket", base_url))
        .send()
        .await
        .unwrap();

    // PUT with metadata
    client
        .put(format!("{}/meta-del-bucket/temp.txt", base_url))
        .header("Cache-Control", "max-age=999")
        .header("x-amz-meta-session", "abc123")
        .body("temporary")
        .send()
        .await
        .unwrap();

    // DELETE
    let resp = client
        .delete(format!("{}/meta-del-bucket/temp.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Re-PUT without metadata
    client
        .put(format!("{}/meta-del-bucket/temp.txt", base_url))
        .body("fresh")
        .send()
        .await
        .unwrap();

    // GET should NOT have old metadata
    let resp = client
        .get(format!("{}/meta-del-bucket/temp.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("cache-control").is_none());
    assert!(resp.headers().get("x-amz-meta-session").is_none());
    assert_eq!(resp.text().await.unwrap(), "fresh");

    cleanup(&tmp_dir);
}

// ======== Server-Side Encryption (SSE) tests ========

#[tokio::test]
async fn test_sse_s3_put_get() {
    let (base_url, tmp_dir, _) = start_server_with_encryption().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/sse-bucket", base_url))
        .send()
        .await
        .unwrap();

    let content = b"hello encrypted world";
    let resp = client
        .put(format!("{}/sse-bucket/secret.txt", base_url))
        .header("x-amz-server-side-encryption", "AES256")
        .body(&content[..])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("etag").is_some());
    assert_eq!(
        resp.headers()
            .get("x-amz-server-side-encryption")
            .unwrap()
            .to_str()
            .unwrap(),
        "AES256"
    );

    // GET should transparently decrypt
    let resp = client
        .get(format!("{}/sse-bucket/secret.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-amz-server-side-encryption")
            .unwrap()
            .to_str()
            .unwrap(),
        "AES256"
    );
    assert_eq!(
        resp.headers()
            .get("content-length")
            .unwrap()
            .to_str()
            .unwrap(),
        "21"
    );
    assert_eq!(&resp.bytes().await.unwrap()[..], content);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_sse_s3_head() {
    let (base_url, tmp_dir, _) = start_server_with_encryption().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/sse-head-bucket", base_url))
        .send()
        .await
        .unwrap();

    let content = "test head with encryption";
    client
        .put(format!("{}/sse-head-bucket/file.txt", base_url))
        .header("x-amz-server-side-encryption", "AES256")
        .body(content)
        .send()
        .await
        .unwrap();

    let resp = client
        .head(format!("{}/sse-head-bucket/file.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-length")
            .unwrap()
            .to_str()
            .unwrap(),
        content.len().to_string()
    );
    assert_eq!(
        resp.headers()
            .get("x-amz-server-side-encryption")
            .unwrap()
            .to_str()
            .unwrap(),
        "AES256"
    );

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_sse_s3_without_master_key_fails() {
    // Server WITHOUT encryption config
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/sse-nokey-bucket", base_url))
        .send()
        .await
        .unwrap();

    let resp = client
        .put(format!("{}/sse-nokey-bucket/file.txt", base_url))
        .header("x-amz-server-side-encryption", "AES256")
        .body("data")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(body.contains("ServerSideEncryptionConfigurationNotFoundError"));

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_sse_c_put_get() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    let (_, key_b64, key_md5) = generate_customer_key();

    client
        .put(format!("{}/ssec-bucket", base_url))
        .send()
        .await
        .unwrap();

    let content = b"customer encrypted data";
    let resp = client
        .put(format!("{}/ssec-bucket/file.txt", base_url))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header("x-amz-server-side-encryption-customer-key", &key_b64)
        .header("x-amz-server-side-encryption-customer-key-md5", &key_md5)
        .body(&content[..])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-amz-server-side-encryption-customer-algorithm")
            .unwrap()
            .to_str()
            .unwrap(),
        "AES256"
    );

    // GET with correct key
    let resp = client
        .get(format!("{}/ssec-bucket/file.txt", base_url))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header("x-amz-server-side-encryption-customer-key", &key_b64)
        .header("x-amz-server-side-encryption-customer-key-md5", &key_md5)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-length")
            .unwrap()
            .to_str()
            .unwrap(),
        content.len().to_string()
    );
    assert_eq!(&resp.bytes().await.unwrap()[..], content);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_sse_c_get_without_key_fails() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    let (_, key_b64, key_md5) = generate_customer_key();

    client
        .put(format!("{}/ssec-nokey-bucket", base_url))
        .send()
        .await
        .unwrap();

    client
        .put(format!("{}/ssec-nokey-bucket/file.txt", base_url))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header("x-amz-server-side-encryption-customer-key", &key_b64)
        .header("x-amz-server-side-encryption-customer-key-md5", &key_md5)
        .body("secret")
        .send()
        .await
        .unwrap();

    // GET without SSE-C headers should fail
    let resp = client
        .get(format!("{}/ssec-nokey-bucket/file.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(body.contains("MissingSecurityHeader"));

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_sse_c_get_wrong_key_fails() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    let (_, key_b64, key_md5) = generate_customer_key();
    let (_, wrong_key_b64, wrong_key_md5) = generate_customer_key_2();

    client
        .put(format!("{}/ssec-wrong-bucket", base_url))
        .send()
        .await
        .unwrap();

    client
        .put(format!("{}/ssec-wrong-bucket/file.txt", base_url))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header("x-amz-server-side-encryption-customer-key", &key_b64)
        .header("x-amz-server-side-encryption-customer-key-md5", &key_md5)
        .body("secret data")
        .send()
        .await
        .unwrap();

    // GET with wrong key should fail (403 AccessDenied)
    let resp = client
        .get(format!("{}/ssec-wrong-bucket/file.txt", base_url))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header("x-amz-server-side-encryption-customer-key", &wrong_key_b64)
        .header(
            "x-amz-server-side-encryption-customer-key-md5",
            &wrong_key_md5,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("AccessDenied"));

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_sse_c_head_with_key() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    let (_, key_b64, key_md5) = generate_customer_key();

    client
        .put(format!("{}/ssec-head-bucket", base_url))
        .send()
        .await
        .unwrap();

    let content = "head with sse-c";
    client
        .put(format!("{}/ssec-head-bucket/file.txt", base_url))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header("x-amz-server-side-encryption-customer-key", &key_b64)
        .header("x-amz-server-side-encryption-customer-key-md5", &key_md5)
        .body(content)
        .send()
        .await
        .unwrap();

    // HEAD with correct key
    let resp = client
        .head(format!("{}/ssec-head-bucket/file.txt", base_url))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header("x-amz-server-side-encryption-customer-key", &key_b64)
        .header("x-amz-server-side-encryption-customer-key-md5", &key_md5)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-length")
            .unwrap()
            .to_str()
            .unwrap(),
        content.len().to_string()
    );
    assert_eq!(
        resp.headers()
            .get("x-amz-server-side-encryption-customer-algorithm")
            .unwrap()
            .to_str()
            .unwrap(),
        "AES256"
    );

    // HEAD without key should fail
    let resp = client
        .head(format!("{}/ssec-head-bucket/file.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_sse_s3_copy_encrypted_to_plaintext() {
    let (base_url, tmp_dir, _) = start_server_with_encryption().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/ssecopy-bucket", base_url))
        .send()
        .await
        .unwrap();

    let content = "encrypted source";
    client
        .put(format!("{}/ssecopy-bucket/encrypted.txt", base_url))
        .header("x-amz-server-side-encryption", "AES256")
        .body(content)
        .send()
        .await
        .unwrap();

    // Copy without SSE headers → destination is plaintext
    let resp = client
        .put(format!("{}/ssecopy-bucket/plain.txt", base_url))
        .header("x-amz-copy-source", "/ssecopy-bucket/encrypted.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // GET destination should work without encryption
    let resp = client
        .get(format!("{}/ssecopy-bucket/plain.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("x-amz-server-side-encryption").is_none());
    assert_eq!(resp.text().await.unwrap(), content);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_sse_s3_copy_plaintext_to_encrypted() {
    let (base_url, tmp_dir, _) = start_server_with_encryption().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/ssecopy2-bucket", base_url))
        .send()
        .await
        .unwrap();

    let content = "plaintext source";
    client
        .put(format!("{}/ssecopy2-bucket/plain.txt", base_url))
        .body(content)
        .send()
        .await
        .unwrap();

    // Copy with SSE-S3 → destination is encrypted
    let resp = client
        .put(format!("{}/ssecopy2-bucket/encrypted.txt", base_url))
        .header("x-amz-copy-source", "/ssecopy2-bucket/plain.txt")
        .header("x-amz-server-side-encryption", "AES256")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // GET destination should transparently decrypt
    let resp = client
        .get(format!("{}/ssecopy2-bucket/encrypted.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-amz-server-side-encryption")
            .unwrap()
            .to_str()
            .unwrap(),
        "AES256"
    );
    assert_eq!(resp.text().await.unwrap(), content);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_sse_c_copy_with_source_key() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    let (_, key_b64, key_md5) = generate_customer_key();

    client
        .put(format!("{}/sseccopy-bucket", base_url))
        .send()
        .await
        .unwrap();

    let content = "sse-c source data";
    client
        .put(format!("{}/sseccopy-bucket/source.txt", base_url))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header("x-amz-server-side-encryption-customer-key", &key_b64)
        .header("x-amz-server-side-encryption-customer-key-md5", &key_md5)
        .body(content)
        .send()
        .await
        .unwrap();

    // Copy with copy-source SSE-C headers, destination is plaintext
    let resp = client
        .put(format!("{}/sseccopy-bucket/dest.txt", base_url))
        .header("x-amz-copy-source", "/sseccopy-bucket/source.txt")
        .header(
            "x-amz-copy-source-server-side-encryption-customer-algorithm",
            "AES256",
        )
        .header(
            "x-amz-copy-source-server-side-encryption-customer-key",
            &key_b64,
        )
        .header(
            "x-amz-copy-source-server-side-encryption-customer-key-md5",
            &key_md5,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // GET destination (plaintext)
    let resp = client
        .get(format!("{}/sseccopy-bucket/dest.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), content);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_sse_s3_multipart() {
    let (base_url, tmp_dir, _) = start_server_with_encryption().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/sse-mp-bucket", base_url))
        .send()
        .await
        .unwrap();

    // Initiate multipart with SSE-S3
    let resp = client
        .post(format!("{}/sse-mp-bucket/bigfile.txt?uploads", base_url))
        .header("x-amz-server-side-encryption", "AES256")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    let upload_id = extract_xml_value(&body, "UploadId");

    // Upload parts
    let resp = client
        .put(format!(
            "{}/sse-mp-bucket/bigfile.txt?partNumber=1&uploadId={}",
            base_url, upload_id
        ))
        .body("part one ")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let etag1 = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let resp = client
        .put(format!(
            "{}/sse-mp-bucket/bigfile.txt?partNumber=2&uploadId={}",
            base_url, upload_id
        ))
        .body("part two")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let etag2 = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Complete
    let complete_xml = format!(
        "<CompleteMultipartUpload>\
           <Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part>\
           <Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part>\
         </CompleteMultipartUpload>",
        etag1, etag2
    );
    let resp = client
        .post(format!(
            "{}/sse-mp-bucket/bigfile.txt?uploadId={}",
            base_url, upload_id
        ))
        .body(complete_xml)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // GET should transparently decrypt
    let resp = client
        .get(format!("{}/sse-mp-bucket/bigfile.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-amz-server-side-encryption")
            .unwrap()
            .to_str()
            .unwrap(),
        "AES256"
    );
    assert_eq!(resp.text().await.unwrap(), "part one part two");

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_sse_c_multipart() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    let (_, key_b64, key_md5) = generate_customer_key();

    client
        .put(format!("{}/ssec-mp-bucket", base_url))
        .send()
        .await
        .unwrap();

    // Initiate multipart with SSE-C
    let resp = client
        .post(format!("{}/ssec-mp-bucket/bigfile.txt?uploads", base_url))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header("x-amz-server-side-encryption-customer-key", &key_b64)
        .header("x-amz-server-side-encryption-customer-key-md5", &key_md5)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    let upload_id = extract_xml_value(&body, "UploadId");

    // Upload parts (SSE-C requires key on each part upload)
    let resp = client
        .put(format!(
            "{}/ssec-mp-bucket/bigfile.txt?partNumber=1&uploadId={}",
            base_url, upload_id
        ))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header("x-amz-server-side-encryption-customer-key", &key_b64)
        .header("x-amz-server-side-encryption-customer-key-md5", &key_md5)
        .body("part A ")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let etag1 = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let resp = client
        .put(format!(
            "{}/ssec-mp-bucket/bigfile.txt?partNumber=2&uploadId={}",
            base_url, upload_id
        ))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header("x-amz-server-side-encryption-customer-key", &key_b64)
        .header("x-amz-server-side-encryption-customer-key-md5", &key_md5)
        .body("part B")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let etag2 = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Complete with SSE-C key
    let complete_xml = format!(
        "<CompleteMultipartUpload>\
           <Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part>\
           <Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part>\
         </CompleteMultipartUpload>",
        etag1, etag2
    );
    let resp = client
        .post(format!(
            "{}/ssec-mp-bucket/bigfile.txt?uploadId={}",
            base_url, upload_id
        ))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header("x-amz-server-side-encryption-customer-key", &key_b64)
        .header("x-amz-server-side-encryption-customer-key-md5", &key_md5)
        .body(complete_xml)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // GET with correct key
    let resp = client
        .get(format!("{}/ssec-mp-bucket/bigfile.txt", base_url))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header("x-amz-server-side-encryption-customer-key", &key_b64)
        .header("x-amz-server-side-encryption-customer-key-md5", &key_md5)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "part A part B");

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_sse_s3_large_object() {
    let (base_url, tmp_dir, _) = start_server_with_encryption().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/sse-large-bucket", base_url))
        .send()
        .await
        .unwrap();

    // Create a >1 MiB payload (spans multiple encryption chunks)
    let large_data = "A".repeat(1_100_000);

    let resp = client
        .put(format!("{}/sse-large-bucket/large.bin", base_url))
        .header("x-amz-server-side-encryption", "AES256")
        .body(large_data.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .get(format!("{}/sse-large-bucket/large.bin", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-length")
            .unwrap()
            .to_str()
            .unwrap(),
        "1100000"
    );
    let downloaded = resp.text().await.unwrap();
    assert_eq!(downloaded.len(), 1_100_000);
    assert_eq!(downloaded, large_data);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_sse_invalid_algorithm() {
    let (base_url, tmp_dir, _) = start_server_with_encryption().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/sse-algo-bucket", base_url))
        .send()
        .await
        .unwrap();

    // Use invalid algorithm
    let resp = client
        .put(format!("{}/sse-algo-bucket/file.txt", base_url))
        .header("x-amz-server-side-encryption", "DES")
        .body("data")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(body.contains("InvalidEncryptionAlgorithmError"));

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_sse_etag_is_plaintext_md5() {
    let (base_url, tmp_dir, _) = start_server_with_encryption().await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/sse-etag-bucket", base_url))
        .send()
        .await
        .unwrap();

    let content = b"verify etag";

    // Compute expected MD5 of plaintext
    let expected_md5 = format!("\"{:x}\"", md5::compute(content));

    let resp = client
        .put(format!("{}/sse-etag-bucket/file.txt", base_url))
        .header("x-amz-server-side-encryption", "AES256")
        .body(&content[..])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let put_etag = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        put_etag, expected_md5,
        "PUT ETag should be MD5 of plaintext"
    );

    // GET ETag should match
    let resp = client
        .get(format!("{}/sse-etag-bucket/file.txt", base_url))
        .send()
        .await
        .unwrap();
    let get_etag = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        get_etag, expected_md5,
        "GET ETag should be MD5 of plaintext"
    );

    // HEAD ETag should match
    let resp = client
        .head(format!("{}/sse-etag-bucket/file.txt", base_url))
        .send()
        .await
        .unwrap();
    let head_etag = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        head_etag, expected_md5,
        "HEAD ETag should be MD5 of plaintext"
    );

    cleanup(&tmp_dir);
}

// ==================== Multi-user tests ====================

#[tokio::test]
async fn test_multi_user_isolation() {
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let client = reqwest::Client::new();
    let host = base_url.strip_prefix("http://").unwrap();

    // Alice creates a bucket
    let resp = sign_request(
        client.put(format!("{}/alice-bucket", base_url)),
        "PUT",
        "/alice-bucket",
        "",
        host,
        b"",
        ALICE_ACCESS_KEY,
        ALICE_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);

    // Alice puts an object
    let resp = sign_request(
        client
            .put(format!("{}/alice-bucket/hello.txt", base_url))
            .body("hello from alice"),
        "PUT",
        "/alice-bucket/hello.txt",
        "",
        host,
        b"hello from alice",
        ALICE_ACCESS_KEY,
        ALICE_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);

    // Alice can read her own object
    let resp = sign_request(
        client.get(format!("{}/alice-bucket/hello.txt", base_url)),
        "GET",
        "/alice-bucket/hello.txt",
        "",
        host,
        b"",
        ALICE_ACCESS_KEY,
        ALICE_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "hello from alice");

    // Bob cannot read Alice's object (no policy)
    let resp = sign_request(
        client.get(format!("{}/alice-bucket/hello.txt", base_url)),
        "GET",
        "/alice-bucket/hello.txt",
        "",
        host,
        b"",
        BOB_ACCESS_KEY,
        BOB_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 403);

    // Bob cannot put into Alice's bucket
    let resp = sign_request(
        client
            .put(format!("{}/alice-bucket/bob.txt", base_url))
            .body("intruder"),
        "PUT",
        "/alice-bucket/bob.txt",
        "",
        host,
        b"intruder",
        BOB_ACCESS_KEY,
        BOB_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 403);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_multi_user_policy_grant() {
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let client = reqwest::Client::new();
    let host = base_url.strip_prefix("http://").unwrap();

    // Alice creates a bucket and puts an object
    sign_request(
        client.put(format!("{}/shared-bucket", base_url)),
        "PUT",
        "/shared-bucket",
        "",
        host,
        b"",
        ALICE_ACCESS_KEY,
        ALICE_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();

    sign_request(
        client
            .put(format!("{}/shared-bucket/file.txt", base_url))
            .body("shared data"),
        "PUT",
        "/shared-bucket/file.txt",
        "",
        host,
        b"shared data",
        ALICE_ACCESS_KEY,
        ALICE_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();

    // Bob can't read yet
    let resp = sign_request(
        client.get(format!("{}/shared-bucket/file.txt", base_url)),
        "GET",
        "/shared-bucket/file.txt",
        "",
        host,
        b"",
        BOB_ACCESS_KEY,
        BOB_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 403);

    // Alice grants Bob GetObject via bucket policy
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:loch:iam:::user/bob"},
            "Action": "s3:GetObject",
            "Resource": "arn:loch:s3:::shared-bucket/*"
        }]
    });
    let policy_bytes = serde_json::to_vec(&policy).unwrap();
    sign_request(
        client
            .put(format!("{}/shared-bucket?policy", base_url))
            .body(policy_bytes.clone()),
        "PUT",
        "/shared-bucket",
        "policy",
        host,
        &policy_bytes,
        ALICE_ACCESS_KEY,
        ALICE_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();

    // Now Bob can read
    let resp = sign_request(
        client.get(format!("{}/shared-bucket/file.txt", base_url)),
        "GET",
        "/shared-bucket/file.txt",
        "",
        host,
        b"",
        BOB_ACCESS_KEY,
        BOB_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "shared data");

    // Bob still can't write (only GetObject granted)
    let resp = sign_request(
        client
            .put(format!("{}/shared-bucket/bob.txt", base_url))
            .body("nope"),
        "PUT",
        "/shared-bucket/bob.txt",
        "",
        host,
        b"nope",
        BOB_ACCESS_KEY,
        BOB_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 403);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_root_access_all() {
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let client = reqwest::Client::new();
    let host = base_url.strip_prefix("http://").unwrap();

    // Alice creates a bucket and puts an object
    sign_request(
        client.put(format!("{}/alice-priv", base_url)),
        "PUT",
        "/alice-priv",
        "",
        host,
        b"",
        ALICE_ACCESS_KEY,
        ALICE_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();

    sign_request(
        client
            .put(format!("{}/alice-priv/secret.txt", base_url))
            .body("secret"),
        "PUT",
        "/alice-priv/secret.txt",
        "",
        host,
        b"secret",
        ALICE_ACCESS_KEY,
        ALICE_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();

    // Root can read Alice's object
    let resp = sign_request(
        client.get(format!("{}/alice-priv/secret.txt", base_url)),
        "GET",
        "/alice-priv/secret.txt",
        "",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "secret");

    // Root can delete Alice's bucket
    sign_request(
        client.delete(format!("{}/alice-priv/secret.txt", base_url)),
        "DELETE",
        "/alice-priv/secret.txt",
        "",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();

    let resp = sign_request(
        client.delete(format!("{}/alice-priv", base_url)),
        "DELETE",
        "/alice-priv",
        "",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 204);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_user_api_crud() {
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let client = reqwest::Client::new();

    // List users
    let resp = client
        .get(format!("{}/_loch/users", base_url))
        .header("Authorization", format!("Bearer {}", ADMIN_API_KEY))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let users = body["users"].as_array().unwrap();
    assert_eq!(users.len(), 3);
    // secret_access_key should NOT be in the response
    assert!(users[0].get("secret_access_key").is_none());

    // Get specific user
    let resp = client
        .get(format!("{}/_loch/users/alice", base_url))
        .header("Authorization", format!("Bearer {}", ADMIN_API_KEY))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["user_id"], "alice");
    assert_eq!(body["display_name"], "Alice");
    assert!(body.get("secret_access_key").is_none());

    // Create a new user
    let new_user = serde_json::json!({
        "display_name": "Charlie",
        "access_key_id": "AKIACHARLIE00000",
        "secret_access_key": "CharlieSecretKey123456789012345"
    });
    let resp = client
        .put(format!("{}/_loch/users/charlie", base_url))
        .header("Authorization", format!("Bearer {}", ADMIN_API_KEY))
        .json(&new_user)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Verify Charlie exists
    let resp = client
        .get(format!("{}/_loch/users", base_url))
        .header("Authorization", format!("Bearer {}", ADMIN_API_KEY))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["users"].as_array().unwrap().len(), 4);

    // Delete Charlie
    let resp = client
        .delete(format!("{}/_loch/users/charlie", base_url))
        .header("Authorization", format!("Bearer {}", ADMIN_API_KEY))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Cannot delete root
    let resp = client
        .delete(format!("{}/_loch/users/root", base_url))
        .header("Authorization", format!("Bearer {}", ADMIN_API_KEY))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_client_error());

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_user_api_requires_admin_key() {
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let client = reqwest::Client::new();

    // No auth header
    let resp = client
        .get(format!("{}/_loch/users", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Wrong key
    let resp = client
        .get(format!("{}/_loch/users", base_url))
        .header("Authorization", "Bearer wrong-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_anonymous_denied_when_users_configured() {
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let client = reqwest::Client::new();
    let host = base_url.strip_prefix("http://").unwrap();

    // Root creates a bucket and puts an object
    sign_request(
        client.put(format!("{}/private-bucket", base_url)),
        "PUT",
        "/private-bucket",
        "",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();

    sign_request(
        client
            .put(format!("{}/private-bucket/data.txt", base_url))
            .body("private"),
        "PUT",
        "/private-bucket/data.txt",
        "",
        host,
        b"private",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();

    // Anonymous GET should be denied (no public policy)
    let resp = client
        .get(format!("{}/private-bucket/data.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    cleanup(&tmp_dir);
}

// --- CLI tests ---

fn loch_s3_bin() -> std::path::PathBuf {
    std::env::var("CARGO_BIN_EXE_loch-s3")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let mut p = std::env::current_exe().expect("cannot determine test binary path");
            p.pop();
            if p.ends_with("deps") {
                p.pop();
            }
            // Unix only: no .exe suffix needed
            p.push("loch-s3");
            p
        })
}

#[tokio::test]
async fn test_cli_users_list() {
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let bin = loch_s3_bin();

    let output = tokio::process::Command::new(&bin)
        .args([
            "--server",
            &base_url,
            "--api-key",
            ADMIN_API_KEY,
            "users",
            "list",
        ])
        .output()
        .await
        .expect("failed to run loch-s3");

    assert!(
        output.status.success(),
        "exit code: {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid JSON");
    let users = parsed["users"]
        .as_array()
        .expect("response must have a 'users' array");
    assert!(!users.is_empty(), "expected at least one user");
    for u in users {
        assert!(u.get("secret_access_key").is_none(), "secret key leaked");
    }

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_cli_users_get() {
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let bin = loch_s3_bin();

    let output = tokio::process::Command::new(&bin)
        .args([
            "--server",
            &base_url,
            "--api-key",
            ADMIN_API_KEY,
            "users",
            "get",
            "alice",
        ])
        .output()
        .await
        .expect("failed to run loch-s3");

    assert!(output.status.success());
    let parsed: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout))
        .expect("stdout is valid JSON");
    assert_eq!(parsed["user_id"], "alice");
    assert_eq!(parsed["display_name"], "Alice");
    assert!(parsed.get("secret_access_key").is_none());

    // Non-existent user must exit with code 1
    let output = tokio::process::Command::new(&bin)
        .args([
            "--server",
            &base_url,
            "--api-key",
            ADMIN_API_KEY,
            "users",
            "get",
            "nobody",
        ])
        .output()
        .await
        .expect("failed to run loch-s3");
    assert!(!output.status.success());

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_cli_users_put_and_delete() {
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let bin = loch_s3_bin();

    // Create user
    let output = tokio::process::Command::new(&bin)
        .args([
            "--server",
            &base_url,
            "--api-key",
            ADMIN_API_KEY,
            "users",
            "put",
            "dave",
            "--display-name",
            "Dave",
            "--access-key",
            "AKIADAVE00000001",
            "--secret-key",
            "DaveSecretKey123456789012345678",
        ])
        .output()
        .await
        .expect("failed to run loch-s3");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify it appears in list
    let output = tokio::process::Command::new(&bin)
        .args([
            "--server",
            &base_url,
            "--api-key",
            ADMIN_API_KEY,
            "users",
            "list",
        ])
        .output()
        .await
        .expect("failed to run loch-s3");
    let parsed: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout))
        .expect("stdout is valid JSON");
    let ids: Vec<&str> = parsed["users"]
        .as_array()
        .expect("response must have a 'users' array")
        .iter()
        .map(|u| u["user_id"].as_str().expect("user_id is a string"))
        .collect();
    assert!(ids.contains(&"dave"));

    // Delete user
    let output = tokio::process::Command::new(&bin)
        .args([
            "--server",
            &base_url,
            "--api-key",
            ADMIN_API_KEY,
            "users",
            "delete",
            "dave",
        ])
        .output()
        .await
        .expect("failed to run loch-s3");
    assert!(output.status.success());

    // Verify deleted
    let output = tokio::process::Command::new(&bin)
        .args([
            "--server",
            &base_url,
            "--api-key",
            ADMIN_API_KEY,
            "users",
            "get",
            "dave",
        ])
        .output()
        .await
        .expect("failed to run loch-s3");
    assert!(!output.status.success());

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_cli_users_wrong_api_key() {
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let bin = loch_s3_bin();

    let output = tokio::process::Command::new(&bin)
        .args([
            "--server",
            &base_url,
            "--api-key",
            "wrong-key",
            "users",
            "list",
        ])
        .output()
        .await
        .expect("failed to run loch-s3");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("403"),
        "expected 403 in stderr, got: {}",
        stderr
    );

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_cli_users_env_vars() {
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let bin = loch_s3_bin();

    let output = tokio::process::Command::new(&bin)
        .env("LOCH_SERVER", &base_url)
        .env("LOCH_ADMIN_KEY", ADMIN_API_KEY)
        .args(["users", "list"])
        .output()
        .await
        .expect("failed to run loch-s3");

    assert!(output.status.success());
    let parsed: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout))
        .expect("stdout is valid JSON");
    assert!(
        !parsed["users"]
            .as_array()
            .expect("response must have a 'users' array")
            .is_empty(),
        "expected at least one user"
    );

    cleanup(&tmp_dir);
}

// ======== ListBuckets visibility tests ========

/// Helper: parse bucket names from a ListAllMyBucketsResult XML response.
fn parse_bucket_names(xml: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<Name>") {
        rest = &rest[start + "<Name>".len()..];
        if let Some(end) = rest.find("</Name>") {
            names.push(rest[..end].to_string());
            rest = &rest[end..];
        }
    }
    names
}

#[tokio::test]
async fn test_list_buckets_owner_only() {
    // A non-root user without any policy grants only sees their own buckets.
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let client = reqwest::Client::new();
    let host = base_url.strip_prefix("http://").unwrap();

    // Alice creates her bucket
    sign_request(
        client.put(format!("{}/alice-only", base_url)),
        "PUT",
        "/alice-only",
        "",
        host,
        b"",
        ALICE_ACCESS_KEY,
        ALICE_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();

    // Root creates a bucket (not shared)
    sign_request(
        client.put(format!("{}/root-private", base_url)),
        "PUT",
        "/root-private",
        "",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();

    // Alice's ListBuckets should contain only her bucket
    let resp = sign_request(
        client.get(&base_url),
        "GET",
        "/",
        "",
        host,
        b"",
        ALICE_ACCESS_KEY,
        ALICE_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    let buckets = parse_bucket_names(&resp.text().await.unwrap());
    assert!(
        buckets.contains(&"alice-only".to_string()),
        "Alice should see her own bucket"
    );
    assert!(
        !buckets.contains(&"root-private".to_string()),
        "Alice should not see root's bucket"
    );

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_list_buckets_shared_via_policy() {
    // A bucket shared with s3:ListBucket appears in the grantee's ListBuckets.
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let client = reqwest::Client::new();
    let host = base_url.strip_prefix("http://").unwrap();

    // Alice creates a bucket and uploads an object
    sign_request(
        client.put(format!("{}/shared-list", base_url)),
        "PUT",
        "/shared-list",
        "",
        host,
        b"",
        ALICE_ACCESS_KEY,
        ALICE_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();

    sign_request(
        client
            .put(format!("{}/shared-list/hello.txt", base_url))
            .body("hello"),
        "PUT",
        "/shared-list/hello.txt",
        "",
        host,
        b"hello",
        ALICE_ACCESS_KEY,
        ALICE_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();

    // Bob cannot see the bucket before policy is set
    let resp = sign_request(
        client.get(&base_url),
        "GET",
        "/",
        "",
        host,
        b"",
        BOB_ACCESS_KEY,
        BOB_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    let buckets = parse_bucket_names(&resp.text().await.unwrap());
    assert!(
        !buckets.contains(&"shared-list".to_string()),
        "Bob should not see the bucket before policy"
    );

    // Alice grants Bob s3:ListBucket + s3:GetObject
    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:loch:iam:::user/bob"},
            "Action": ["s3:ListBucket", "s3:GetObject"],
            "Resource": ["arn:loch:s3:::shared-list", "arn:loch:s3:::shared-list/*"]
        }]
    }"#;
    let resp = sign_request(
        client
            .put(format!("{}/shared-list?policy", base_url))
            .body(policy_json),
        "PUT",
        "/shared-list",
        "policy",
        host,
        policy_json.as_bytes(),
        ALICE_ACCESS_KEY,
        ALICE_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 204, "PUT policy should succeed");

    // Bob now sees the shared bucket in ListBuckets
    let resp = sign_request(
        client.get(&base_url),
        "GET",
        "/",
        "",
        host,
        b"",
        BOB_ACCESS_KEY,
        BOB_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    let buckets = parse_bucket_names(&resp.text().await.unwrap());
    assert!(
        buckets.contains(&"shared-list".to_string()),
        "Bob should see the shared bucket after policy"
    );

    // Bob can list objects in the shared bucket
    let resp = sign_request(
        client.get(format!("{}/shared-list", base_url)),
        "GET",
        "/shared-list",
        "",
        host,
        b"",
        BOB_ACCESS_KEY,
        BOB_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200, "Bob should be able to list objects");
    assert!(resp.text().await.unwrap().contains("hello.txt"));

    // Bob can read objects in the shared bucket
    let resp = sign_request(
        client.get(format!("{}/shared-list/hello.txt", base_url)),
        "GET",
        "/shared-list/hello.txt",
        "",
        host,
        b"",
        BOB_ACCESS_KEY,
        BOB_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "hello");

    // Bob cannot write (only read was granted)
    let resp = sign_request(
        client
            .put(format!("{}/shared-list/intruder.txt", base_url))
            .body("nope"),
        "PUT",
        "/shared-list/intruder.txt",
        "",
        host,
        b"nope",
        BOB_ACCESS_KEY,
        BOB_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 403, "Bob should not be able to write");

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_list_buckets_root_sees_all() {
    // Root always sees all buckets regardless of owner.
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let client = reqwest::Client::new();
    let host = base_url.strip_prefix("http://").unwrap();

    sign_request(
        client.put(format!("{}/alice-bucket2", base_url)),
        "PUT",
        "/alice-bucket2",
        "",
        host,
        b"",
        ALICE_ACCESS_KEY,
        ALICE_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();

    sign_request(
        client.put(format!("{}/bob-bucket2", base_url)),
        "PUT",
        "/bob-bucket2",
        "",
        host,
        b"",
        BOB_ACCESS_KEY,
        BOB_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();

    let resp = sign_request(
        client.get(&base_url),
        "GET",
        "/",
        "",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    let buckets = parse_bucket_names(&resp.text().await.unwrap());
    assert!(
        buckets.contains(&"alice-bucket2".to_string()),
        "Root should see Alice's bucket"
    );
    assert!(
        buckets.contains(&"bob-bucket2".to_string()),
        "Root should see Bob's bucket"
    );

    cleanup(&tmp_dir);
}

// ---- Storage quota (S3_MAX_STORAGE_BYTES) and health endpoint ----

/// Start a test server with a storage quota and an optional user store.
/// Mirrors main.rs startup: initial recount + background recount worker.
async fn start_server_with_quota_in(
    tmp_dir: std::path::PathBuf,
    max_bytes: Option<u64>,
    user_store: Option<Arc<RwLock<UserStore>>>,
) -> String {
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let storage = Arc::new(Storage::with_quota(tmp_dir.clone(), max_bytes));
    storage.quota.recount(&storage.data_dir).await;
    tokio::spawn(
        storage
            .quota
            .clone()
            .run_recount_worker(storage.data_dir.clone()),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(ServerConfig {
        storage,
        user_store,
        admin_api_key: None,
        upload_ttl_secs: 86400,
        encryption: None,
    });
    tokio::spawn(async move {
        s3::serve(listener, config).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    format!("http://127.0.0.1:{}", port)
}

async fn start_server_with_quota(max_bytes: Option<u64>) -> (String, std::path::PathBuf) {
    let tmp_dir = std::env::temp_dir().join(format!("s3-test-{}", uuid::Uuid::new_v4()));
    let url = start_server_with_quota_in(tmp_dir.clone(), max_bytes, None).await;
    (url, tmp_dir)
}

async fn health_json(client: &reqwest::Client, base_url: &str) -> serde_json::Value {
    let resp = client
        .get(format!("{}/_loch/health", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

/// Storage usage from /_loch/usage (open access: these servers have no user store).
async fn used_bytes(client: &reqwest::Client, base_url: &str) -> u64 {
    let resp = client
        .get(format!("{}/_loch/usage", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    json["used_bytes"].as_u64().unwrap()
}

/// Poll the health endpoint until `used_bytes` satisfies `pred` (background recount).
async fn wait_for_usage(
    client: &reqwest::Client,
    base_url: &str,
    pred: impl Fn(u64) -> bool,
) -> u64 {
    for _ in 0..50 {
        let used = used_bytes(client, base_url).await;
        if pred(used) {
            return used;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    used_bytes(client, base_url).await
}

fn count_tmp_files(dir: &std::path::Path) -> usize {
    let mut count = 0;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                count += count_tmp_files(&path);
            } else if entry.file_name().to_string_lossy().ends_with(".tmp") {
                count += 1;
            }
        }
    }
    count
}

/// Usage equals `expected` up to small internal metadata files (upload metadata, sidecars).
fn assert_near(used: u64, expected: u64) {
    assert!(
        used >= expected && used <= expected + 4096,
        "used = {used}, expected about {expected}"
    );
}

async fn assert_quota_exceeded(resp: reqwest::Response) {
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>QuotaExceeded</Code>"), "body: {body}");
}

#[tokio::test]
async fn test_health_endpoint() {
    let (base_url, tmp_dir) = start_server_with_quota(Some(1_000_000)).await;
    let client = reqwest::Client::new();

    client
        .put(format!("{}/secret-bucket-name", base_url))
        .send()
        .await
        .unwrap();
    client
        .put(format!("{}/secret-bucket-name/obj", base_url))
        .body("hello")
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!("{}/_loch/health", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/json"
    );
    let body = resp.text().await.unwrap();
    // No figures, no names: only the status and the quota state
    assert_eq!(body, r#"{"status":"ok","quota":"ok"}"#);

    // HEAD works too, other methods are rejected
    let resp = client
        .head(format!("{}/_loch/health", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .post(format!("{}/_loch/health", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 405);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_health_endpoint_without_auth_when_auth_enabled() {
    let creds = Credentials {
        access_key_id: TEST_ACCESS_KEY.to_string(),
        secret_access_key: TEST_SECRET_KEY.to_string(),
    };
    let (base_url, tmp_dir) = start_server_with_auth(Some(creds)).await;
    let client = reqwest::Client::new();

    // Regular S3 requests are denied anonymously...
    let resp = client.get(format!("{}/", base_url)).send().await.unwrap();
    assert_eq!(resp.status(), 403);

    // ...but the health probe is not
    let json = health_json(&client, &base_url).await;
    assert_eq!(json, serde_json::json!({"status": "ok"}));

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_quota_put_object_and_delete_frees_space() {
    let (base_url, tmp_dir) = start_server_with_quota(Some(1000)).await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/quota-bucket", base_url))
        .send()
        .await
        .unwrap();

    let resp = client
        .put(format!("{}/quota-bucket/a", base_url))
        .body(vec![b'a'; 600])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .put(format!("{}/quota-bucket/b", base_url))
        .body(vec![b'b'; 600])
        .send()
        .await
        .unwrap();
    assert_quota_exceeded(resp).await;

    // The refused object does not exist and left no temporary file
    let resp = client
        .get(format!("{}/quota-bucket/b", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    assert_eq!(count_tmp_files(&tmp_dir), 0);
    assert_eq!(used_bytes(&client, &base_url).await, 600);

    // Deleting frees space immediately
    let resp = client
        .delete(format!("{}/quota-bucket/a", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(used_bytes(&client, &base_url).await, 0);

    let resp = client
        .put(format!("{}/quota-bucket/b", base_url))
        .body(vec![b'b'; 600])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Overwriting releases the previous size
    let resp = client
        .put(format!("{}/quota-bucket/b", base_url))
        .body(vec![b'c'; 300])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(used_bytes(&client, &base_url).await, 300);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_quota_concurrent_uploads_cannot_exceed_limit() {
    let limit = 1_000_000u64;
    let (base_url, tmp_dir) = start_server_with_quota(Some(limit)).await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/quota-bucket", base_url))
        .send()
        .await
        .unwrap();

    // 8 concurrent uploads of 300 KB: at most 3 fit in 1 MB
    let mut handles = Vec::new();
    for i in 0..8 {
        let client = client.clone();
        let url = format!("{}/quota-bucket/obj-{}", base_url, i);
        handles.push(tokio::spawn(async move {
            match client.put(url).body(vec![b'x'; 300_000]).send().await {
                Ok(resp) => resp.status().as_u16(),
                Err(_) => 0,
            }
        }));
    }
    let mut ok = 0;
    for h in handles {
        let status = h.await.unwrap();
        assert!(status == 200 || status == 403, "unexpected status {status}");
        if status == 200 {
            ok += 1;
        }
    }
    assert_eq!(ok, 3);

    let used = used_bytes(&client, &base_url).await;
    assert_eq!(used, 900_000);
    assert!(used <= limit);
    assert_eq!(count_tmp_files(&tmp_dir), 0);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_quota_streaming_upload_stops_early() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (base_url, tmp_dir) = start_server_with_quota(Some(1024 * 1024)).await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/quota-bucket", base_url))
        .send()
        .await
        .unwrap();

    // Raw HTTP/1.1 chunked upload without Content-Length: the server only learns
    // the size while streaming. Try to send 256 MiB.
    let addr = base_url.trim_start_matches("http://").to_string();
    let stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let (mut reader, mut writer) = stream.into_split();
    let total: u64 = 256 * 1024 * 1024;
    let writer_task = tokio::spawn(async move {
        let head = format!(
            "PUT /quota-bucket/big HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\n\r\n",
            addr
        );
        writer.write_all(head.as_bytes()).await.unwrap();
        let chunk = vec![b'z'; 64 * 1024];
        let mut sent: u64 = 0;
        while sent < total {
            let frame = [
                format!("{:x}\r\n", chunk.len()).into_bytes(),
                chunk.clone(),
                b"\r\n".to_vec(),
            ]
            .concat();
            if writer.write_all(&frame).await.is_err() {
                break;
            }
            sent += chunk.len() as u64;
        }
        sent
    });

    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    let read = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    response.extend_from_slice(&buf[..n]);
                    if String::from_utf8_lossy(&response).contains("</Error>") {
                        break;
                    }
                }
            }
        }
    })
    .await;
    assert!(
        read.is_ok(),
        "server did not answer while the upload was in progress"
    );
    let response = String::from_utf8_lossy(&response).to_string();
    assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");
    assert!(response.contains("QuotaExceeded"));
    drop(reader);

    let sent = writer_task.await.unwrap();
    assert!(
        sent < total,
        "the server should stop reading before the end"
    );

    // Nothing stored, nothing reserved, no temporary file left
    let resp = client
        .get(format!("{}/quota-bucket/big", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    assert_eq!(used_bytes(&client, &base_url).await, 0);
    assert_eq!(count_tmp_files(&tmp_dir), 0);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_quota_multipart_upload_exceeds() {
    let mib = 1024 * 1024;
    let (base_url, tmp_dir) = start_server_with_quota(Some(12 * mib)).await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/mp-bucket", base_url))
        .send()
        .await
        .unwrap();

    let start = |key: &'static str| {
        let client = client.clone();
        let base_url = base_url.clone();
        async move {
            let resp = client
                .post(format!("{}/mp-bucket/{}?uploads", base_url, key))
                .send()
                .await
                .unwrap();
            extract_xml_value(&resp.text().await.unwrap(), "UploadId")
        }
    };
    let upload_part = |key: &'static str, upload_id: String, n: u32, size: u64| {
        let client = client.clone();
        let base_url = base_url.clone();
        async move {
            client
                .put(format!(
                    "{}/mp-bucket/{}?partNumber={}&uploadId={}",
                    base_url, key, n, upload_id
                ))
                .body(vec![b'p'; size as usize])
                .send()
                .await
                .unwrap()
        }
    };

    // Parts count toward the quota while the upload is in progress
    let upload_id = start("big").await;
    let mut etags = Vec::new();
    for n in 1..=2 {
        let resp = upload_part("big", upload_id.clone(), n, 5 * mib).await;
        assert_eq!(resp.status(), 200);
        etags.push(resp.headers()["etag"].to_str().unwrap().to_string());
    }
    assert_near(used_bytes(&client, &base_url).await, 10 * mib);

    let resp = upload_part("big", upload_id.clone(), 3, 5 * mib).await;
    assert_quota_exceeded(resp).await;
    assert_near(used_bytes(&client, &base_url).await, 10 * mib);
    assert_eq!(count_tmp_files(&tmp_dir), 0);

    // Completing with the two accepted parts is space-neutral
    let complete_xml = format!(
        "<CompleteMultipartUpload>\
           <Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part>\
           <Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part>\
         </CompleteMultipartUpload>",
        etags[0], etags[1]
    );
    let resp = client
        .post(format!("{}/mp-bucket/big?uploadId={}", base_url, upload_id))
        .body(complete_xml)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let used = used_bytes(&client, &base_url).await;
    assert_near(used, 10 * mib);

    // Aborting a second upload releases its parts
    let upload_id = start("other").await;
    let resp = upload_part("other", upload_id.clone(), 1, mib).await;
    assert_eq!(resp.status(), 200);
    assert_near(used_bytes(&client, &base_url).await, 11 * mib);
    let resp = client
        .delete(format!(
            "{}/mp-bucket/other?uploadId={}",
            base_url, upload_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_near(used_bytes(&client, &base_url).await, 10 * mib);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_quota_copy_object() {
    let (base_url, tmp_dir) = start_server_with_quota(Some(1000)).await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/quota-bucket", base_url))
        .send()
        .await
        .unwrap();
    let resp = client
        .put(format!("{}/quota-bucket/src", base_url))
        .body(vec![b's'; 600])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .put(format!("{}/quota-bucket/dst", base_url))
        .header("x-amz-copy-source", "/quota-bucket/src")
        .send()
        .await
        .unwrap();
    assert_quota_exceeded(resp).await;
    assert_eq!(used_bytes(&client, &base_url).await, 600);
    assert_eq!(count_tmp_files(&tmp_dir), 0);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_quota_counts_versions() {
    let (base_url, tmp_dir) = start_server_with_quota(Some(1000)).await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/ver-bucket", base_url))
        .send()
        .await
        .unwrap();
    client
        .put(format!("{}/ver-bucket?versioning", base_url))
        .body("<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>")
        .send()
        .await
        .unwrap();

    // A versioned object is stored twice (current copy + version)
    let resp = client
        .put(format!("{}/ver-bucket/obj", base_url))
        .body(vec![b'v'; 300])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let used = wait_for_usage(&client, &base_url, |u| u >= 600).await;
    assert!(used >= 600, "used = {used}");

    // A new version of 300 bytes needs 600 more: refused
    let resp = client
        .put(format!("{}/ver-bucket/obj", base_url))
        .body(vec![b'w'; 300])
        .send()
        .await
        .unwrap();
    assert_quota_exceeded(resp).await;

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_quota_initialized_from_existing_data() {
    let tmp_dir = std::env::temp_dir().join(format!("s3-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(tmp_dir.join("existing-bucket")).unwrap();
    std::fs::write(tmp_dir.join("existing-bucket/file"), vec![0u8; 700]).unwrap();
    // In-flight temporary files are not counted
    std::fs::create_dir_all(tmp_dir.join(".loch-tmp")).unwrap();
    std::fs::write(tmp_dir.join(".loch-tmp/abc.tmp"), vec![0u8; 5000]).unwrap();

    let base_url = start_server_with_quota_in(tmp_dir.clone(), Some(1000), None).await;
    let client = reqwest::Client::new();
    assert_eq!(used_bytes(&client, &base_url).await, 700);

    let resp = client
        .put(format!("{}/existing-bucket/new", base_url))
        .body(vec![b'n'; 400])
        .send()
        .await
        .unwrap();
    assert_quota_exceeded(resp).await;

    cleanup(&tmp_dir);
}

// ---- Read-only users file (managed deployments) ----

/// With the admin API disabled, the server never writes the users file:
/// a 0400 file is accepted, used for auth, and left untouched.
#[cfg(unix)]
#[tokio::test]
async fn test_read_only_users_file_is_never_written() {
    use std::os::unix::fs::PermissionsExt;

    let tmp_dir = std::env::temp_dir().join(format!("s3-test-{}", uuid::Uuid::new_v4()));
    let conf_dir = tmp_dir.join("conf");
    std::fs::create_dir_all(&conf_dir).unwrap();
    let users_file = conf_dir.join("users.json");
    let users_json = serde_json::json!({
        "users": [
            {
                "user_id": "root",
                "display_name": "Root",
                "access_key_id": TEST_ACCESS_KEY,
                "secret_access_key": TEST_SECRET_KEY,
                "is_root": true
            },
            {
                "user_id": "reader",
                "display_name": "Reader",
                "access_key_id": BOB_ACCESS_KEY,
                "secret_access_key": BOB_SECRET_KEY
            }
        ]
    });
    let original = serde_json::to_string_pretty(&users_json).unwrap();
    std::fs::write(&users_file, &original).unwrap();
    std::fs::set_permissions(&users_file, std::fs::Permissions::from_mode(0o400)).unwrap();
    std::fs::set_permissions(&conf_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let mtime = std::fs::metadata(&users_file).unwrap().modified().unwrap();

    let store = UserStore::load_from_file(&users_file).unwrap();
    let base_url = start_server_with_quota_in(
        tmp_dir.join("data"),
        None,
        Some(Arc::new(RwLock::new(store))),
    )
    .await;
    let client = reqwest::Client::new();
    let host = base_url.trim_start_matches("http://");

    // Root creates a bucket and an object
    sign_request(
        client.put(format!("{}/managed-bucket", base_url)),
        "PUT",
        "/managed-bucket",
        "",
        host,
        b"",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    let resp = sign_request(
        client
            .put(format!("{}/managed-bucket/file.txt", base_url))
            .body("data"),
        "PUT",
        "/managed-bucket/file.txt",
        "",
        host,
        b"data",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);

    // Read-only key for a non-root user through a bucket policy
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:loch:iam:::user/reader"},
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": ["arn:loch:s3:::managed-bucket", "arn:loch:s3:::managed-bucket/*"]
        }]
    });
    let policy_bytes = serde_json::to_vec(&policy).unwrap();
    let resp = sign_request(
        client
            .put(format!("{}/managed-bucket?policy", base_url))
            .body(policy_bytes.clone()),
        "PUT",
        "/managed-bucket",
        "policy",
        host,
        &policy_bytes,
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert!(resp.status().is_success());

    let resp = sign_request(
        client.get(format!("{}/managed-bucket/file.txt", base_url)),
        "GET",
        "/managed-bucket/file.txt",
        "",
        host,
        b"",
        BOB_ACCESS_KEY,
        BOB_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "data");

    let resp = sign_request(
        client
            .put(format!("{}/managed-bucket/nope.txt", base_url))
            .body("nope"),
        "PUT",
        "/managed-bucket/nope.txt",
        "",
        host,
        b"nope",
        BOB_ACCESS_KEY,
        BOB_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 403);

    // The user management API is disabled without S3_ADMIN_API_KEY
    let resp = client
        .put(format!("{}/_loch/users/eve", base_url))
        .bearer_auth("anything")
        .body(r#"{"display_name":"Eve","access_key_id":"AKIAEVE","secret_access_key":"secret"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // The users file is unchanged
    assert_eq!(std::fs::read_to_string(&users_file).unwrap(), original);
    assert_eq!(
        std::fs::metadata(&users_file).unwrap().modified().unwrap(),
        mtime
    );
    let dir_entries: Vec<_> = std::fs::read_dir(&conf_dir).unwrap().flatten().collect();
    assert_eq!(dir_entries.len(), 1);

    std::fs::set_permissions(&conf_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    cleanup(&tmp_dir);
}

/// A missing users file in a read-only directory makes startup fail
/// (no open access, no in-memory root account).
#[cfg(unix)]
#[test]
fn test_missing_users_file_in_read_only_dir_fails_startup() {
    use std::os::unix::fs::PermissionsExt;

    let tmp_dir = std::env::temp_dir().join(format!("s3-test-{}", uuid::Uuid::new_v4()));
    let conf_dir = tmp_dir.join("conf");
    std::fs::create_dir_all(&conf_dir).unwrap();
    std::fs::set_permissions(&conf_dir, std::fs::Permissions::from_mode(0o500)).unwrap();

    // Running as root bypasses permissions: nothing to verify then
    if std::fs::write(conf_dir.join("probe"), b"").is_ok() {
        std::fs::set_permissions(&conf_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        cleanup(&tmp_dir);
        return;
    }

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_s3"))
        .env("S3_USERS_FILE", conf_dir.join("users.json"))
        .env("S3_DATA_DIR", tmp_dir.join("data"))
        .env("S3_PORT", "0")
        .env_remove("S3_ACCESS_KEY_ID")
        .env_remove("S3_SECRET_ACCESS_KEY")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Invalid configuration"), "stderr: {stderr}");
    assert!(!conf_dir.join("users.json").exists());

    std::fs::set_permissions(&conf_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    cleanup(&tmp_dir);
}

// ---- Security regressions ----

/// Send a signed request as the given user.
async fn signed(
    client: &reqwest::Client,
    base_url: &str,
    method: reqwest::Method,
    path: &str,
    query: &str,
    body: &[u8],
    headers: &[(&str, &str)],
    keys: (&str, &str),
) -> reqwest::Response {
    let host = base_url.trim_start_matches("http://");
    let url = if query.is_empty() {
        format!("{}{}", base_url, path)
    } else {
        format!("{}{}?{}", base_url, path, query)
    };
    sign_request_with_headers(
        client.request(method.clone(), url).body(body.to_vec()),
        method.as_str(),
        path,
        query,
        host,
        body,
        headers,
        keys.0,
        keys.1,
    )
    .send()
    .await
    .unwrap()
}

const ALICE: (&str, &str) = (ALICE_ACCESS_KEY, ALICE_SECRET_KEY);
const BOB: (&str, &str) = (BOB_ACCESS_KEY, BOB_SECRET_KEY);

/// alice owns alice-b with a private secret.txt, bob owns bob-b.
async fn setup_alice_and_bob(client: &reqwest::Client, base_url: &str) {
    use reqwest::Method;
    let r = signed(
        client,
        base_url,
        Method::PUT,
        "/alice-b",
        "",
        b"",
        &[],
        ALICE,
    )
    .await;
    assert_eq!(r.status(), 200);
    let r = signed(
        client,
        base_url,
        Method::PUT,
        "/alice-b/secret.txt",
        "",
        b"alice secret",
        &[],
        ALICE,
    )
    .await;
    assert_eq!(r.status(), 200);
    let r = signed(client, base_url, Method::PUT, "/bob-b", "", b"", &[], BOB).await;
    assert_eq!(r.status(), 200);
}

#[tokio::test]
async fn test_security_copy_object_requires_read_access_on_source() {
    use reqwest::Method;
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let client = reqwest::Client::new();
    setup_alice_and_bob(&client, &base_url).await;

    // Direct GET is denied
    let r = signed(
        &client,
        &base_url,
        Method::GET,
        "/alice-b/secret.txt",
        "",
        b"",
        &[],
        BOB,
    )
    .await;
    assert_eq!(r.status(), 403);

    // Copy into bob's own bucket must be denied too
    for source in [
        "/alice-b/secret.txt",
        "alice-b/secret.txt",
        "/alice-b/secret%2Etxt",
    ] {
        let r = signed(
            &client,
            &base_url,
            Method::PUT,
            "/bob-b/stolen.txt",
            "",
            b"",
            &[("x-amz-copy-source", source)],
            BOB,
        )
        .await;
        assert_eq!(r.status(), 403, "copy from {source} should be denied");
    }
    let r = signed(
        &client,
        &base_url,
        Method::GET,
        "/bob-b/stolen.txt",
        "",
        b"",
        &[],
        BOB,
    )
    .await;
    assert_eq!(r.status(), 404);

    // Same with a versionId
    let r = signed(
        &client,
        &base_url,
        Method::PUT,
        "/alice-b",
        "versioning",
        b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
        &[],
        ALICE,
    )
    .await;
    assert_eq!(r.status(), 200);
    let r = signed(
        &client,
        &base_url,
        Method::PUT,
        "/alice-b/secret.txt",
        "",
        b"alice secret v2",
        &[],
        ALICE,
    )
    .await;
    let vid = r.headers()["x-amz-version-id"]
        .to_str()
        .unwrap()
        .to_string();
    let source = format!("/alice-b/secret.txt?versionId={}", vid);
    let r = signed(
        &client,
        &base_url,
        Method::PUT,
        "/bob-b/stolen.txt",
        "",
        b"",
        &[("x-amz-copy-source", &source)],
        BOB,
    )
    .await;
    assert_eq!(r.status(), 403);
    let r = signed(
        &client,
        &base_url,
        Method::GET,
        "/bob-b/stolen.txt",
        "",
        b"",
        &[],
        BOB,
    )
    .await;
    assert_eq!(r.status(), 404);

    // Once alice grants GetObject through a policy, the copy is allowed
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:loch:iam:::user/bob"},
            "Action": "s3:GetObject",
            "Resource": "arn:loch:s3:::alice-b/*"
        }]
    });
    let policy = serde_json::to_vec(&policy).unwrap();
    let r = signed(
        &client,
        &base_url,
        Method::PUT,
        "/alice-b",
        "policy",
        &policy,
        &[],
        ALICE,
    )
    .await;
    assert!(r.status().is_success());
    let r = signed(
        &client,
        &base_url,
        Method::PUT,
        "/bob-b/granted.txt",
        "",
        b"",
        &[("x-amz-copy-source", "/alice-b/secret.txt")],
        BOB,
    )
    .await;
    assert_eq!(r.status(), 200);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_security_copy_source_header_must_be_signed() {
    use reqwest::Method;
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let client = reqwest::Client::new();
    setup_alice_and_bob(&client, &base_url).await;
    let host = base_url.trim_start_matches("http://");

    // Alice hands out a presigned PUT URL for an upload into her bucket. The holder
    // must not turn it into a copy of another of her objects.
    let url = sign_presigned_url(
        &base_url,
        "PUT",
        "/alice-b/upload.txt",
        host,
        300,
        ALICE_ACCESS_KEY,
        ALICE_SECRET_KEY,
    );
    let r = client
        .put(&url)
        .header("x-amz-copy-source", "/alice-b/secret.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    // The regular presigned upload still works
    let r = client.put(&url).body("uploaded").send().await.unwrap();
    assert_eq!(r.status(), 200);

    // Header-signed request with an unsigned x-amz-copy-source header
    let r = sign_request(
        client
            .put(format!("{}/alice-b/copy.txt", base_url))
            .header("x-amz-copy-source", "/alice-b/secret.txt"),
        "PUT",
        "/alice-b/copy.txt",
        "",
        host,
        b"",
        ALICE_ACCESS_KEY,
        ALICE_SECRET_KEY,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(r.status(), 403);

    // Signed copy-source header is accepted
    let r = signed(
        &client,
        &base_url,
        Method::PUT,
        "/alice-b/copy.txt",
        "",
        b"",
        &[("x-amz-copy-source", "/alice-b/secret.txt")],
        ALICE,
    )
    .await;
    assert_eq!(r.status(), 200);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_security_upload_id_path_traversal() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    for b in ["victim-b", "attacker-b"] {
        client
            .put(format!("{}/{}", base_url, b))
            .send()
            .await
            .unwrap();
    }
    client
        .put(format!("{}/victim-b/precious.txt", base_url))
        .body("precious")
        .send()
        .await
        .unwrap();
    let r = client
        .post(format!("{}/attacker-b/x?uploads", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    for upload_id in ["../../victim-b", "..%2F..%2Fvictim-b", "../..", "..", "."] {
        let r = client
            .delete(format!("{}/attacker-b/x?uploadId={}", base_url, upload_id))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "abort with uploadId={upload_id}");
        let r = client
            .put(format!(
                "{}/attacker-b/x?partNumber=1&uploadId={}",
                base_url, upload_id
            ))
            .body("part")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "upload part with uploadId={upload_id}");
        let r = client
            .get(format!("{}/attacker-b/x?uploadId={}", base_url, upload_id))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "list parts with uploadId={upload_id}");
        let r = client
            .post(format!("{}/attacker-b/x?uploadId={}", base_url, upload_id))
            .body("<CompleteMultipartUpload></CompleteMultipartUpload>")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "complete with uploadId={upload_id}");
    }

    let r = client
        .get(format!("{}/victim-b/precious.txt", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "precious");
    assert!(tmp_dir.join("victim-b").is_dir());

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_security_version_id_path_traversal() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    for b in ["victim-b", "attacker-b"] {
        client
            .put(format!("{}/{}", base_url, b))
            .send()
            .await
            .unwrap();
    }
    client
        .put(format!("{}/victim-b/report.data", base_url))
        .body("report")
        .send()
        .await
        .unwrap();
    client
        .put(format!("{}/attacker-b?versioning", base_url))
        .body("<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>")
        .send()
        .await
        .unwrap();
    client
        .put(format!("{}/attacker-b/x", base_url))
        .body("x")
        .send()
        .await
        .unwrap();

    for vid in [
        "../../../victim-b/report",
        "..%2F..%2F..%2Fvictim-b%2Freport",
        "../x",
        "00000000000000-0000000",
    ] {
        let r = client
            .delete(format!("{}/attacker-b/x?versionId={}", base_url, vid))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "delete versionId={vid}");
        let r = client
            .get(format!("{}/attacker-b/x?versionId={}", base_url, vid))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "get versionId={vid}");
        let r = client
            .head(format!("{}/attacker-b/x?versionId={}", base_url, vid))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "head versionId={vid}");
        let r = client
            .put(format!("{}/attacker-b/copy", base_url))
            .header(
                "x-amz-copy-source",
                format!("/attacker-b/x?versionId={}", vid),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "copy versionId={vid}");
    }

    let r = client
        .get(format!("{}/victim-b/report.data", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "report");

    cleanup(&tmp_dir);
}

/// Request logs must not contain credentials: admin Bearer key, SigV4
/// signatures (header or presigned query) or SSE-C customer keys.
#[test]
fn test_security_logs_contain_no_secrets() {
    use std::io::Read;

    let tmp_dir = std::env::temp_dir().join(format!("s3-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let admin_key = "admin-key-that-must-not-leak-0123456789";
    let mut port = port;
    let mut child = None;
    for _ in 0..5 {
        let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_s3"))
            .env("S3_PORT", port.to_string())
            .env("S3_DATA_DIR", tmp_dir.join("data"))
            .env("S3_ACCESS_KEY_ID", TEST_ACCESS_KEY)
            .env("S3_SECRET_ACCESS_KEY", TEST_SECRET_KEY)
            .env("S3_ADMIN_API_KEY", admin_key)
            .env_remove("S3_USERS_FILE")
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        if c.try_wait().unwrap().is_none() {
            child = Some(c);
            break;
        }
        // Port taken by another test in the meantime: pick another one
        port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
    }
    let mut child = child.expect("server did not start");

    let base_url = format!("http://127.0.0.1:{}", port);
    let host = format!("127.0.0.1:{}", port);
    let (_, sse_key_b64, sse_key_md5) = generate_customer_key();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let signatures = rt.block_on(async {
        let client = reqwest::Client::new();
        for _ in 0..50 {
            if client
                .get(format!("{}/_loch/health", base_url))
                .send()
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        let mut signatures = Vec::new();
        client
            .get(format!("{}/_loch/users", base_url))
            .bearer_auth(admin_key)
            .send()
            .await
            .unwrap();

        let req = sign_request(
            client.put(format!("{}/log-bucket", base_url)),
            "PUT",
            "/log-bucket",
            "",
            &host,
            b"",
            TEST_ACCESS_KEY,
            TEST_SECRET_KEY,
        )
        .build()
        .unwrap();
        let auth = req.headers()["authorization"].to_str().unwrap().to_string();
        signatures.push(auth.rsplit("Signature=").next().unwrap().to_string());
        assert_eq!(client.execute(req).await.unwrap().status(), 200);

        let r = signed(
            &client,
            &base_url,
            reqwest::Method::PUT,
            "/log-bucket/ssec.txt",
            "",
            b"secret body",
            &[
                ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
                ("x-amz-server-side-encryption-customer-key", &sse_key_b64),
                (
                    "x-amz-server-side-encryption-customer-key-md5",
                    &sse_key_md5,
                ),
            ],
            (TEST_ACCESS_KEY, TEST_SECRET_KEY),
        )
        .await;
        assert_eq!(r.status(), 200);

        let url = sign_presigned_url(
            &base_url,
            "GET",
            "/log-bucket/ssec.txt",
            &host,
            300,
            TEST_ACCESS_KEY,
            TEST_SECRET_KEY,
        );
        signatures.push(url.rsplit("X-Amz-Signature=").next().unwrap().to_string());
        client.get(&url).send().await.unwrap();
        signatures
    });

    let _ = child.kill();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let _ = child.wait();

    assert!(
        stderr.contains("PUT /log-bucket/ssec.txt"),
        "stderr: {stderr}"
    );
    for secret in [admin_key, &sse_key_b64, TEST_SECRET_KEY] {
        assert!(!stderr.contains(secret), "secret leaked in logs: {secret}");
    }
    for sig in &signatures {
        assert!(!stderr.contains(sig.as_str()), "signature leaked in logs");
    }
    assert!(!stderr.to_lowercase().contains("authorization"));
    assert!(!stderr.contains("X-Amz-Signature"));

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_health_reports_quota_exceeded_without_figures() {
    let tmp_dir = std::env::temp_dir().join(format!("s3-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(tmp_dir.join("full-bucket")).unwrap();
    std::fs::write(tmp_dir.join("full-bucket/file"), vec![0u8; 2000]).unwrap();
    let base_url = start_server_with_quota_in(tmp_dir.clone(), Some(1000), None).await;
    let client = reqwest::Client::new();
    let json = health_json(&client, &base_url).await;
    assert_eq!(
        json,
        serde_json::json!({"status": "ok", "quota": "exceeded"})
    );
    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_usage_endpoint_is_root_only() {
    use reqwest::Method;
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let client = reqwest::Client::new();

    let r = client
        .get(format!("{}/_loch/usage", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = signed(
        &client,
        &base_url,
        Method::GET,
        "/_loch/usage",
        "",
        b"",
        &[],
        ALICE,
    )
    .await;
    assert_eq!(r.status(), 403);
    let r = signed(
        &client,
        &base_url,
        Method::GET,
        "/_loch/usage",
        "",
        b"",
        &[],
        (TEST_ACCESS_KEY, TEST_SECRET_KEY),
    )
    .await;
    assert_eq!(r.status(), 200);
    let json: serde_json::Value = r.json().await.unwrap();
    assert!(json["used_bytes"].is_u64());
    assert!(json["reserved_bytes"].is_u64());
    assert!(json["limit_bytes"].is_null());

    cleanup(&tmp_dir);
}

/// Run the server binary until its health endpoint answers, then stop it.
/// Returns (exit status if it exited by itself, stderr).
fn run_server_briefly(envs: &[(&str, String)]) -> (Option<std::process::ExitStatus>, String) {
    // The port is picked by binding then releasing it: another test may grab it
    // in between, so retry on "Address already in use".
    for _ in 0..5 {
        let (exited, stderr) = run_server_briefly_once(envs);
        if !stderr.contains("Address already in use") {
            return (exited, stderr);
        }
    }
    panic!("could not find a free port");
}

fn run_server_briefly_once(envs: &[(&str, String)]) -> (Option<std::process::ExitStatus>, String) {
    use std::io::Read;
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_s3"));
    cmd.env("S3_PORT", port.to_string())
        .env_remove("S3_USERS_FILE")
        .env_remove("S3_ACCESS_KEY_ID")
        .env_remove("S3_SECRET_ACCESS_KEY")
        .env_remove("S3_INIT_BUCKETS")
        .env_remove("S3_ENCRYPTION_KEY")
        .env_remove("S3_ENCRYPTION_KEY_FILE")
        .env_remove("S3_ENCRYPT_BY_DEFAULT")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let mut exited = None;
    for _ in 0..100 {
        if let Some(status) = child.try_wait().unwrap() {
            exited = Some(status);
            break;
        }
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if exited.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    (exited, stderr)
}

#[test]
fn test_init_buckets_created_owned_by_root_and_idempotent() {
    let tmp_dir = std::env::temp_dir().join(format!("s3-test-{}", uuid::Uuid::new_v4()));
    let data = tmp_dir.join("data");
    std::fs::create_dir_all(data.join("existing-b")).unwrap();
    let existing_meta = r#"{"created":"2020-01-01T00:00:00.000Z","owner":"alice"}"#;
    std::fs::write(data.join("existing-b/.metadata"), existing_meta).unwrap();
    std::fs::write(data.join("existing-b/keep.txt"), "keep").unwrap();
    let users_file = tmp_dir.join("users.json");
    std::fs::write(
        &users_file,
        serde_json::json!({"users": [{
            "user_id": "panel-root",
            "display_name": "Root",
            "access_key_id": TEST_ACCESS_KEY,
            "secret_access_key": TEST_SECRET_KEY,
            "is_root": true
        }]})
        .to_string(),
    )
    .unwrap();

    let envs = [
        ("S3_DATA_DIR", data.to_string_lossy().to_string()),
        ("S3_USERS_FILE", users_file.to_string_lossy().to_string()),
        (
            "S3_INIT_BUCKETS",
            " media , existing-b,media,backups ".to_string(),
        ),
    ];
    for _ in 0..2 {
        let (exited, stderr) = run_server_briefly(&envs);
        assert!(exited.is_none(), "server exited: {stderr}");
    }

    for b in ["media", "backups"] {
        let meta: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(data.join(b).join(".metadata")).unwrap())
                .unwrap();
        assert_eq!(meta["owner"], "panel-root", "bucket {b}");
    }
    // Existing bucket untouched
    assert_eq!(
        std::fs::read_to_string(data.join("existing-b/.metadata")).unwrap(),
        existing_meta
    );
    assert_eq!(
        std::fs::read_to_string(data.join("existing-b/keep.txt")).unwrap(),
        "keep"
    );

    cleanup(&tmp_dir);
}

#[test]
fn test_init_buckets_invalid_name_fails_startup() {
    let tmp_dir = std::env::temp_dir().join(format!("s3-test-{}", uuid::Uuid::new_v4()));
    for bad in ["ok-bucket,Bad_Name", "ab", "../etc"] {
        let (exited, stderr) = run_server_briefly(&[
            (
                "S3_DATA_DIR",
                tmp_dir.join("data").to_string_lossy().to_string(),
            ),
            ("S3_INIT_BUCKETS", bad.to_string()),
        ]);
        let status = exited.expect("server should exit");
        assert!(!status.success());
        assert!(stderr.contains("S3_INIT_BUCKETS"), "stderr: {stderr}");
    }
    assert!(!tmp_dir.join("data/ok-bucket").exists());
    cleanup(&tmp_dir);
}

/// Large aws-chunked upload with a trailing checksum, as sent by recent AWS SDKs:
/// decoded on the fly, stored byte for byte.
#[tokio::test]
async fn test_aws_chunked_streaming_upload_with_trailer() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/chunked-b", base_url))
        .send()
        .await
        .unwrap();

    let payload: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    let mut body = Vec::new();
    for chunk in payload.chunks(65_536) {
        body.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        body.extend_from_slice(chunk);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n");

    let resp = client
        .put(format!("{}/chunked-b/obj", base_url))
        .header("content-encoding", "aws-chunked")
        .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
        .header("x-amz-decoded-content-length", payload.len().to_string())
        .header("x-amz-trailer", "x-amz-checksum-crc32")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let got = client
        .get(format!("{}/chunked-b/obj", base_url))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(got.len(), payload.len());
    assert!(got.as_ref() == payload.as_slice());

    cleanup(&tmp_dir);
}

// ---- Range requests ----

/// Deterministic payload spanning several 1 MiB encryption chunks.
fn range_payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 7 + i / 1000) % 256) as u8).collect()
}

/// GET `url` with `Range: range` and the given extra headers.
async fn get_range(
    client: &reqwest::Client,
    url: &str,
    range: &str,
    headers: &[(&str, &str)],
) -> reqwest::Response {
    let mut req = client.get(url).header("range", range);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    req.send().await.unwrap()
}

/// Check the three range forms, clamping and 416 against `payload`.
async fn check_ranges(
    client: &reqwest::Client,
    url: &str,
    payload: &[u8],
    headers: &[(&str, &str)],
) {
    let total = payload.len() as u64;
    let cases: Vec<(String, u64, u64)> = vec![
        ("bytes=0-9".into(), 0, 9),
        ("bytes=1048570-1048590".into(), 1_048_570, 1_048_590), // across a 1 MiB chunk boundary
        (format!("bytes={}-", total - 100), total - 100, total - 1),
        ("bytes=-5".into(), total - 5, total - 1),
        (format!("bytes=-{}", total + 10), 0, total - 1),
        (
            format!("bytes=2097152-{}", total + 1000),
            2_097_152,
            total - 1,
        ), // end clamped
        ("bytes=2097151-2097151".into(), 2_097_151, 2_097_151),
    ];
    for (range, start, end) in cases {
        let resp = get_range(client, url, &range, headers).await;
        assert_eq!(resp.status(), 206, "range {range}");
        assert_eq!(
            resp.headers()["content-range"],
            format!("bytes {}-{}/{}", start, end, total).as_str(),
            "range {range}"
        );
        assert_eq!(
            resp.headers()["content-length"],
            (end - start + 1).to_string().as_str()
        );
        assert_eq!(resp.headers()["accept-ranges"], "bytes");
        let body = resp.bytes().await.unwrap();
        assert!(
            body.as_ref() == &payload[start as usize..=end as usize],
            "range {range}: wrong bytes"
        );
    }

    for range in [
        format!("bytes={}-", total),
        format!("bytes={}-{}", total + 5, total + 9),
        "bytes=-0".to_string(),
    ] {
        let resp = get_range(client, url, &range, headers).await;
        assert_eq!(resp.status(), 416, "range {range}");
        assert_eq!(
            resp.headers()["content-range"],
            format!("bytes */{}", total).as_str()
        );
        assert!(
            resp.text()
                .await
                .unwrap()
                .contains("<Code>InvalidRange</Code>")
        );
    }

    // Malformed or multi-range headers are ignored: full object
    for range in ["bytes=5-2", "items=0-1", "bytes=0-1,4-5", "bytes=x-y"] {
        let resp = get_range(client, url, range, headers).await;
        assert_eq!(resp.status(), 200, "range {range}");
        assert_eq!(resp.bytes().await.unwrap().len(), payload.len());
    }
}

/// Download in 3 parallel ranges, concatenate, compare with the original.
async fn check_parallel_download(
    client: &reqwest::Client,
    url: &str,
    payload: &[u8],
    headers: &[(&str, &str)],
) {
    let total = payload.len() as u64;
    let third = total / 3;
    let ranges = [
        (0, third - 1),
        (third, 2 * third - 1),
        (2 * third, total - 1),
    ];
    let mut tasks = Vec::new();
    for (start, end) in ranges {
        let client = client.clone();
        let url = url.to_string();
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        tasks.push(tokio::spawn(async move {
            let mut req = client
                .get(&url)
                .header("range", format!("bytes={}-{}", start, end));
            for (k, v) in &headers {
                req = req.header(k.as_str(), v.as_str());
            }
            let resp = req.send().await.unwrap();
            assert_eq!(resp.status(), 206);
            resp.bytes().await.unwrap().to_vec()
        }));
    }
    let mut assembled = Vec::new();
    for t in tasks {
        assembled.extend(t.await.unwrap());
    }
    assert_eq!(assembled.len(), payload.len());
    assert!(assembled == payload);
}

#[tokio::test]
async fn test_range_get_plain_object() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/range-b", base_url))
        .send()
        .await
        .unwrap();
    let payload = range_payload(3_500_000);
    let url = format!("{}/range-b/obj.bin", base_url);
    let r = client.put(&url).body(payload.clone()).send().await.unwrap();
    assert_eq!(r.status(), 200);

    check_ranges(&client, &url, &payload, &[]).await;
    check_parallel_download(&client, &url, &payload, &[]).await;

    // HEAD ignores Range but advertises support
    let r = client
        .head(&url)
        .header("range", "bytes=0-9")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        r.headers()["content-length"],
        payload.len().to_string().as_str()
    );
    assert_eq!(r.headers()["accept-ranges"], "bytes");
    assert!(r.headers().get("content-range").is_none());

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_range_get_empty_object() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/range-b", base_url))
        .send()
        .await
        .unwrap();
    let url = format!("{}/range-b/empty", base_url);
    client.put(&url).body("").send().await.unwrap();
    for range in ["bytes=0-0", "bytes=-1", "bytes=0-"] {
        let r = get_range(&client, &url, range, &[]).await;
        assert_eq!(r.status(), 416, "range {range}");
    }
    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_range_get_sse_s3_object() {
    let (base_url, tmp_dir, _) = start_server_with_encryption().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/range-b", base_url))
        .send()
        .await
        .unwrap();
    let payload = range_payload(3_500_000);
    let url = format!("{}/range-b/enc.bin", base_url);
    let r = client
        .put(&url)
        .header("x-amz-server-side-encryption", "AES256")
        .body(payload.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    check_ranges(&client, &url, &payload, &[]).await;
    check_parallel_download(&client, &url, &payload, &[]).await;
    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_range_get_sse_c_object() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/range-b", base_url))
        .send()
        .await
        .unwrap();
    let (_, key_b64, key_md5) = generate_customer_key();
    let sse = [
        ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
        (
            "x-amz-server-side-encryption-customer-key",
            key_b64.as_str(),
        ),
        (
            "x-amz-server-side-encryption-customer-key-md5",
            key_md5.as_str(),
        ),
    ];
    let payload = range_payload(3_500_000);
    let url = format!("{}/range-b/ssec.bin", base_url);
    let mut req = client.put(&url).body(payload.clone());
    for (k, v) in &sse {
        req = req.header(*k, *v);
    }
    assert_eq!(req.send().await.unwrap().status(), 200);

    check_ranges(&client, &url, &payload, &sse).await;
    check_parallel_download(&client, &url, &payload, &sse).await;
    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_range_get_multipart_and_versioned_object() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/range-b", base_url))
        .send()
        .await
        .unwrap();
    client
        .put(format!("{}/range-b?versioning", base_url))
        .body("<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>")
        .send()
        .await
        .unwrap();

    let payload = range_payload(5 * 1024 * 1024 + 1_234_567);
    let r = client
        .post(format!("{}/range-b/mp.bin?uploads", base_url))
        .send()
        .await
        .unwrap();
    let upload_id = extract_xml_value(&r.text().await.unwrap(), "UploadId");
    let mut parts_xml = String::new();
    for (i, chunk) in payload.chunks(5 * 1024 * 1024).enumerate() {
        let n = i + 1;
        let r = client
            .put(format!(
                "{}/range-b/mp.bin?partNumber={}&uploadId={}",
                base_url, n, upload_id
            ))
            .body(chunk.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let etag = r.headers()["etag"].to_str().unwrap().to_string();
        parts_xml.push_str(&format!(
            "<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>",
            n, etag
        ));
    }
    let r = client
        .post(format!(
            "{}/range-b/mp.bin?uploadId={}",
            base_url, upload_id
        ))
        .body(format!(
            "<CompleteMultipartUpload>{}</CompleteMultipartUpload>",
            parts_xml
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let url = format!("{}/range-b/mp.bin", base_url);
    check_ranges(&client, &url, &payload, &[]).await;
    check_parallel_download(&client, &url, &payload, &[]).await;

    // Ranged read of a specific version
    let r = client
        .put(&url)
        .body(range_payload(3_000_000))
        .send()
        .await
        .unwrap();
    let vid = r.headers()["x-amz-version-id"]
        .to_str()
        .unwrap()
        .to_string();
    let v2 = range_payload(3_000_000);
    let vurl = format!("{}?versionId={}", url, vid);
    check_ranges(&client, &vurl, &v2, &[]).await;

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_quota_counts_user_objects_named_tmp() {
    let (base_url, tmp_dir) = start_server_with_quota(Some(1000)).await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/tmp-b", base_url))
        .send()
        .await
        .unwrap();
    let r = client
        .put(format!("{}/tmp-b/backup.tmp", base_url))
        .body(vec![b't'; 600])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // Listed like any other object, and still counted after a recount
    let list = client
        .get(format!("{}/tmp-b?list-type=2", base_url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(list.contains("<Key>backup.tmp</Key>"), "{list}");
    client
        .delete(format!("{}/tmp-b/missing", base_url))
        .send()
        .await
        .unwrap();
    client
        .put(format!("{}/other-b", base_url))
        .send()
        .await
        .unwrap();
    client
        .delete(format!("{}/other-b", base_url))
        .send()
        .await
        .unwrap(); // triggers a recount
    tokio::time::sleep(std::time::Duration::from_millis(900)).await;
    assert!(used_bytes(&client, &base_url).await >= 600);
    let r = client
        .put(format!("{}/tmp-b/more", base_url))
        .body(vec![b'm'; 600])
        .send()
        .await
        .unwrap();
    assert_quota_exceeded(r).await;

    cleanup(&tmp_dir);
}

/// Startup removes interrupted temporary files, never objects whose key ends in `.tmp`.
#[test]
fn test_startup_tmp_cleanup_keeps_user_objects() {
    let tmp_dir = std::env::temp_dir().join(format!("s3-test-{}", uuid::Uuid::new_v4()));
    let data = tmp_dir.join("data");
    std::fs::create_dir_all(data.join("keep-b/dir")).unwrap();
    std::fs::create_dir_all(data.join(".loch-tmp")).unwrap();
    std::fs::write(data.join("keep-b/backup.tmp"), "user data").unwrap();
    std::fs::write(data.join("keep-b/dir/x.tmp"), "user data").unwrap();
    std::fs::write(
        data.join(".loch-tmp/0f8fad5b-d9cb-469f-a165-70867728950e.tmp"),
        "partial",
    )
    .unwrap();
    // Even a key shaped like an old temporary name is left alone
    std::fs::write(
        data.join("keep-b/photo.jpg.0f8fad5b-d9cb-469f-a165-70867728950e.tmp"),
        "user data",
    )
    .unwrap();

    let (exited, stderr) =
        run_server_briefly(&[("S3_DATA_DIR", data.to_string_lossy().to_string())]);
    assert!(exited.is_none(), "server exited: {stderr}");
    assert!(
        stderr.contains("Removed 1 stale temporary file(s)"),
        "{stderr}"
    );
    assert!(data.join("keep-b/backup.tmp").exists());
    assert!(data.join("keep-b/dir/x.tmp").exists());
    assert!(
        data.join("keep-b/photo.jpg.0f8fad5b-d9cb-469f-a165-70867728950e.tmp")
            .exists()
    );
    assert_eq!(
        std::fs::read_dir(data.join(".loch-tmp")).unwrap().count(),
        0
    );

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_internal_tmp_dir_is_not_a_bucket() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/list-b", base_url))
        .send()
        .await
        .unwrap();
    client
        .put(format!("{}/list-b/obj", base_url))
        .body("x")
        .send()
        .await
        .unwrap();
    assert!(tmp_dir.join(".loch-tmp").is_dir());
    let body = client
        .get(format!("{}/", base_url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("<Name>list-b</Name>"));
    assert!(!body.contains(".loch-tmp"));
    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_security_multipart_upload_bound_to_its_key() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/mp-b", base_url))
        .send()
        .await
        .unwrap();
    let r = client
        .post(format!("{}/mp-b/secret/target?uploads", base_url))
        .send()
        .await
        .unwrap();
    let upload_id = extract_xml_value(&r.text().await.unwrap(), "UploadId");
    let r = client
        .put(format!(
            "{}/mp-b/secret/target?partNumber=1&uploadId={}",
            base_url, upload_id
        ))
        .body("part")
        .send()
        .await
        .unwrap();
    let etag = r.headers()["etag"].to_str().unwrap().to_string();

    // Same upload ID used through another key (the one authorization is evaluated on)
    let other = format!("{}/mp-b/pub/x", base_url);
    let r = client
        .put(format!("{}?partNumber=1&uploadId={}", other, upload_id))
        .body("evil")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    let r = client
        .get(format!("{}?uploadId={}", other, upload_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    let complete = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        etag
    );
    let r = client
        .post(format!("{}?uploadId={}", other, upload_id))
        .body(complete.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    let r = client
        .delete(format!("{}?uploadId={}", other, upload_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    // The upload is intact and completes under its own key
    let r = client
        .post(format!(
            "{}/mp-b/secret/target?uploadId={}",
            base_url, upload_id
        ))
        .body(complete)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = client
        .get(format!("{}/mp-b/secret/target", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.text().await.unwrap(), "part");

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_aws_chunked_incomplete_body_rejected() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/chunked-b", base_url))
        .send()
        .await
        .unwrap();
    let r = client
        .put(format!("{}/chunked-b/obj", base_url))
        .header("content-encoding", "aws-chunked")
        .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
        .body("5\r\nhello\r\n") // final 0-size chunk missing
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let r = client
        .get(format!("{}/chunked-b/obj", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    assert_eq!(count_tmp_files(&tmp_dir), 0);
    cleanup(&tmp_dir);
}

/// Concurrent overwrites and deletes of one key must neither fail (deletes remove
/// directories that become empty, including `.meta/` and the key's parents) nor
/// leave the counter wrong.
#[tokio::test]
async fn test_quota_concurrent_overwrites_same_key_stay_exact() {
    let (base_url, tmp_dir) = start_server_with_quota(Some(100_000_000)).await;
    let client = reqwest::Client::new();
    client
        .put(format!("{}/race-b", base_url))
        .send()
        .await
        .unwrap();
    for key in ["same", "nested/dir/same"] {
        let url = format!("{}/race-b/{}", base_url, key);
        let mut tasks = Vec::new();
        for i in 0..150usize {
            let client = client.clone();
            let url = url.clone();
            tasks.push(tokio::spawn(async move {
                let resp = if i % 3 == 2 {
                    client.delete(&url).send().await.unwrap()
                } else {
                    let size = 1_000 + (i * 997) % 50_000;
                    client
                        .put(&url)
                        .body(vec![b'r'; size])
                        .send()
                        .await
                        .unwrap()
                };
                let status = resp.status().as_u16();
                (status, resp.text().await.unwrap_or_default())
            }));
        }
        for t in tasks {
            let (status, body) = t.await.unwrap();
            assert!(
                status == 200 || status == 204,
                "{key}: status {status}: {body}"
            );
        }
    }
    let used = used_bytes(&client, &base_url).await;
    let actual = s3::quota::data_dir_usage(&tmp_dir);
    // Exact up to untracked metadata sidecars (rewritten in place, < 1 KiB each)
    assert!(
        used <= actual + 2048 && used + 2048 >= actual,
        "used {used}, on disk {actual}"
    );
    cleanup(&tmp_dir);
}

/// Once the quota is exceeded, empty writes and new multipart uploads are refused too.
#[tokio::test]
async fn test_quota_exceeded_refuses_empty_writes() {
    let tmp_dir = std::env::temp_dir().join(format!("s3-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(tmp_dir.join("full-b")).unwrap();
    std::fs::write(tmp_dir.join("full-b/file"), vec![0u8; 2000]).unwrap();
    let base_url = start_server_with_quota_in(tmp_dir.clone(), Some(1000), None).await;
    let client = reqwest::Client::new();
    let r = client
        .put(format!("{}/full-b/empty", base_url))
        .body("")
        .send()
        .await
        .unwrap();
    assert_quota_exceeded(r).await;
    let r = client
        .post(format!("{}/full-b/mp?uploads", base_url))
        .send()
        .await
        .unwrap();
    assert_quota_exceeded(r).await;
    // Deleting still works and frees space
    let r = client
        .delete(format!("{}/full-b/file", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    let r = client
        .put(format!("{}/full-b/empty", base_url))
        .body("")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    cleanup(&tmp_dir);
}

// ---------------------------------------------------------------------------
// Server-side encryption by default (S3_ENCRYPT_BY_DEFAULT) and key file
// ---------------------------------------------------------------------------

/// Start an in-process server on an existing data directory.
async fn start_server_in_dir(
    dir: &std::path::Path,
    encryption: Option<EncryptionConfig>,
) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(ServerConfig {
        storage: Arc::new(Storage::new(dir.to_path_buf())),
        user_store: None,
        admin_api_key: None,
        upload_ttl_secs: 86400,
        encryption,
    });
    tokio::spawn(async move {
        s3::serve(listener, config).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    format!("http://127.0.0.1:{}", port)
}

fn by_default_config() -> Option<EncryptionConfig> {
    Some(EncryptionConfig {
        master_key: [0x24u8; 32],
        encrypt_by_default: true,
    })
}

/// A recognizable payload spanning several 1 MiB encryption chunks.
fn marked_payload(len: usize) -> Vec<u8> {
    b"LOCH-PLAINTEXT-MARKER-"
        .iter()
        .cycle()
        .take(len)
        .copied()
        .collect()
}

fn contains_marker(data: &[u8]) -> bool {
    data.windows(22).any(|w| w == b"LOCH-PLAINTEXT-MARKER-")
}

fn sse_header(resp: &reqwest::Response) -> Option<String> {
    resp.headers()
        .get("x-amz-server-side-encryption")
        .map(|v| v.to_str().unwrap().to_string())
}

#[tokio::test]
async fn test_encrypt_by_default_put_get_range() {
    let tmp = std::env::temp_dir().join(format!("s3-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp).unwrap();
    let base = start_server_in_dir(&tmp, by_default_config()).await;
    let client = reqwest::Client::new();
    client.put(format!("{base}/sse-def")).send().await.unwrap();

    let payload = marked_payload(2 * 1024 * 1024 + 4321);
    let resp = client
        .put(format!("{base}/sse-def/obj.bin"))
        .body(payload.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(sse_header(&resp).as_deref(), Some("AES256"));

    // Stored encrypted: no plaintext on disk, and larger (GCM tags)
    let on_disk = std::fs::read(tmp.join("sse-def/obj.bin")).unwrap();
    assert!(!contains_marker(&on_disk), "object stored in plaintext");
    assert!(on_disk.len() > payload.len());

    let resp = client
        .get(format!("{base}/sse-def/obj.bin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(sse_header(&resp).as_deref(), Some("AES256"));
    assert_eq!(resp.bytes().await.unwrap().as_ref(), &payload[..]);

    let resp = client
        .head(format!("{base}/sse-def/obj.bin"))
        .send()
        .await
        .unwrap();
    assert_eq!(sse_header(&resp).as_deref(), Some("AES256"));

    // Range across the first 1 MiB chunk boundary
    let (start, end) = (1024 * 1024 - 10, 1024 * 1024 + 99);
    let resp = client
        .get(format!("{base}/sse-def/obj.bin"))
        .header("Range", format!("bytes={start}-{end}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 206);
    assert_eq!(
        resp.headers()
            .get("content-range")
            .unwrap()
            .to_str()
            .unwrap(),
        format!("bytes {start}-{end}/{}", payload.len())
    );
    assert_eq!(resp.bytes().await.unwrap().as_ref(), &payload[start..=end]);

    // Suffix range (last bytes)
    let resp = client
        .get(format!("{base}/sse-def/obj.bin"))
        .header("Range", "bytes=-100")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 206);
    assert_eq!(
        resp.bytes().await.unwrap().as_ref(),
        &payload[payload.len() - 100..]
    );

    cleanup(&tmp);
}

#[tokio::test]
async fn test_encrypt_by_default_sse_c_takes_precedence() {
    let tmp = std::env::temp_dir().join(format!("s3-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp).unwrap();
    let base = start_server_in_dir(&tmp, by_default_config()).await;
    let client = reqwest::Client::new();
    let (_, key_b64, key_md5) = generate_customer_key();
    client
        .put(format!("{base}/sse-def-c"))
        .send()
        .await
        .unwrap();

    let resp = client
        .put(format!("{base}/sse-def-c/f.txt"))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header("x-amz-server-side-encryption-customer-key", &key_b64)
        .header("x-amz-server-side-encryption-customer-key-md5", &key_md5)
        .body(marked_payload(1000))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(sse_header(&resp), None);

    // SSE-C object: unreadable without the customer key, readable with it
    let resp = client
        .get(format!("{base}/sse-def-c/f.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let resp = client
        .get(format!("{base}/sse-def-c/f.txt"))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header("x-amz-server-side-encryption-customer-key", &key_b64)
        .header("x-amz-server-side-encryption-customer-key-md5", &key_md5)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.bytes().await.unwrap().as_ref(),
        &marked_payload(1000)[..]
    );

    cleanup(&tmp);
}

#[tokio::test]
async fn test_encrypt_by_default_multipart() {
    let tmp = std::env::temp_dir().join(format!("s3-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp).unwrap();
    let base = start_server_in_dir(&tmp, by_default_config()).await;
    let client = reqwest::Client::new();
    client
        .put(format!("{base}/sse-def-mp"))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/sse-def-mp/big.bin?uploads"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(sse_header(&resp).as_deref(), Some("AES256"));
    let upload_id = extract_xml_value(&resp.text().await.unwrap(), "UploadId");

    let payload = marked_payload(3 * 1024 * 1024 + 17);
    let (p1, p2) = payload.split_at(1536 * 1024);
    let mut etags = Vec::new();
    for (n, part) in [(1, p1), (2, p2)] {
        let resp = client
            .put(format!(
                "{base}/sse-def-mp/big.bin?partNumber={n}&uploadId={upload_id}"
            ))
            .body(part.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        etags.push(
            resp.headers()
                .get("etag")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
        );
    }
    let complete = format!(
        "<CompleteMultipartUpload>\
           <Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part>\
           <Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part>\
         </CompleteMultipartUpload>",
        etags[0], etags[1]
    );
    let resp = client
        .post(format!("{base}/sse-def-mp/big.bin?uploadId={upload_id}"))
        .body(complete)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(sse_header(&resp).as_deref(), Some("AES256"));

    let on_disk = std::fs::read(tmp.join("sse-def-mp/big.bin")).unwrap();
    assert!(
        !contains_marker(&on_disk),
        "multipart object stored in plaintext"
    );

    let resp = client
        .get(format!("{base}/sse-def-mp/big.bin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(sse_header(&resp).as_deref(), Some("AES256"));
    assert_eq!(resp.bytes().await.unwrap().as_ref(), &payload[..]);

    let resp = client
        .get(format!("{base}/sse-def-mp/big.bin"))
        .header("Range", "bytes=1572860-1572870")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 206);
    assert_eq!(
        resp.bytes().await.unwrap().as_ref(),
        &payload[1572860..=1572870]
    );

    cleanup(&tmp);
}

#[tokio::test]
async fn test_encrypt_by_default_keeps_old_objects_and_encrypts_copies_and_versions() {
    let tmp = std::env::temp_dir().join(format!("s3-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp).unwrap();
    let client = reqwest::Client::new();

    // Written before encryption by default is turned on
    let before = start_server_in_dir(&tmp, None).await;
    client
        .put(format!("{before}/sse-def-old"))
        .send()
        .await
        .unwrap();
    let old = marked_payload(5000);
    let resp = client
        .put(format!("{before}/sse-def-old/old.txt"))
        .body(old.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let base = start_server_in_dir(&tmp, by_default_config()).await;

    // Old object: still plaintext on disk, readable, no SSE header
    let resp = client
        .get(format!("{base}/sse-def-old/old.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(sse_header(&resp), None);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), &old[..]);

    // CopyObject without SSE header: the copy is encrypted
    let resp = client
        .put(format!("{base}/sse-def-old/copy.txt"))
        .header("x-amz-copy-source", "/sse-def-old/old.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(sse_header(&resp).as_deref(), Some("AES256"));
    let on_disk = std::fs::read(tmp.join("sse-def-old/copy.txt")).unwrap();
    assert!(!contains_marker(&on_disk), "copy stored in plaintext");
    let resp = client
        .get(format!("{base}/sse-def-old/copy.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.bytes().await.unwrap().as_ref(), &old[..]);

    // Versioned bucket: the stored version is encrypted too
    let resp = client
        .put(format!("{base}/sse-def-old?versioning"))
        .body("<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .put(format!("{base}/sse-def-old/v.txt"))
        .body(marked_payload(3000))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(sse_header(&resp).as_deref(), Some("AES256"));
    let vid = resp
        .headers()
        .get("x-amz-version-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let version_data =
        std::fs::read(tmp.join(format!("sse-def-old/.versions/v.txt/{vid}.data"))).unwrap();
    assert!(
        !contains_marker(&version_data),
        "version stored in plaintext"
    );
    let resp = client
        .get(format!("{base}/sse-def-old/v.txt?versionId={vid}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.bytes().await.unwrap().as_ref(),
        &marked_payload(3000)[..]
    );

    cleanup(&tmp);
}

/// Run the binary with an encryption setup; returns (exit status if it
/// exited, stderr). `data` must be a scratch directory.
fn run_with_encryption_env(
    data: &std::path::Path,
    envs: &[(&str, String)],
) -> (Option<std::process::ExitStatus>, String) {
    let mut all = vec![("S3_DATA_DIR", data.to_string_lossy().to_string())];
    all.extend(envs.iter().cloned());
    run_server_briefly(&all)
}

#[test]
fn test_encryption_key_file_loading_and_refusals() {
    let tmp = std::env::temp_dir().join(format!("s3-test-{}", uuid::Uuid::new_v4()));
    let data = tmp.join("data");
    std::fs::create_dir_all(&data).unwrap();
    let key_b64 = BASE64.encode([0x5Au8; 32]);
    let file = |name: &str, content: &str| {
        let p = tmp.join(name);
        std::fs::write(&p, content).unwrap();
        p.to_string_lossy().to_string()
    };

    // Valid file, with and without a trailing newline: the server starts,
    // and the key never shows up in the logs.
    for (name, content) in [
        ("nl.key", format!("{key_b64}\n")),
        ("crlf.key", format!("{key_b64}\r\n")),
        ("raw.key", key_b64.clone()),
    ] {
        let path = file(name, &content);
        let (exited, stderr) = run_with_encryption_env(
            &data,
            &[
                ("S3_ENCRYPTION_KEY_FILE", path),
                ("S3_ENCRYPT_BY_DEFAULT", "true".into()),
            ],
        );
        assert!(exited.is_none(), "{name}: server should start: {stderr}");
        assert!(stderr.contains("applied by default"), "{stderr}");
        assert!(!stderr.contains(&key_b64), "key leaked in logs");
    }

    let refused = |envs: &[(&str, String)], expected: &str| {
        let (exited, stderr) = run_with_encryption_env(&data, envs);
        let status = exited.unwrap_or_else(|| panic!("server should refuse to start: {envs:?}"));
        assert_eq!(status.code(), Some(1), "{stderr}");
        assert!(
            stderr.contains(expected),
            "expected '{expected}' in: {stderr}"
        );
        assert!(!stderr.contains(&key_b64), "key leaked in logs");
    };

    // Missing file
    let missing = tmp.join("missing.key").to_string_lossy().to_string();
    refused(&[("S3_ENCRYPTION_KEY_FILE", missing)], "cannot read");
    // Invalid content: not base64, wrong length, key wrapped in extra text
    refused(
        &[("S3_ENCRYPTION_KEY_FILE", file("bad.key", "not base64 !!\n"))],
        "valid base64",
    );
    refused(
        &[(
            "S3_ENCRYPTION_KEY_FILE",
            file("short.key", &BASE64.encode([1u8; 16])),
        )],
        "exactly 32 bytes",
    );
    refused(
        &[("S3_ENCRYPTION_KEY_FILE", file("empty.key", ""))],
        "exactly 32 bytes",
    );
    // Both sources at once
    refused(
        &[
            ("S3_ENCRYPTION_KEY", key_b64.clone()),
            ("S3_ENCRYPTION_KEY_FILE", file("both.key", &key_b64)),
        ],
        "mutually exclusive",
    );
    // Encryption by default without any key
    refused(
        &[("S3_ENCRYPT_BY_DEFAULT", "true".into())],
        "requires a master key",
    );
    // Invalid boolean
    refused(
        &[
            ("S3_ENCRYPTION_KEY_FILE", file("bool.key", &key_b64)),
            ("S3_ENCRYPT_BY_DEFAULT", "sometimes".into()),
        ],
        "must be true or false",
    );
    // Empty variables do not silently disable encryption
    refused(
        &[("S3_ENCRYPTION_KEY_FILE", String::new())],
        "set but empty",
    );
    refused(&[("S3_ENCRYPTION_KEY", String::new())], "set but empty");

    // Unreadable file (skipped when running as root, which reads anything)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = file("locked.key", &key_b64);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&path).is_err() {
            refused(&[("S3_ENCRYPTION_KEY_FILE", path.clone())], "cannot read");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    cleanup(&tmp);
}

// ---------------------------------------------------------------------------
// 1.4.1: non-canonical object keys (dot segments, empty segments)
// ---------------------------------------------------------------------------

/// Send a raw HTTP/1.1 request with the path exactly as given (reqwest would
/// normalize "./" segments). Returns the status code.
async fn raw_request(base_url: &str, method: &str, path: &str, body: &str) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = base_url.trim_start_matches("http://");
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.unwrap();
    let text = String::from_utf8_lossy(&resp);
    text.split_whitespace().nth(1).unwrap().parse().unwrap()
}

#[tokio::test]
async fn test_security_dot_segment_keys_cannot_reach_internal_files() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{base_url}/dotseg"))
        .send()
        .await
        .unwrap();
    client
        .put(format!("{base_url}/dotseg/secret/x"))
        .body("TOPSECRET")
        .send()
        .await
        .unwrap();
    let metadata_before = std::fs::read(tmp_dir.join("dotseg/.metadata")).unwrap();
    let forged = r#"{"created":"2026-01-01T00:00:00.000Z","owner":"mallory"}"#;

    for path in [
        "/dotseg/./.metadata",
        "/dotseg/%2e/.metadata",
        "/dotseg/.//.metadata",
        "/dotseg//.metadata",
        "/dotseg/./.policy.json",
        "/dotseg/%2E/.policy.json",
        "/dotseg/./.meta/secret/x.json",
        "/dotseg/a/./b",
        "/dotseg/a//b",
    ] {
        for method in ["PUT", "GET", "DELETE"] {
            let status = raw_request(&base_url, method, path, forged).await;
            assert!(
                status == 400 || status == 403,
                "{method} {path} returned {status}"
            );
        }
    }
    // Reading through a dot segment is refused too (Deny bypass vector)
    assert_eq!(
        raw_request(&base_url, "GET", "/dotseg/./secret/x", "").await,
        400
    );

    // Internal state untouched, no policy planted, no aliased object created
    assert_eq!(
        std::fs::read(tmp_dir.join("dotseg/.metadata")).unwrap(),
        metadata_before
    );
    assert!(!tmp_dir.join("dotseg/.policy.json").exists());
    assert!(!tmp_dir.join("dotseg/a").exists());
    // The legitimate object is still there
    let resp = client
        .get(format!("{base_url}/dotseg/secret/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "TOPSECRET");

    cleanup(&tmp_dir);
}

// ---------------------------------------------------------------------------
// 1.4.1: signed payload integrity (x-amz-content-sha256, chunk signatures)
// ---------------------------------------------------------------------------

/// Build a STREAMING-AWS4-HMAC-SHA256-PAYLOAD PUT: returns the request
/// headers and the aws-chunked body. `tamper` alters the data of the first
/// chunk after it has been signed.
fn streaming_signed_put(
    host: &str,
    path: &str,
    chunks: &[&[u8]],
    keys: (&str, &str),
    tamper: bool,
) -> (Vec<(String, String)>, Vec<u8>) {
    let now = chrono::Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();
    let scope = format!("{date_stamp}/loch-sh/s3/aws4_request");
    let decoded_len: usize = chunks.iter().map(|c| c.len()).sum();
    let mut headers = vec![
        ("content-encoding".to_string(), "aws-chunked".to_string()),
        ("host".to_string(), host.to_string()),
        (
            "x-amz-content-sha256".to_string(),
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".to_string(),
        ),
        ("x-amz-date".to_string(), amz_date.clone()),
        (
            "x-amz-decoded-content-length".to_string(),
            decoded_len.to_string(),
        ),
    ];
    headers.sort();
    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_request = format!(
        "PUT\n{path}\n\n{canonical_headers}\n{signed_headers}\nSTREAMING-AWS4-HMAC-SHA256-PAYLOAD"
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let signing_key = derive_signing_key(keys.1, &date_stamp, "loch-sh", "s3");
    let seed = hmac_sha256_hex(&signing_key, string_to_sign.as_bytes());

    let empty = sha256_hex(b"");
    let mut previous = seed.clone();
    let mut body = Vec::new();
    let mut all: Vec<&[u8]> = chunks.to_vec();
    all.push(b"");
    for (i, chunk) in all.iter().enumerate() {
        let sts = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{scope}\n{previous}\n{empty}\n{}",
            sha256_hex(chunk)
        );
        let sig = hmac_sha256_hex(&signing_key, sts.as_bytes());
        body.extend_from_slice(format!("{:x};chunk-signature={sig}\r\n", chunk.len()).as_bytes());
        let mut data = chunk.to_vec();
        if tamper && i == 0 {
            data[0] ^= 0xff;
        }
        body.extend_from_slice(&data);
        body.extend_from_slice(b"\r\n");
        previous = sig;
    }
    headers.push((
        "authorization".to_string(),
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={seed}",
            keys.0
        ),
    ));
    (headers, body)
}

#[tokio::test]
async fn test_security_signed_payload_integrity_is_verified() {
    use reqwest::Method;
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let client = reqwest::Client::new();
    let host = base_url.trim_start_matches("http://").to_string();
    let r = signed(
        &client,
        &base_url,
        Method::PUT,
        "/integ-b",
        "",
        b"",
        &[],
        ALICE,
    )
    .await;
    assert_eq!(r.status(), 200);

    // 1. Body replaced after signing: x-amz-content-sha256 no longer matches
    let resp = sign_request_with_headers(
        client
            .put(format!("{base_url}/integ-b/tampered.txt"))
            .body("EVIL"),
        "PUT",
        "/integ-b/tampered.txt",
        "",
        &host,
        b"hello",
        &[],
        ALICE.0,
        ALICE.1,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 400);
    assert!(
        resp.text()
            .await
            .unwrap()
            .contains("XAmzContentSHA256Mismatch")
    );
    let r = signed(
        &client,
        &base_url,
        Method::GET,
        "/integ-b/tampered.txt",
        "",
        b"",
        &[],
        ALICE,
    )
    .await;
    assert_eq!(r.status(), 404, "tampered body must not be stored");

    // Same for a small XML/JSON body (bucket policy)
    let policy = br#"{"Version":"2012-10-17","Statement":[]}"#;
    let resp = sign_request_with_headers(
        client
            .put(format!("{base_url}/integ-b?policy"))
            .body(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::integ-b/*"}]}"#),
        "PUT",
        "/integ-b",
        "policy=",
        &host,
        policy,
        &[],
        ALICE.0,
        ALICE.1,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 400);
    assert!(!tmp_dir.join("integ-b/.policy.json").exists());

    // 2. x-amz-* header added after signing
    let resp = sign_request_with_headers(
        client
            .put(format!("{base_url}/integ-b/meta.txt"))
            .body("hello")
            .header("x-amz-meta-injected", "1"),
        "PUT",
        "/integ-b/meta.txt",
        "",
        &host,
        b"hello",
        &[],
        ALICE.0,
        ALICE.1,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 403);

    // 3. Signed aws-chunked upload: accepted when every chunk signature is valid
    let (c1, c2) = (vec![b'a'; 70_000], vec![b'b'; 1234]);
    let send = |headers: Vec<(String, String)>, body: Vec<u8>, path: &str| {
        let mut b = client.put(format!("{base_url}{path}")).body(body);
        for (k, v) in headers {
            if k != "host" {
                b = b.header(k, v);
            }
        }
        b.send()
    };
    let (h, body) = streaming_signed_put(&host, "/integ-b/stream.bin", &[&c1, &c2], ALICE, false);
    let resp = send(h, body, "/integ-b/stream.bin").await.unwrap();
    assert_eq!(resp.status(), 200);
    let r = signed(
        &client,
        &base_url,
        Method::GET,
        "/integ-b/stream.bin",
        "",
        b"",
        &[],
        ALICE,
    )
    .await;
    let got = r.bytes().await.unwrap();
    assert_eq!(got.len(), c1.len() + c2.len());
    assert!(got[..c1.len()].iter().all(|&b| b == b'a'));

    // ... and rejected when a chunk was modified after signing
    let (h, body) = streaming_signed_put(&host, "/integ-b/stream2.bin", &[&c1, &c2], ALICE, true);
    let resp = send(h, body, "/integ-b/stream2.bin").await.unwrap();
    assert_eq!(resp.status(), 403);
    let r = signed(
        &client,
        &base_url,
        Method::GET,
        "/integ-b/stream2.bin",
        "",
        b"",
        &[],
        ALICE,
    )
    .await;
    assert_eq!(
        r.status(),
        404,
        "object with a forged chunk must not be stored"
    );

    cleanup(&tmp_dir);
}

// ---------------------------------------------------------------------------
// 1.4.1: authorization, quota and robustness fixes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_security_policy_deny_wins_over_public_acl() {
    use reqwest::Method;
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let client = reqwest::Client::new();
    setup_alice_and_bob(&client, &base_url).await;
    let r = signed(
        &client,
        &base_url,
        Method::PUT,
        "/alice-b/public.txt",
        "",
        b"P",
        &[],
        ALICE,
    )
    .await;
    assert_eq!(r.status(), 200);
    let r = signed(
        &client,
        &base_url,
        Method::PUT,
        "/alice-b",
        "acl=",
        b"",
        &[("x-amz-acl", "public-read")],
        ALICE,
    )
    .await;
    assert_eq!(r.status(), 200);
    // Public ACL alone: anonymous reads are allowed
    let r = client
        .get(format!("{base_url}/alice-b/public.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let policy = br#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:loch:s3:::alice-b/secret.txt"}]}"#;
    let r = signed(
        &client,
        &base_url,
        Method::PUT,
        "/alice-b",
        "policy=",
        policy,
        &[],
        ALICE,
    )
    .await;
    assert_eq!(r.status(), 204);
    // The explicit Deny wins over the ACL grant
    let r = client
        .get(format!("{base_url}/alice-b/secret.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = client
        .get(format!("{base_url}/alice-b/public.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_security_policy_with_unsupported_fields_is_rejected() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{base_url}/cond-b"))
        .send()
        .await
        .unwrap();
    for policy in [
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::cond-b/*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}"#,
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","NotAction":"s3:DeleteObject","Action":"s3:GetObject","Resource":"arn:aws:s3:::cond-b/*"}]}"#,
    ] {
        let r = client
            .put(format!("{base_url}/cond-b?policy"))
            .body(policy)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400);
        assert!(r.text().await.unwrap().contains("MalformedPolicy"));
    }
    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_quota_delete_markers_are_refused_once_exceeded() {
    let (base_url, tmp_dir) = start_server_with_quota(Some(2000)).await;
    let client = reqwest::Client::new();
    client
        .put(format!("{base_url}/dm-quota"))
        .send()
        .await
        .unwrap();
    client
        .put(format!("{base_url}/dm-quota?versioning"))
        .body("<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>")
        .send()
        .await
        .unwrap();
    // Delete markers on missing keys are counted and stop at the limit
    let mut refused = false;
    for i in 0..200 {
        let r = client
            .delete(format!("{base_url}/dm-quota/missing-{i}"))
            .send()
            .await
            .unwrap();
        if r.status() == 403 {
            refused = true;
            break;
        }
        assert_eq!(r.status(), 204);
    }
    assert!(refused, "delete markers must not grow past the quota");
    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_delete_bucket_refused_with_noncurrent_versions_or_uploads() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{base_url}/del-ver"))
        .send()
        .await
        .unwrap();
    client
        .put(format!("{base_url}/del-ver?versioning"))
        .body("<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>")
        .send()
        .await
        .unwrap();
    client
        .put(format!("{base_url}/del-ver/k"))
        .body("v1")
        .send()
        .await
        .unwrap();
    client
        .delete(format!("{base_url}/del-ver/k"))
        .send()
        .await
        .unwrap();
    // Only a delete marker is current, but v1 still exists
    let r = client
        .delete(format!("{base_url}/del-ver"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
    assert!(tmp_dir.join("del-ver/.versions").exists());

    client
        .put(format!("{base_url}/del-up"))
        .send()
        .await
        .unwrap();
    let r = client
        .post(format!("{base_url}/del-up/big?uploads"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = client
        .delete(format!("{base_url}/del-up"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_complete_multipart_requires_parts() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{base_url}/mp-empty"))
        .send()
        .await
        .unwrap();
    let r = client
        .post(format!("{base_url}/mp-empty/o?uploads"))
        .send()
        .await
        .unwrap();
    let upload_id = extract_xml_value(&r.text().await.unwrap(), "UploadId");
    let r = client
        .post(format!("{base_url}/mp-empty/o?uploadId={upload_id}"))
        .body("<CompleteMultipartUpload></CompleteMultipartUpload>")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let r = client
        .head(format!("{base_url}/mp-empty/o"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_list_with_multibyte_delimiter_does_not_panic() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{base_url}/delim-b"))
        .send()
        .await
        .unwrap();
    client
        .put(format!("{base_url}/delim-b/a%C3%A9b"))
        .body("x")
        .send()
        .await
        .unwrap();
    for delimiter in ["%E9", "%C3%A9", "%C3%A9b", "ab"] {
        let r = client
            .get(format!(
                "{base_url}/delim-b?list-type=2&delimiter={delimiter}"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "delimiter {delimiter}");
    }
    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_cors_rule_with_invalid_header_value_is_rejected() {
    let (base_url, tmp_dir) = start_server().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{base_url}/cors-nl"))
        .send()
        .await
        .unwrap();
    let r = client
        .put(format!("{base_url}/cors-nl?cors"))
        .body("<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>PUT\n</AllowedMethod></CORSRule></CORSConfiguration>")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_create_existing_bucket_error_depends_on_owner() {
    use reqwest::Method;
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let client = reqwest::Client::new();
    setup_alice_and_bob(&client, &base_url).await;
    let r = signed(
        &client,
        &base_url,
        Method::PUT,
        "/alice-b",
        "",
        b"",
        &[],
        BOB,
    )
    .await;
    assert_eq!(r.status(), 409);
    let body = r.text().await.unwrap();
    assert!(body.contains("<Code>BucketAlreadyExists</Code>"), "{body}");
    let r = signed(
        &client,
        &base_url,
        Method::PUT,
        "/alice-b",
        "",
        b"",
        &[],
        ALICE,
    )
    .await;
    assert_eq!(r.status(), 409);
    assert!(
        r.text()
            .await
            .unwrap()
            .contains("<Code>BucketAlreadyOwnedByYou</Code>")
    );
    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_sse_multipart_over_encrypted_object_gets_fresh_metadata() {
    let (base_url, tmp_dir, _) = start_server_with_encryption().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{base_url}/sse-mp"))
        .send()
        .await
        .unwrap();
    let r = client
        .put(format!("{base_url}/sse-mp/k"))
        .header("x-amz-server-side-encryption", "AES256")
        .body("old encrypted")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let r = client
        .post(format!("{base_url}/sse-mp/k?uploads"))
        .send()
        .await
        .unwrap();
    let upload_id = extract_xml_value(&r.text().await.unwrap(), "UploadId");
    let r = client
        .put(format!(
            "{base_url}/sse-mp/k?partNumber=1&uploadId={upload_id}"
        ))
        .body("new-plain-content")
        .send()
        .await
        .unwrap();
    let etag = r
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let r = client
        .post(format!("{base_url}/sse-mp/k?uploadId={upload_id}"))
        .body(format!(
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let r = client
        .get(format!("{base_url}/sse-mp/k"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.headers().get("x-amz-server-side-encryption").is_none());
    assert_eq!(r.text().await.unwrap(), "new-plain-content");
    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_sse_truncated_ciphertext_is_not_copied() {
    let (base_url, tmp_dir, _) = start_server_with_encryption().await;
    let client = reqwest::Client::new();
    client
        .put(format!("{base_url}/sse-trunc"))
        .send()
        .await
        .unwrap();
    let payload = vec![7u8; 3 * 1024 * 1024];
    client
        .put(format!("{base_url}/sse-trunc/o"))
        .header("x-amz-server-side-encryption", "AES256")
        .body(payload)
        .send()
        .await
        .unwrap();
    // Drop the last chunk on disk (2 full chunks left)
    let path = tmp_dir.join("sse-trunc/o");
    let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.set_len(2 * (1024 * 1024 + 16)).unwrap();
    drop(f);

    let r = client
        .put(format!("{base_url}/sse-trunc/copy"))
        .header("x-amz-copy-source", "/sse-trunc/o")
        .send()
        .await
        .unwrap();
    assert_ne!(
        r.status(),
        200,
        "a truncated object must not be copied as valid"
    );
    assert!(!tmp_dir.join("sse-trunc/copy").exists());

    // A GET fails instead of ending cleanly after 2 MiB
    let r = client
        .get(format!("{base_url}/sse-trunc/o"))
        .send()
        .await
        .unwrap();
    assert!(
        r.bytes().await.is_err(),
        "truncated body must surface as an error"
    );
    cleanup(&tmp_dir);
}
