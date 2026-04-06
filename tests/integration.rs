use std::sync::Arc;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use s3::ServerConfig;
use s3::auth::Credentials;
use s3::encryption::EncryptionConfig;
use s3::storage::Storage;
use s3::users::{UserRecord, UserStore};

const TEST_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const TEST_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

/// Start a test server without authentication on a random port.
async fn start_server() -> (String, std::path::PathBuf) {
    start_server_with_auth(None).await
}

/// Start a test server with optional authentication on a random port.
async fn start_server_with_auth(credentials: Option<Credentials>) -> (String, std::path::PathBuf) {
    let user_store = credentials.map(|c| Arc::new(RwLock::new(UserStore::from_single_credentials(c))));
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
    let (url, tmp) = start_server_full(None, None, Some(EncryptionConfig { master_key })).await;
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
    std::fs::write(&users_file, serde_json::to_string_pretty(&users_json).unwrap()).unwrap();

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
    let now = chrono::Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();

    let region = "loch-sh";
    let service = "s3";
    let scope = format!("{}/{}/{}/aws4_request", date_stamp, region, service);

    // Hash the payload
    let payload_hash = sha256_hex(body);

    // Build canonical headers (sorted)
    let canonical_headers = format!(
        "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
        host, payload_hash, amz_date
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";

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
        "PUT", "/alice-bucket", "", host, b"",
        ALICE_ACCESS_KEY, ALICE_SECRET_KEY,
    ).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // Alice puts an object
    let resp = sign_request(
        client.put(format!("{}/alice-bucket/hello.txt", base_url)).body("hello from alice"),
        "PUT", "/alice-bucket/hello.txt", "", host, b"hello from alice",
        ALICE_ACCESS_KEY, ALICE_SECRET_KEY,
    ).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // Alice can read her own object
    let resp = sign_request(
        client.get(format!("{}/alice-bucket/hello.txt", base_url)),
        "GET", "/alice-bucket/hello.txt", "", host, b"",
        ALICE_ACCESS_KEY, ALICE_SECRET_KEY,
    ).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "hello from alice");

    // Bob cannot read Alice's object (no policy)
    let resp = sign_request(
        client.get(format!("{}/alice-bucket/hello.txt", base_url)),
        "GET", "/alice-bucket/hello.txt", "", host, b"",
        BOB_ACCESS_KEY, BOB_SECRET_KEY,
    ).send().await.unwrap();
    assert_eq!(resp.status(), 403);

    // Bob cannot put into Alice's bucket
    let resp = sign_request(
        client.put(format!("{}/alice-bucket/bob.txt", base_url)).body("intruder"),
        "PUT", "/alice-bucket/bob.txt", "", host, b"intruder",
        BOB_ACCESS_KEY, BOB_SECRET_KEY,
    ).send().await.unwrap();
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
        "PUT", "/shared-bucket", "", host, b"",
        ALICE_ACCESS_KEY, ALICE_SECRET_KEY,
    ).send().await.unwrap();

    sign_request(
        client.put(format!("{}/shared-bucket/file.txt", base_url)).body("shared data"),
        "PUT", "/shared-bucket/file.txt", "", host, b"shared data",
        ALICE_ACCESS_KEY, ALICE_SECRET_KEY,
    ).send().await.unwrap();

    // Bob can't read yet
    let resp = sign_request(
        client.get(format!("{}/shared-bucket/file.txt", base_url)),
        "GET", "/shared-bucket/file.txt", "", host, b"",
        BOB_ACCESS_KEY, BOB_SECRET_KEY,
    ).send().await.unwrap();
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
        client.put(format!("{}/shared-bucket?policy", base_url)).body(policy_bytes.clone()),
        "PUT", "/shared-bucket", "policy", host, &policy_bytes,
        ALICE_ACCESS_KEY, ALICE_SECRET_KEY,
    ).send().await.unwrap();

    // Now Bob can read
    let resp = sign_request(
        client.get(format!("{}/shared-bucket/file.txt", base_url)),
        "GET", "/shared-bucket/file.txt", "", host, b"",
        BOB_ACCESS_KEY, BOB_SECRET_KEY,
    ).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "shared data");

    // Bob still can't write (only GetObject granted)
    let resp = sign_request(
        client.put(format!("{}/shared-bucket/bob.txt", base_url)).body("nope"),
        "PUT", "/shared-bucket/bob.txt", "", host, b"nope",
        BOB_ACCESS_KEY, BOB_SECRET_KEY,
    ).send().await.unwrap();
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
        "PUT", "/alice-priv", "", host, b"",
        ALICE_ACCESS_KEY, ALICE_SECRET_KEY,
    ).send().await.unwrap();

    sign_request(
        client.put(format!("{}/alice-priv/secret.txt", base_url)).body("secret"),
        "PUT", "/alice-priv/secret.txt", "", host, b"secret",
        ALICE_ACCESS_KEY, ALICE_SECRET_KEY,
    ).send().await.unwrap();

    // Root can read Alice's object
    let resp = sign_request(
        client.get(format!("{}/alice-priv/secret.txt", base_url)),
        "GET", "/alice-priv/secret.txt", "", host, b"",
        TEST_ACCESS_KEY, TEST_SECRET_KEY,
    ).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "secret");

    // Root can delete Alice's bucket
    sign_request(
        client.delete(format!("{}/alice-priv/secret.txt", base_url)),
        "DELETE", "/alice-priv/secret.txt", "", host, b"",
        TEST_ACCESS_KEY, TEST_SECRET_KEY,
    ).send().await.unwrap();

    let resp = sign_request(
        client.delete(format!("{}/alice-priv", base_url)),
        "DELETE", "/alice-priv", "", host, b"",
        TEST_ACCESS_KEY, TEST_SECRET_KEY,
    ).send().await.unwrap();
    assert_eq!(resp.status(), 204);

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_user_api_crud() {
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let client = reqwest::Client::new();

    // List users
    let resp = client.get(format!("{}/_loch/users", base_url))
        .header("Authorization", format!("Bearer {}", ADMIN_API_KEY))
        .send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let users = body["users"].as_array().unwrap();
    assert_eq!(users.len(), 3);
    // secret_access_key should NOT be in the response
    assert!(users[0].get("secret_access_key").is_none());

    // Get specific user
    let resp = client.get(format!("{}/_loch/users/alice", base_url))
        .header("Authorization", format!("Bearer {}", ADMIN_API_KEY))
        .send().await.unwrap();
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
    let resp = client.put(format!("{}/_loch/users/charlie", base_url))
        .header("Authorization", format!("Bearer {}", ADMIN_API_KEY))
        .json(&new_user)
        .send().await.unwrap();
    assert_eq!(resp.status(), 201);

    // Verify Charlie exists
    let resp = client.get(format!("{}/_loch/users", base_url))
        .header("Authorization", format!("Bearer {}", ADMIN_API_KEY))
        .send().await.unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["users"].as_array().unwrap().len(), 4);

    // Delete Charlie
    let resp = client.delete(format!("{}/_loch/users/charlie", base_url))
        .header("Authorization", format!("Bearer {}", ADMIN_API_KEY))
        .send().await.unwrap();
    assert_eq!(resp.status(), 204);

    // Cannot delete root
    let resp = client.delete(format!("{}/_loch/users/root", base_url))
        .header("Authorization", format!("Bearer {}", ADMIN_API_KEY))
        .send().await.unwrap();
    assert!(resp.status().is_client_error());

    cleanup(&tmp_dir);
}

#[tokio::test]
async fn test_user_api_requires_admin_key() {
    let (base_url, tmp_dir) = start_multi_user_server().await;
    let client = reqwest::Client::new();

    // No auth header
    let resp = client.get(format!("{}/_loch/users", base_url))
        .send().await.unwrap();
    assert_eq!(resp.status(), 403);

    // Wrong key
    let resp = client.get(format!("{}/_loch/users", base_url))
        .header("Authorization", "Bearer wrong-key")
        .send().await.unwrap();
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
        "PUT", "/private-bucket", "", host, b"",
        TEST_ACCESS_KEY, TEST_SECRET_KEY,
    ).send().await.unwrap();

    sign_request(
        client.put(format!("{}/private-bucket/data.txt", base_url)).body("private"),
        "PUT", "/private-bucket/data.txt", "", host, b"private",
        TEST_ACCESS_KEY, TEST_SECRET_KEY,
    ).send().await.unwrap();

    // Anonymous GET should be denied (no public policy)
    let resp = client.get(format!("{}/private-bucket/data.txt", base_url))
        .send().await.unwrap();
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
        .args(["--server", &base_url, "--api-key", ADMIN_API_KEY, "users", "list"])
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
    let users = parsed["users"].as_array().expect("response must have a 'users' array");
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
        .args(["--server", &base_url, "--api-key", ADMIN_API_KEY, "users", "get", "alice"])
        .output()
        .await
        .expect("failed to run loch-s3");

    assert!(output.status.success());
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("stdout is valid JSON");
    assert_eq!(parsed["user_id"], "alice");
    assert_eq!(parsed["display_name"], "Alice");
    assert!(parsed.get("secret_access_key").is_none());

    // Non-existent user must exit with code 1
    let output = tokio::process::Command::new(&bin)
        .args(["--server", &base_url, "--api-key", ADMIN_API_KEY, "users", "get", "nobody"])
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
            "--server", &base_url,
            "--api-key", ADMIN_API_KEY,
            "users", "put", "dave",
            "--display-name", "Dave",
            "--access-key", "AKIADAVE00000001",
            "--secret-key", "DaveSecretKey123456789012345678",
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
        .args(["--server", &base_url, "--api-key", ADMIN_API_KEY, "users", "list"])
        .output()
        .await
        .expect("failed to run loch-s3");
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("stdout is valid JSON");
    let ids: Vec<&str> = parsed["users"]
        .as_array()
        .expect("response must have a 'users' array")
        .iter()
        .map(|u| u["user_id"].as_str().expect("user_id is a string"))
        .collect();
    assert!(ids.contains(&"dave"));

    // Delete user
    let output = tokio::process::Command::new(&bin)
        .args(["--server", &base_url, "--api-key", ADMIN_API_KEY, "users", "delete", "dave"])
        .output()
        .await
        .expect("failed to run loch-s3");
    assert!(output.status.success());

    // Verify deleted
    let output = tokio::process::Command::new(&bin)
        .args(["--server", &base_url, "--api-key", ADMIN_API_KEY, "users", "get", "dave"])
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
        .args(["--server", &base_url, "--api-key", "wrong-key", "users", "list"])
        .output()
        .await
        .expect("failed to run loch-s3");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("403"), "expected 403 in stderr, got: {}", stderr);

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
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("stdout is valid JSON");
    assert!(
        !parsed["users"].as_array().expect("response must have a 'users' array").is_empty(),
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
        "PUT", "/alice-only", "", host, b"",
        ALICE_ACCESS_KEY, ALICE_SECRET_KEY,
    ).send().await.unwrap();

    // Root creates a bucket (not shared)
    sign_request(
        client.put(format!("{}/root-private", base_url)),
        "PUT", "/root-private", "", host, b"",
        TEST_ACCESS_KEY, TEST_SECRET_KEY,
    ).send().await.unwrap();

    // Alice's ListBuckets should contain only her bucket
    let resp = sign_request(
        client.get(&base_url),
        "GET", "/", "", host, b"",
        ALICE_ACCESS_KEY, ALICE_SECRET_KEY,
    ).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let buckets = parse_bucket_names(&resp.text().await.unwrap());
    assert!(buckets.contains(&"alice-only".to_string()), "Alice should see her own bucket");
    assert!(!buckets.contains(&"root-private".to_string()), "Alice should not see root's bucket");

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
        "PUT", "/shared-list", "", host, b"",
        ALICE_ACCESS_KEY, ALICE_SECRET_KEY,
    ).send().await.unwrap();

    sign_request(
        client.put(format!("{}/shared-list/hello.txt", base_url)).body("hello"),
        "PUT", "/shared-list/hello.txt", "", host, b"hello",
        ALICE_ACCESS_KEY, ALICE_SECRET_KEY,
    ).send().await.unwrap();

    // Bob cannot see the bucket before policy is set
    let resp = sign_request(
        client.get(&base_url),
        "GET", "/", "", host, b"",
        BOB_ACCESS_KEY, BOB_SECRET_KEY,
    ).send().await.unwrap();
    let buckets = parse_bucket_names(&resp.text().await.unwrap());
    assert!(!buckets.contains(&"shared-list".to_string()), "Bob should not see the bucket before policy");

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
        client.put(format!("{}/shared-list?policy", base_url)).body(policy_json),
        "PUT", "/shared-list", "policy", host, policy_json.as_bytes(),
        ALICE_ACCESS_KEY, ALICE_SECRET_KEY,
    ).send().await.unwrap();
    assert_eq!(resp.status(), 204, "PUT policy should succeed");

    // Bob now sees the shared bucket in ListBuckets
    let resp = sign_request(
        client.get(&base_url),
        "GET", "/", "", host, b"",
        BOB_ACCESS_KEY, BOB_SECRET_KEY,
    ).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let buckets = parse_bucket_names(&resp.text().await.unwrap());
    assert!(buckets.contains(&"shared-list".to_string()), "Bob should see the shared bucket after policy");

    // Bob can list objects in the shared bucket
    let resp = sign_request(
        client.get(format!("{}/shared-list", base_url)),
        "GET", "/shared-list", "", host, b"",
        BOB_ACCESS_KEY, BOB_SECRET_KEY,
    ).send().await.unwrap();
    assert_eq!(resp.status(), 200, "Bob should be able to list objects");
    assert!(resp.text().await.unwrap().contains("hello.txt"));

    // Bob can read objects in the shared bucket
    let resp = sign_request(
        client.get(format!("{}/shared-list/hello.txt", base_url)),
        "GET", "/shared-list/hello.txt", "", host, b"",
        BOB_ACCESS_KEY, BOB_SECRET_KEY,
    ).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "hello");

    // Bob cannot write (only read was granted)
    let resp = sign_request(
        client.put(format!("{}/shared-list/intruder.txt", base_url)).body("nope"),
        "PUT", "/shared-list/intruder.txt", "", host, b"nope",
        BOB_ACCESS_KEY, BOB_SECRET_KEY,
    ).send().await.unwrap();
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
        "PUT", "/alice-bucket2", "", host, b"",
        ALICE_ACCESS_KEY, ALICE_SECRET_KEY,
    ).send().await.unwrap();

    sign_request(
        client.put(format!("{}/bob-bucket2", base_url)),
        "PUT", "/bob-bucket2", "", host, b"",
        BOB_ACCESS_KEY, BOB_SECRET_KEY,
    ).send().await.unwrap();

    let resp = sign_request(
        client.get(&base_url),
        "GET", "/", "", host, b"",
        TEST_ACCESS_KEY, TEST_SECRET_KEY,
    ).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let buckets = parse_bucket_names(&resp.text().await.unwrap());
    assert!(buckets.contains(&"alice-bucket2".to_string()), "Root should see Alice's bucket");
    assert!(buckets.contains(&"bob-bucket2".to_string()), "Root should see Bob's bucket");

    cleanup(&tmp_dir);
}
