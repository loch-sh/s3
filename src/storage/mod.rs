pub mod acl;
pub mod bucket;
pub mod cors;
pub mod encryption;
pub mod multipart;
pub mod object;
pub mod policy;
pub mod versioning;

use std::path::{Component, PathBuf};

use crate::error::S3Error;

/// Sentinel file for directory marker objects (keys ending with `/`).
/// On S3, `prefix/` is a valid object key, but on the filesystem a trailing
/// slash denotes a directory. We store a hidden marker file inside the
/// directory so that both the "directory object" and nested objects can coexist.
pub(crate) const DIR_MARKER: &str = ".dir_marker";

/// Shared storage backend backed by the local filesystem.
pub struct Storage {
    pub data_dir: PathBuf,
}

impl Storage {
    pub fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    /// Resolve a safe bucket path. Validates the bucket name and ensures
    /// the result stays within data_dir (path traversal protection).
    pub(crate) fn safe_bucket_path(&self, name: &str) -> Result<PathBuf, S3Error> {
        validate_bucket_name(name)?;
        let path = self.data_dir.join(name);
        assert_path_within(&path, &self.data_dir)?;
        Ok(path)
    }

    /// Construct a safe object path, validating the key and ensuring the
    /// result stays within the bucket directory (path traversal protection).
    /// Keys ending with `/` are mapped to a `.dir_marker` sentinel file
    /// inside the directory so they can coexist with nested objects.
    pub(crate) fn object_path(&self, bucket: &str, key: &str) -> Result<PathBuf, S3Error> {
        validate_object_key(key)?;

        let bucket_dir = self.data_dir.join(bucket);
        let path = if key.ends_with('/') {
            bucket_dir.join(key).join(DIR_MARKER)
        } else {
            bucket_dir.join(key)
        };

        // Defense in depth: reject ".." components and verify containment
        assert_path_within(&path, &self.data_dir)?;

        Ok(path)
    }
}

/// Assert that a path stays within the base directory.
/// Rejects any Component::ParentDir ("..") and verifies the normalized path
/// starts with the base directory.
fn assert_path_within(path: &PathBuf, base: &PathBuf) -> Result<(), S3Error> {
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(S3Error::AccessDenied);
        }
    }
    // Also verify logical prefix containment
    if !path.starts_with(base) {
        return Err(S3Error::AccessDenied);
    }
    Ok(())
}

/// Check if a path is a regular file (not a symlink).
/// Uses symlink_metadata() which does NOT follow symlinks.
pub(crate) async fn is_regular_file(path: &std::path::Path) -> bool {
    match tokio::fs::symlink_metadata(path).await {
        Ok(m) => m.is_file() && !m.file_type().is_symlink(),
        Err(_) => false,
    }
}

/// Check if a path is a real directory (not a symlink).
/// Uses symlink_metadata() which does NOT follow symlinks.
pub(crate) async fn is_real_dir(path: &std::path::Path) -> bool {
    match tokio::fs::symlink_metadata(path).await {
        Ok(m) => m.is_dir() && !m.file_type().is_symlink(),
        Err(_) => false,
    }
}

/// Validate a bucket name per S3 naming rules.
/// - 3 to 63 characters
/// - Only lowercase ASCII letters, digits, hyphens, dots
/// - Must start and end with a letter or digit
/// - No ".." sequences (prevents path traversal)
pub fn validate_bucket_name(name: &str) -> Result<(), S3Error> {
    if name.len() < 3 || name.len() > 63 {
        return Err(S3Error::InvalidBucketName);
    }

    if name.contains("..") {
        return Err(S3Error::InvalidBucketName);
    }

    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return Err(S3Error::InvalidBucketName);
    }

    let first = name.as_bytes()[0];
    let last = name.as_bytes()[name.len() - 1];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(S3Error::InvalidBucketName);
    }
    if !(last.is_ascii_lowercase() || last.is_ascii_digit()) {
        return Err(S3Error::InvalidBucketName);
    }

    Ok(())
}

/// Validate an object key.
/// - 1 to 1024 bytes
/// - No null bytes
/// - No ".." path component (prevents path traversal)
/// - No component matching DIR_MARKER (prevents sentinel collision)
/// - First component must not match any INTERNAL_NAMES (prevents bucket state overwrites)
pub fn validate_object_key(key: &str) -> Result<(), S3Error> {
    if key.is_empty() || key.len() > 1024 {
        return Err(S3Error::InvalidObjectKey);
    }

    if key.bytes().any(|b| b == 0) {
        return Err(S3Error::InvalidObjectKey);
    }

    let mut first = true;
    for component in key.split('/') {
        // Reject ".." to prevent path traversal
        if component == ".." {
            return Err(S3Error::InvalidObjectKey);
        }
        // Reject DIR_MARKER to prevent collision with directory marker sentinels
        if component == DIR_MARKER {
            return Err(S3Error::InvalidObjectKey);
        }
        // Reject internal names as the first component to prevent bucket state overwrites
        if first && INTERNAL_NAMES.contains(&component) {
            return Err(S3Error::AccessDenied);
        }
        first = false;
    }

    Ok(())
}

pub use bucket::BucketInfo;
pub use object::{ListObjectsResult, ObjectMetadata};

/// Generate a UUID-based temporary file path next to the given path.
/// Used for atomic writes (write to tmp, then rename).
pub(crate) fn atomic_tmp_path(path: &std::path::Path) -> std::path::PathBuf {
    let tmp_name = format!(
        "{}.{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        uuid::Uuid::new_v4()
    );
    path.with_file_name(&tmp_name)
}

/// Guess MIME content type from file extension.
pub fn guess_content_type(key: &str) -> String {
    let ext = key.rsplit('.').next().unwrap_or("");
    match ext.to_lowercase().as_str() {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "txt" => "text/plain",
        "csv" => "text/csv",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "tar" => "application/x-tar",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Internal file and directory names that should be excluded from object listings
/// and "bucket empty" checks (metadata, policies, CORS, uploads, versions, ACLs).
pub(crate) const INTERNAL_NAMES: &[&str] = &[
    ".metadata",
    ".meta",
    ".policy.json",
    ".cors.json",
    ".encryption.json",
    ".acl.xml",
    ".acl",
    ".uploads",
    ".versions",
    ".versioning.json",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_bucket_names() {
        assert!(validate_bucket_name("my-bucket").is_ok());
        assert!(validate_bucket_name("my.bucket.123").is_ok());
        assert!(validate_bucket_name("abc").is_ok());
    }

    #[test]
    fn test_invalid_bucket_names() {
        assert!(validate_bucket_name("ab").is_err()); // too short
        assert!(validate_bucket_name(&"a".repeat(64)).is_err()); // too long
        assert!(validate_bucket_name("My-Bucket").is_err()); // uppercase
        assert!(validate_bucket_name("-bucket").is_err()); // starts with hyphen
        assert!(validate_bucket_name("bucket-").is_err()); // ends with hyphen
        assert!(validate_bucket_name("bucket..name").is_err()); // double dot
        assert!(validate_bucket_name("bucket/name").is_err()); // slash
        assert!(validate_bucket_name("bucket\\name").is_err()); // backslash
        assert!(validate_bucket_name("../etc").is_err()); // traversal
    }

    #[test]
    fn test_valid_object_keys() {
        assert!(validate_object_key("file.txt").is_ok());
        assert!(validate_object_key("dir/nested/file.txt").is_ok());
        assert!(validate_object_key("a").is_ok());
        assert!(validate_object_key("./file.txt").is_ok()); // single dot is ok
    }

    #[test]
    fn test_invalid_object_keys() {
        assert!(validate_object_key("").is_err()); // empty
        assert!(validate_object_key(&"a".repeat(1025)).is_err()); // too long
        assert!(validate_object_key("../etc/passwd").is_err()); // traversal
        assert!(validate_object_key("dir/../../etc/passwd").is_err()); // nested traversal
        assert!(validate_object_key("dir/..").is_err()); // trailing traversal
    }

    #[test]
    fn test_dir_marker_rejected() {
        // Direct .dir_marker as key
        assert!(validate_object_key(".dir_marker").is_err());
        // .dir_marker as nested component
        assert!(validate_object_key("foo/.dir_marker").is_err());
        assert!(validate_object_key("foo/.dir_marker/bar").is_err());
        // Similar names that are NOT .dir_marker should be ok
        assert!(validate_object_key("dir_marker").is_ok());
        assert!(validate_object_key(".dir_marker2").is_ok());
    }

    #[test]
    fn test_internal_names_rejected_at_root() {
        // Internal names as the first component should be rejected
        assert!(validate_object_key(".metadata").is_err());
        assert!(validate_object_key(".meta").is_err());
        assert!(validate_object_key(".policy.json").is_err());
        assert!(validate_object_key(".cors.json").is_err());
        assert!(validate_object_key(".encryption.json").is_err());
        assert!(validate_object_key(".acl.xml").is_err());
        assert!(validate_object_key(".acl").is_err());
        assert!(validate_object_key(".uploads").is_err());
        assert!(validate_object_key(".versions").is_err());
        assert!(validate_object_key(".versioning.json").is_err());
        // With sub-paths
        assert!(validate_object_key(".metadata/something").is_err());
        assert!(validate_object_key(".uploads/upload-id").is_err());
        // Internal names NOT at the root should be allowed
        assert!(validate_object_key("foo/.metadata").is_ok());
        assert!(validate_object_key("foo/.uploads/bar").is_ok());
    }

    #[test]
    fn test_object_path_containment() {
        let storage = Storage::new(PathBuf::from("/tmp/data"));
        // Normal key
        assert!(storage.object_path("my-bucket", "file.txt").is_ok());
        // Traversal attempt blocked by validation
        assert!(storage.object_path("my-bucket", "../escape").is_err());
        assert!(storage.object_path("my-bucket", "a/../../escape").is_err());
    }

    #[test]
    fn test_safe_bucket_path() {
        let storage = Storage::new(PathBuf::from("/tmp/data"));
        assert!(storage.safe_bucket_path("my-bucket").is_ok());
        assert!(storage.safe_bucket_path("ab").is_err()); // too short
        assert!(storage.safe_bucket_path("../etc").is_err()); // traversal
    }

    #[test]
    fn test_assert_path_within() {
        let base = PathBuf::from("/data");
        assert!(assert_path_within(&PathBuf::from("/data/bucket/key"), &base).is_ok());
        assert!(assert_path_within(&PathBuf::from("/data/bucket/../etc"), &base).is_err());
        assert!(assert_path_within(&PathBuf::from("/other/path"), &base).is_err());
    }
}
