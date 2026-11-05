pub mod acl;
pub mod bucket;
pub mod cors;
pub mod encryption;
pub mod multipart;
pub mod object;
pub mod policy;
pub mod versioning;

use std::path::{Component, PathBuf};
use std::sync::Arc;

use crate::error::S3Error;
use crate::quota::Quota;

/// Sentinel file for directory marker objects (keys ending with `/`).
/// On S3, `prefix/` is a valid object key, but on the filesystem a trailing
/// slash denotes a directory. We store a hidden marker file inside the
/// directory so that both the "directory object" and nested objects can coexist.
pub(crate) const DIR_MARKER: &str = ".dir_marker";

/// Directory (directly under the data directory) holding in-flight temporary files.
pub const TMP_DIR: &str = ".loch-tmp";

/// Shared storage backend backed by the local filesystem.
pub struct Storage {
    pub data_dir: PathBuf,
    /// Storage quota for the whole data directory (unlimited by default).
    pub quota: Arc<Quota>,
    /// Multipart uploads being completed (one completion at a time each).
    completing: std::sync::Mutex<std::collections::HashSet<String>>,
}

/// A temporary file path under `TMP_DIR`, removed when dropped. Writes that
/// are cancelled mid-way (client disconnect drops the handler future) or fail
/// therefore never leave temporary files behind. Once the file has been
/// renamed into place, the removal is a harmless no-op.
pub(crate) struct TmpPath(PathBuf);

impl std::ops::Deref for TmpPath {
    type Target = std::path::Path;
    fn deref(&self) -> &std::path::Path {
        &self.0
    }
}

impl AsRef<std::path::Path> for TmpPath {
    fn as_ref(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TmpPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Exclusive right to complete one multipart upload, released on drop
/// (including when the request is cancelled).
pub(crate) struct CompletionGuard<'a> {
    storage: &'a Storage,
    upload_id: String,
}

impl Drop for CompletionGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut set) = self.storage.completing.lock() {
            set.remove(&self.upload_id);
        }
    }
}

impl Storage {
    pub fn new(data_dir: PathBuf) -> Self {
        Self::with_quota(data_dir, None)
    }

    /// Create a storage backend with an optional quota (in bytes) on the whole data directory.
    pub fn with_quota(data_dir: PathBuf, max_bytes: Option<u64>) -> Self {
        Self {
            data_dir,
            quota: Arc::new(Quota::new(max_bytes)),
            completing: Default::default(),
        }
    }

    /// Claim the completion of `upload_id`; `None` if already in progress.
    pub(crate) fn begin_completion(&self, upload_id: &str) -> Option<CompletionGuard<'_>> {
        let mut set = self.completing.lock().unwrap_or_else(|e| e.into_inner());
        set.insert(upload_id.to_string()).then(|| CompletionGuard {
            storage: self,
            upload_id: upload_id.to_string(),
        })
    }

    /// New temporary file path for an atomic write (write to tmp, then rename).
    /// Temporary files live in `{data_dir}/.loch-tmp/`, never next to objects: a
    /// bucket name cannot start with '.', so no bucket or object key can collide
    /// with them, and leftovers can be removed safely at startup. The data
    /// directory must be a single filesystem (rename across it must be atomic).
    pub(crate) fn tmp_file(&self) -> TmpPath {
        let dir = self.data_dir.join(TMP_DIR);
        // Cheap when it already exists; recreated if removed while running
        let _ = std::fs::create_dir_all(&dir);
        TmpPath(dir.join(format!("{}.tmp", uuid::Uuid::new_v4())))
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
pub(crate) fn assert_path_within(path: &PathBuf, base: &PathBuf) -> Result<(), S3Error> {
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
/// - No "..", "." or empty path component (prevents path traversal and
///   aliasing: one key maps to exactly one path); a single trailing '/'
///   (directory marker) is allowed
/// - No component matching DIR_MARKER (prevents sentinel collision)
/// - First component must not match any INTERNAL_NAMES (prevents bucket state overwrites)
pub fn validate_object_key(key: &str) -> Result<(), S3Error> {
    if key.is_empty() || key.len() > 1024 {
        return Err(S3Error::InvalidObjectKey);
    }

    if key.bytes().any(|b| b == 0) {
        return Err(S3Error::InvalidObjectKey);
    }

    // A key ending with '/' is a directory marker: its last component is empty.
    let body = key.strip_suffix('/').unwrap_or(key);
    // Each component is a directory on disk: bound the nesting so a single
    // request cannot create hundreds of directories.
    if body.split('/').count() > MAX_KEY_DEPTH {
        return Err(S3Error::InvalidObjectKey);
    }
    let mut first = true;
    for component in body.split('/') {
        // Reject "..", "." and empty components: the filesystem resolves
        // "a/./b", "a//b", "./x" and "/x" to another key (possibly an
        // internal file such as "./.policy.json"), while authorization
        // would see the literal key. One key = one path.
        if component.is_empty() || component == "." || component == ".." {
            return Err(S3Error::InvalidObjectKey);
        }
        // Reject DIR_MARKER to prevent collision with directory marker sentinels.
        // Names are compared case-insensitively: on a case-insensitive
        // filesystem (macOS, Windows) ".METADATA" is the same file as ".metadata".
        if component.eq_ignore_ascii_case(DIR_MARKER) {
            return Err(S3Error::InvalidObjectKey);
        }
        // Reject internal names as the first component to prevent bucket state overwrites
        if first
            && INTERNAL_NAMES
                .iter()
                .any(|name| name.eq_ignore_ascii_case(component))
        {
            return Err(S3Error::AccessDenied);
        }
        // Windows: '\' is a path separator, ':' selects an NTFS stream and a
        // trailing '.' or ' ' is stripped, so such names alias other files
        #[cfg(windows)]
        if component.contains(['\\', ':']) || component.ends_with(['.', ' ']) {
            return Err(S3Error::InvalidObjectKey);
        }
        first = false;
    }

    Ok(())
}

pub use bucket::BucketInfo;
pub use object::{ListObjectsResult, ObjectMetadata};

/// Rename a temporary file to its destination, recreating the destination's
/// parent directory if needed. A concurrent delete removes directories that
/// become empty (object parents, `.meta/`, version directories) between the
/// writer's `create_dir_all` and its rename, which would otherwise fail with
/// `NotFound`. Retries a few times, then returns the last error.
pub(crate) async fn rename_into(
    tmp: &std::path::Path,
    dest: &std::path::Path,
) -> std::io::Result<()> {
    let mut attempt = 0;
    loop {
        match tokio::fs::rename(tmp, dest).await {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && attempt < 5 => {
                attempt += 1;
                // The temporary file itself must still exist; only the parent is recreated
                if tokio::fs::symlink_metadata(tmp).await.is_err() {
                    return Err(e);
                }
                if let Some(parent) = dest.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
            }
            other => return other,
        }
    }
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
/// True when `dir` is on a case-insensitive filesystem: a probe file created
/// under `TMP_DIR` is visible under its upper-case name.
pub fn is_case_insensitive(dir: &std::path::Path) -> bool {
    let tmp = dir.join(TMP_DIR);
    let _ = std::fs::create_dir_all(&tmp);
    let name = format!("case-probe-{}", uuid::Uuid::new_v4().simple());
    let lower = tmp.join(&name);
    if std::fs::write(&lower, b"").is_err() {
        return false;
    }
    let insensitive = tmp.join(name.to_uppercase()).exists();
    let _ = std::fs::remove_file(&lower);
    insensitive
}

/// Map a filesystem error from writing an object or one of its sidecars.
/// Layout conflicts (a key that is also a "directory" of another key, such
/// as `a` and `a/b`, or `k` and `k.json/x` for sidecars, or a name too long
/// once suffixed) are client errors, not internal errors.
pub(crate) fn path_conflict_error(e: std::io::Error) -> S3Error {
    use std::io::ErrorKind::*;
    match e.kind() {
        NotADirectory | IsADirectory | AlreadyExists | DirectoryNotEmpty | InvalidFilename => {
            S3Error::InvalidObjectKey
        }
        _ => S3Error::InternalError(e.to_string()),
    }
}

/// Maximum number of `/`-separated components in an object key.
pub const MAX_KEY_DEPTH: usize = 64;

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
    ".users.json",
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
        assert!(validate_object_key("dir/").is_ok()); // directory marker
        assert!(validate_object_key("dir/sub/").is_ok());
        assert!(validate_object_key(".hidden").is_ok());
        assert!(validate_object_key("a/.policy.json").is_ok()); // nested: not internal
        assert!(validate_object_key("a.b/c..d/...").is_ok()); // dots inside names
    }

    #[test]
    fn test_internal_names_rejected_in_any_case() {
        for key in [".METADATA", ".Policy.Json", ".META/x", ".Dir_Marker", "a/.DIR_MARKER/b"] {
            assert!(validate_object_key(key).is_err(), "{key:?} must be rejected");
        }
        // Nested internal names are ordinary keys
        assert!(validate_object_key("d/.meta").is_ok());
    }

    #[test]
    fn test_non_canonical_keys_rejected() {
        // Each of these resolves on disk to another key or to an internal
        // file, while authorization would see the literal string.
        for key in [
            "./file.txt",
            "./.policy.json",
            "./.metadata",
            ".//.policy.json",
            "a/./b",
            "a//b",
            "a/b//",
            "a/.",
            "/abs",
            "//x",
            "/",
            ".",
            "./",
            "x/./.meta/y.json",
        ] {
            assert!(validate_object_key(key).is_err(), "{key:?} must be rejected");
        }
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
