use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::fs;

use super::object::{StoredMetadata, compute_file_md5};
use super::{
    INTERNAL_NAMES, Storage, atomic_tmp_path, guess_content_type, is_real_dir, is_regular_file,
};
use crate::encryption::EncryptionMeta;
use crate::error::S3Error;
use crate::storage::bucket::format_system_time;

const VERSIONING_FILE: &str = ".versioning.json";
const VERSIONS_DIR: &str = ".versions";

/// Versioning status for a bucket.
#[derive(Debug, Clone, PartialEq)]
pub enum VersioningStatus {
    Unversioned,
    Enabled,
    Suspended,
}

/// Persisted versioning configuration.
#[derive(Serialize, Deserialize)]
struct VersioningConfig {
    status: String,
}

/// Metadata stored alongside each version.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VersionMeta {
    pub etag: String,
    pub content_type: String,
    pub last_modified: String,
    pub size: u64,
    #[serde(default)]
    pub is_delete_marker: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<StoredMetadata>,
    /// Encryption parameters (if version is encrypted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionMeta>,
}

impl VersionMeta {
    /// Build a VersionMeta from stored metadata and object info.
    pub fn from_stored(
        etag: String,
        content_type: String,
        last_modified: String,
        size: u64,
        stored: StoredMetadata,
    ) -> Self {
        Self {
            etag,
            content_type,
            last_modified,
            size,
            is_delete_marker: false,
            encryption: stored.encryption.clone(),
            metadata: Some(stored),
        }
    }
}

/// Info about a single version (for listing).
pub struct VersionInfo {
    pub key: String,
    pub version_id: String,
    pub is_delete_marker: bool,
    pub last_modified: String,
    pub etag: String,
    pub size: u64,
    pub is_latest: bool,
}

/// Result of list_all_versions.
pub struct ListVersionsOutput {
    pub versions: Vec<VersionInfo>,
    pub delete_markers: Vec<VersionInfo>,
    pub common_prefixes: Vec<String>,
    pub is_truncated: bool,
}

impl Storage {
    // -- Versioning config --

    /// Set the versioning status for a bucket.
    pub async fn put_versioning(&self, bucket: &str, status: &str) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        let path = self.data_dir.join(bucket).join(VERSIONING_FILE);
        let config = VersioningConfig {
            status: status.to_string(),
        };
        let json =
            serde_json::to_vec(&config).map_err(|e| S3Error::InternalError(e.to_string()))?;
        fs::write(&path, &json)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))
    }

    /// Get the versioning status for a bucket.
    pub async fn get_versioning(&self, bucket: &str) -> Result<VersioningStatus, S3Error> {
        self.head_bucket(bucket).await?;
        let path = self.data_dir.join(bucket).join(VERSIONING_FILE);
        if !is_regular_file(&path).await {
            return Ok(VersioningStatus::Unversioned);
        }
        let data = fs::read(&path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;
        let config: VersioningConfig =
            serde_json::from_slice(&data).map_err(|e| S3Error::InternalError(e.to_string()))?;
        match config.status.as_str() {
            "Enabled" => Ok(VersioningStatus::Enabled),
            "Suspended" => Ok(VersioningStatus::Suspended),
            _ => Ok(VersioningStatus::Unversioned),
        }
    }

    // -- Version ID generation --

    /// Generate a sortable version ID: {14-digit-ms-timestamp}-{8-hex-random}.
    pub fn generate_version_id() -> String {
        let ts = Utc::now().timestamp_millis();
        let uuid = uuid::Uuid::new_v4();
        let hex = format!("{:x}", uuid);
        format!("{:014}-{}", ts, &hex[..8])
    }

    // -- Path helpers --

    /// Path to the versions directory for a given key within a bucket.
    fn versions_key_dir(&self, bucket: &str, key: &str) -> Result<PathBuf, S3Error> {
        let bucket_dir = self.data_dir.join(bucket);
        let path = bucket_dir.join(VERSIONS_DIR).join(key);
        Ok(path)
    }

    // -- Core operations --

    /// Store a version of an object by copying data from source_path.
    /// Uses atomic write (tmp + rename).
    pub async fn store_version(
        &self,
        bucket: &str,
        key: &str,
        vid: &str,
        source_path: &Path,
        meta: &VersionMeta,
    ) -> Result<(), S3Error> {
        let ver_dir = self.versions_key_dir(bucket, key)?;
        fs::create_dir_all(&ver_dir)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        let data_path = ver_dir.join(format!("{}.data", vid));
        let meta_path = ver_dir.join(format!("{}.meta", vid));

        // Atomic copy to .data
        let tmp_path = atomic_tmp_path(&data_path);
        fs::copy(source_path, &tmp_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;
        fs::rename(&tmp_path, &data_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        // Write meta
        let meta_json =
            serde_json::to_vec(meta).map_err(|e| S3Error::InternalError(e.to_string()))?;
        fs::write(&meta_path, &meta_json)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        Ok(())
    }

    /// Store a delete marker version.
    pub async fn store_delete_marker(
        &self,
        bucket: &str,
        key: &str,
        vid: &str,
    ) -> Result<(), S3Error> {
        let ver_dir = self.versions_key_dir(bucket, key)?;
        fs::create_dir_all(&ver_dir)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        let marker_path = ver_dir.join(format!("{}.marker", vid));
        let meta_path = ver_dir.join(format!("{}.meta", vid));

        // Empty marker file
        fs::write(&marker_path, b"")
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        // Meta with is_delete_marker = true
        let meta = VersionMeta {
            etag: String::new(),
            content_type: String::new(),
            last_modified: format_system_time(std::time::SystemTime::now()),
            size: 0,
            is_delete_marker: true,
            metadata: None,
            encryption: None,
        };
        let meta_json =
            serde_json::to_vec(&meta).map_err(|e| S3Error::InternalError(e.to_string()))?;
        fs::write(&meta_path, &meta_json)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        Ok(())
    }

    /// Migrate a pre-versioning object to a "null" version.
    /// Only does work if the object exists at the normal path AND no versions exist yet.
    pub async fn migrate_pre_versioning_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(), S3Error> {
        let object_path = self.object_path(bucket, key)?;
        if !is_regular_file(&object_path).await {
            return Ok(());
        }

        let ver_dir = self.versions_key_dir(bucket, key)?;

        // Already has versions (either migrated or versioned PUT happened) — skip
        if is_real_dir(&ver_dir).await {
            return Ok(());
        }

        fs::create_dir_all(&ver_dir)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        // Derive metadata from the existing file
        let file_meta = fs::symlink_metadata(&object_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;
        let etag = compute_file_md5(&object_path).await?;
        let last_modified = file_meta
            .modified()
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);

        // Include stored metadata if available
        let stored = self
            .get_stored_metadata(bucket, key)
            .await
            .unwrap_or_default();
        let content_type = stored
            .content_type
            .clone()
            .unwrap_or_else(|| guess_content_type(key));

        let meta = VersionMeta::from_stored(
            etag,
            content_type,
            format_system_time(last_modified),
            file_meta.len(),
            stored,
        );

        // Copy file to null.data
        let null_data_path = ver_dir.join("null.data");
        let tmp_path = atomic_tmp_path(&null_data_path);
        fs::copy(&object_path, &tmp_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;
        fs::rename(&tmp_path, &null_data_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        // Write null.meta
        let meta_json =
            serde_json::to_vec(&meta).map_err(|e| S3Error::InternalError(e.to_string()))?;
        fs::write(ver_dir.join("null.meta"), &meta_json)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        Ok(())
    }

    /// Find the latest version for a key. Returns (version_id, is_delete_marker).
    /// Returns None if no versions exist.
    pub async fn get_latest_version(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<(String, bool)>, S3Error> {
        let ver_dir = self.versions_key_dir(bucket, key)?;
        if !is_real_dir(&ver_dir).await {
            return Ok(None);
        }

        let versions = self.scan_versions_dir(&ver_dir).await?;
        Ok(versions.last().cloned())
    }

    /// Read version metadata.
    pub async fn get_version_meta(
        &self,
        bucket: &str,
        key: &str,
        vid: &str,
    ) -> Result<VersionMeta, S3Error> {
        let ver_dir = self.versions_key_dir(bucket, key)?;
        let meta_path = ver_dir.join(format!("{}.meta", vid));
        if !is_regular_file(&meta_path).await {
            return Err(S3Error::NoSuchVersion);
        }
        let data = fs::read(&meta_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;
        serde_json::from_slice(&data).map_err(|e| S3Error::InternalError(e.to_string()))
    }

    /// Get the path to a version's data file. Returns NoSuchVersion if absent.
    pub async fn get_version_data_path(
        &self,
        bucket: &str,
        key: &str,
        vid: &str,
    ) -> Result<PathBuf, S3Error> {
        let ver_dir = self.versions_key_dir(bucket, key)?;
        let data_path = ver_dir.join(format!("{}.data", vid));
        if !is_regular_file(&data_path).await {
            return Err(S3Error::NoSuchVersion);
        }
        Ok(data_path)
    }

    /// Check if a version is a delete marker.
    pub async fn is_version_delete_marker(
        &self,
        bucket: &str,
        key: &str,
        vid: &str,
    ) -> Result<bool, S3Error> {
        let ver_dir = self.versions_key_dir(bucket, key)?;
        let marker_path = ver_dir.join(format!("{}.marker", vid));
        Ok(is_regular_file(&marker_path).await)
    }

    /// Delete a specific version. Returns true if the deleted version was a delete marker.
    pub async fn delete_version(
        &self,
        bucket: &str,
        key: &str,
        vid: &str,
    ) -> Result<bool, S3Error> {
        let ver_dir = self.versions_key_dir(bucket, key)?;

        let data_path = ver_dir.join(format!("{}.data", vid));
        let marker_path = ver_dir.join(format!("{}.marker", vid));
        let meta_path = ver_dir.join(format!("{}.meta", vid));

        let was_marker = is_regular_file(&marker_path).await;
        let has_data = is_regular_file(&data_path).await;

        if !was_marker && !has_data {
            return Err(S3Error::NoSuchVersion);
        }

        // Remove all files for this version
        if was_marker {
            let _ = fs::remove_file(&marker_path).await;
        }
        if has_data {
            let _ = fs::remove_file(&data_path).await;
        }
        if is_regular_file(&meta_path).await {
            let _ = fs::remove_file(&meta_path).await;
        }

        // Clean up empty version directory
        if is_dir_empty(&ver_dir).await {
            let _ = fs::remove_dir(&ver_dir).await;
            // Also clean empty parent dirs up to .versions/
            let versions_root = self.data_dir.join(bucket).join(VERSIONS_DIR);
            let mut current = ver_dir.parent().map(|p| p.to_path_buf());
            while let Some(dir) = current {
                if dir == versions_root {
                    // Remove .versions/ itself if empty
                    let _ = fs::remove_dir(&dir).await;
                    break;
                }
                if fs::remove_dir(&dir).await.is_err() {
                    break;
                }
                current = dir.parent().map(|p| p.to_path_buf());
            }
        }

        Ok(was_marker)
    }

    /// Sync the normal object path with the latest version.
    /// If latest is data, copy it to the normal path.
    /// If latest is a delete marker or no versions remain, remove the normal path.
    pub async fn sync_normal_path(&self, bucket: &str, key: &str) -> Result<(), S3Error> {
        let object_path = self.object_path(bucket, key)?;
        let latest = self.get_latest_version(bucket, key).await?;

        match latest {
            Some((vid, false)) => {
                // Latest is data — copy to normal path
                let ver_dir = self.versions_key_dir(bucket, key)?;
                let data_path = ver_dir.join(format!("{}.data", vid));
                if is_regular_file(&data_path).await {
                    if let Some(parent) = object_path.parent() {
                        fs::create_dir_all(parent)
                            .await
                            .map_err(|e| S3Error::InternalError(e.to_string()))?;
                    }
                    let tmp_path = atomic_tmp_path(&object_path);
                    fs::copy(&data_path, &tmp_path)
                        .await
                        .map_err(|e| S3Error::InternalError(e.to_string()))?;
                    fs::rename(&tmp_path, &object_path)
                        .await
                        .map_err(|e| S3Error::InternalError(e.to_string()))?;

                    // Sync metadata sidecar from version meta (important for encryption info)
                    let meta_path = ver_dir.join(format!("{}.meta", vid));
                    if let Ok(data) = fs::read(&meta_path).await {
                        if let Ok(ver_meta) = serde_json::from_slice::<VersionMeta>(&data) {
                            if let Some(stored) = ver_meta.metadata {
                                let _ = self.put_object_metadata(bucket, key, &stored).await;
                            }
                        }
                    }
                }
            }
            Some((_, true)) | None => {
                // Latest is a delete marker or no versions — remove normal path
                if is_regular_file(&object_path).await {
                    let _ = fs::remove_file(&object_path).await;
                    // Clean up empty parent directories (but not the bucket root)
                    let bucket_root = self.data_dir.join(bucket);
                    let mut current = object_path.parent().map(|p| p.to_path_buf());
                    while let Some(dir) = current {
                        if dir == bucket_root {
                            break;
                        }
                        if fs::remove_dir(&dir).await.is_err() {
                            break;
                        }
                        current = dir.parent().map(|p| p.to_path_buf());
                    }
                }
                // Also remove metadata sidecar and ACL
                self.delete_object_metadata(bucket, key).await?;
                self.delete_object_acl(bucket, key).await?;
            }
        }

        Ok(())
    }

    /// List all versions across all keys in a bucket.
    /// Supports prefix filtering, key/version-id markers for pagination,
    /// max_keys truncation, and delimiter for common prefixes.
    pub async fn list_all_versions(
        &self,
        bucket: &str,
        prefix: &str,
        key_marker: &str,
        version_id_marker: &str,
        max_keys: usize,
        delimiter: &str,
    ) -> Result<ListVersionsOutput, S3Error> {
        self.head_bucket(bucket).await?;

        let versions_root = self.data_dir.join(bucket).join(VERSIONS_DIR);
        let mut all_entries: Vec<VersionInfo> = Vec::new();

        // Collect versions from .versions/ directory
        if is_real_dir(&versions_root).await {
            collect_version_entries(&versions_root, &versions_root, &mut all_entries).await?;
        }

        // Also check for unversioned objects (normal path, no .versions/ entry)
        let bucket_path = self.data_dir.join(bucket);
        let mut unversioned_keys = Vec::new();
        collect_unversioned_keys(
            &bucket_path,
            &bucket_path,
            &versions_root,
            &mut unversioned_keys,
        )
        .await?;

        for key in unversioned_keys {
            let object_path = match self.object_path(bucket, &key) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if let Ok(file_meta) = fs::symlink_metadata(&object_path).await {
                let etag = compute_file_md5(&object_path).await.unwrap_or_default();
                let last_modified = file_meta
                    .modified()
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                all_entries.push(VersionInfo {
                    key,
                    version_id: "null".to_string(),
                    is_delete_marker: false,
                    last_modified: format_system_time(last_modified),
                    etag,
                    size: file_meta.len(),
                    is_latest: true,
                });
            }
        }

        // Sort by key, then by version ID descending (latest first)
        all_entries.sort_by(|a, b| {
            a.key
                .cmp(&b.key)
                .then_with(|| b.version_id.cmp(&a.version_id))
        });

        // Mark is_latest for each key
        let mut seen_keys = std::collections::HashSet::new();
        for entry in &mut all_entries {
            if seen_keys.insert(entry.key.clone()) {
                entry.is_latest = true;
            } else {
                entry.is_latest = false;
            }
        }

        // Apply prefix filter
        let filtered: Vec<VersionInfo> = all_entries
            .into_iter()
            .filter(|e| e.key.starts_with(prefix))
            .collect();

        // Apply key-marker / version-id-marker pagination
        let paginated: Vec<VersionInfo> = filtered
            .into_iter()
            .filter(|e| {
                if key_marker.is_empty() {
                    return true;
                }
                if e.key.as_str() > key_marker {
                    return true;
                }
                if e.key == key_marker && !version_id_marker.is_empty() {
                    return e.version_id.as_str() < version_id_marker;
                }
                false
            })
            .collect();

        // Handle delimiter and common prefixes
        let mut common_prefixes = std::collections::BTreeSet::new();
        let mut result_entries: Vec<VersionInfo> = Vec::new();

        for entry in paginated {
            if !delimiter.is_empty() {
                let after_prefix = &entry.key[prefix.len()..];
                if let Some(pos) = after_prefix.find(delimiter) {
                    let cp = format!("{}{}", prefix, &after_prefix[..pos + delimiter.len()]);
                    common_prefixes.insert(cp);
                    continue;
                }
            }
            result_entries.push(entry);
        }

        // Apply max_keys truncation
        let is_truncated = result_entries.len() + common_prefixes.len() > max_keys;
        result_entries.truncate(max_keys);

        // Split into versions and delete markers
        let mut versions = Vec::new();
        let mut delete_markers = Vec::new();
        for entry in result_entries {
            if entry.is_delete_marker {
                delete_markers.push(entry);
            } else {
                versions.push(entry);
            }
        }

        Ok(ListVersionsOutput {
            versions,
            delete_markers,
            common_prefixes: common_prefixes.into_iter().collect(),
            is_truncated,
        })
    }

    /// Scan a versions directory for a single key, returning sorted (version_id, is_delete_marker) pairs.
    async fn scan_versions_dir(&self, ver_dir: &Path) -> Result<Vec<(String, bool)>, S3Error> {
        let mut versions = Vec::new();
        let mut entries = fs::read_dir(ver_dir)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?
        {
            let name = entry.file_name().to_string_lossy().to_string();

            if let Some(vid) = name.strip_suffix(".data") {
                versions.push((vid.to_string(), false));
            } else if let Some(vid) = name.strip_suffix(".marker") {
                versions.push((vid.to_string(), true));
            }
            // Skip .meta files and subdirectories
        }

        // Sort by version ID (lexicographic = chronological for our format)
        // "null" sorts before any timestamp-based ID
        versions.sort_by(|a, b| version_sort_key(&a.0).cmp(&version_sort_key(&b.0)));
        Ok(versions)
    }
}

/// Sort key for version IDs. "null" sorts before everything else.
fn version_sort_key(vid: &str) -> (u8, &str) {
    if vid == "null" { (0, vid) } else { (1, vid) }
}

/// Recursively collect version entries from the .versions/ tree.
async fn collect_version_entries(
    base: &Path,
    current: &Path,
    entries: &mut Vec<VersionInfo>,
) -> Result<(), S3Error> {
    let mut dir_entries = fs::read_dir(current)
        .await
        .map_err(|e| S3Error::InternalError(e.to_string()))?;

    // Collect .data and .marker files at this level (these are versions for the key = relative path of current dir)
    let mut has_versions = false;
    let mut version_files: Vec<(String, bool)> = Vec::new();
    let mut subdirs: Vec<PathBuf> = Vec::new();

    while let Some(entry) = dir_entries
        .next_entry()
        .await
        .map_err(|e| S3Error::InternalError(e.to_string()))?
    {
        let meta = match fs::symlink_metadata(entry.path()).await {
            Ok(m) => m,
            Err(_) => continue,
        };

        if meta.file_type().is_symlink() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().to_string();

        if meta.is_dir() {
            subdirs.push(entry.path());
        } else if meta.is_file() {
            if let Some(vid) = name.strip_suffix(".data") {
                version_files.push((vid.to_string(), false));
                has_versions = true;
            } else if let Some(vid) = name.strip_suffix(".marker") {
                version_files.push((vid.to_string(), true));
                has_versions = true;
            }
        }
    }

    // If this directory has version files, derive the key from relative path
    if has_versions {
        let key = current
            .strip_prefix(base)
            .unwrap_or(Path::new(""))
            .to_string_lossy()
            .to_string();

        for (vid, is_marker) in &version_files {
            let meta_path = current.join(format!("{}.meta", vid));
            let meta: Option<VersionMeta> = if let Ok(data) = fs::read(&meta_path).await {
                serde_json::from_slice(&data).ok()
            } else {
                None
            };

            let (etag, last_modified, size) = if let Some(m) = &meta {
                (m.etag.clone(), m.last_modified.clone(), m.size)
            } else {
                (String::new(), String::new(), 0)
            };

            entries.push(VersionInfo {
                key: key.clone(),
                version_id: vid.clone(),
                is_delete_marker: *is_marker,
                last_modified,
                etag,
                size,
                is_latest: false, // will be set later
            });
        }
    }

    // Recurse into subdirectories
    for subdir in subdirs {
        Box::pin(collect_version_entries(base, &subdir, entries)).await?;
    }

    Ok(())
}

/// Collect object keys that have NO .versions/ entry (pre-versioning objects).
/// These are objects at the normal path with no corresponding directory in .versions/.
async fn collect_unversioned_keys(
    bucket_base: &Path,
    current: &Path,
    versions_root: &Path,
    keys: &mut Vec<String>,
) -> Result<(), S3Error> {
    let mut entries = fs::read_dir(current)
        .await
        .map_err(|e| S3Error::InternalError(e.to_string()))?;

    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| S3Error::InternalError(e.to_string()))?
    {
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip internal files
        if INTERNAL_NAMES.contains(&name.as_str()) || name.ends_with(".tmp") {
            continue;
        }

        let path = entry.path();
        let meta = match fs::symlink_metadata(&path).await {
            Ok(m) => m,
            Err(_) => continue,
        };

        if meta.file_type().is_symlink() {
            continue;
        }

        if meta.is_dir() {
            Box::pin(collect_unversioned_keys(
                bucket_base,
                &path,
                versions_root,
                keys,
            ))
            .await?;
        } else if meta.is_file() {
            if let Ok(relative) = path.strip_prefix(bucket_base) {
                let key = relative.to_string_lossy().to_string();
                // Check if this key has a versions directory
                let ver_dir = versions_root.join(&key);
                if !is_real_dir(&ver_dir).await {
                    keys.push(key);
                }
            }
        }
    }

    Ok(())
}

/// Check if a directory is empty.
async fn is_dir_empty(path: &Path) -> bool {
    match fs::read_dir(path).await {
        Ok(mut entries) => entries.next_entry().await.ok().flatten().is_none(),
        Err(_) => true,
    }
}
